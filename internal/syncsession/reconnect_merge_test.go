package syncsession

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

func TestPreviewReconnectMerge(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, confirmed, signer := queueFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	confirmed.Binding.RelayURL = server.URL
	store, err := replicastore.Create(ctx, filepath.Join(t.TempDir(), "merge.sqlite"), queueTestKey)
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 0))

	operation := func(id byte, action syncmerge.Action, data string, parents ...[32]byte) syncwire.LocalOperation {
		return syncwire.LocalOperation{RecordID: [16]byte{id}, Action: action, Data: []byte(data), Parents: parents}
	}
	writer, peer := incomingWriter(confirmed, 3)
	seal := func(op syncwire.LocalOperation) ([]byte, [32]byte) {
		t.Helper()
		wire, hash, err := syncwire.SealOperation(writer, op, confirmed.EpochKey, peer)
		require(err)
		writer.Seq++
		writer.PrevHash = hash
		return wire, hash
	}
	newLog := func(wires ...[]byte) *syncrelay.Log {
		t.Helper()
		log := syncrelay.NewLog(128, 128*syncrelay.MaxEnvelopeSize)
		for _, wire := range wires {
			_, err := log.Append(wire)
			require(err)
		}
		return log
	}
	var common [][]byte
	var root1 [32]byte
	for range syncrelay.MaxPageSize - 1 {
		op := operation(1, syncmerge.Put, "common history")
		if root1 != [32]byte{} {
			op.Parents = append(op.Parents, root1)
		}
		var wire []byte
		wire, root1 = seal(op)
		common = append(common, wire)
	}
	rootWire, root2 := seal(operation(2, syncmerge.Put, "second root"))
	common = append(common, rootWire)
	prefix := newLog(common...)
	page, err := prefix.List(0, syncrelay.MaxPageSize)
	require(err)
	require(AcceptPage(ctx, store, confirmed, 0, page, uint64(len(common))))

	queue := func(command string, op syncwire.LocalOperation) []byte {
		t.Helper()
		wire, err := QueueLocal(ctx, store, confirmed, signer, command, op)
		require(err)
		return wire
	}
	echo := queue("echo", operation(4, syncmerge.Put, "accepted on relay"))
	queue("edit1", operation(1, syncmerge.Put, "local candidate", root1))
	queue("edit2", operation(2, syncmerge.Put, "keep locally", root2))
	edit, _ := seal(operation(1, syncmerge.Put, "peer candidate", root1))
	deletion, _ := seal(operation(2, syncmerge.Delete, "", root2))
	independent, independentID := seal(operation(3, syncmerge.Put, "peer only"))
	tail, _ := seal(operation(3, syncmerge.Put, "after reviewed cursor", independentID))
	require(store.DisconnectExchange(ctx, confirmed.Binding, read().Generation))
	before := read()
	b := confirmed.Binding

	point := func(wires [][]byte) ReconnectCheckpoint {
		t.Helper()
		data, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, wires, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
		require(err)
		t.Cleanup(func() { clear(data) })
		return ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
			CheckpointHash: sha256.Sum256(data), Wire: data}
	}
	reviewed := append(slices.Clone(common), echo, edit, deletion, independent)
	remote := point(reviewed)
	through := uint64(len(reviewed))
	log := newLog(append(slices.Clone(reviewed), tail)...)
	reader := &previewReader{Store: store}
	got, err := PreviewReconnectMerge(ctx, reader, confirmed, remote, log, through)
	require(err)
	recordID := func(first byte) string {
		id := [16]byte{first}
		return hex.EncodeToString(id[:])
	}
	want := ReconnectMergePreview{Generation: before.Generation, CheckpointHash: remote.CheckpointHash, Cursor: through, Unsent: 2,
		Records: []ReconnectMergeRecord{
			{ID: recordID(1), Local: ReconnectVersionCounts{Versions: 1}, Merged: ReconnectVersionCounts{Versions: 2}},
			{ID: recordID(2), Local: ReconnectVersionCounts{Versions: 1}, Merged: ReconnectVersionCounts{Versions: 2, Deletions: 1}},
			{ID: recordID(3), Merged: ReconnectVersionCounts{Versions: 1}},
		},
	}
	if !reflect.DeepEqual(got, want) || reader.reads != 1 {
		t.Fatalf("got %+v after %d reads, want %+v after one read", got, reader.reads, want)
	}

	tampered := remote
	tampered.CheckpointHash[0] ^= 1
	substituted := slices.Clone(reviewed)
	substituted[0] = []byte("an envelope absent from the local prefix")
	missingDependency := append(slices.Clone(reviewed[:len(reviewed)-2]), independent, tail)
	for _, test := range []struct {
		name    string
		remote  ReconnectCheckpoint
		log     *syncrelay.Log
		through uint64
		want    error
	}{
		{"truncated", remote, newLog(reviewed[:len(reviewed)-1]...), through, ErrReconnectRelayLog},
		{"substituted prefix", remote, newLog(substituted...), through, ErrReconnectRelayLog},
		{"checkpoint needs an entry after the cursor", remote, log, through - 1, ErrReconnectCheckpoint},
		{"different checkpoint at the same cursor", point(reviewed[:len(reviewed)-1]), log, through, ErrReconnectCheckpoint},
		{"invalid hash", tampered, log, through, ErrReconnectCheckpoint},
		{"missing dependency", remote, newLog(missingDependency...), through, syncwire.ErrReplayPending},
		{"cursor exceeds journal limit", remote, log, replicastore.MaxExchangeEnvelopes + 1, replicastore.ErrLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := PreviewReconnectMerge(t.Context(), store, confirmed, test.remote, test.log, test.through)
			if !errors.Is(err, test.want) || !reflect.DeepEqual(result, ReconnectMergePreview{}) {
				t.Fatalf("result = %+v, error = %v, want zero result and %v", result, err, test.want)
			}
		})
	}
	if !reflect.DeepEqual(read(), before) || requests.Load() != 0 {
		t.Fatal("preview changed the stored replica or contacted the relay")
	}
}

func TestPreviewReconnectMergeRejectsUnresolvedLocalJournal(t *testing.T) {
	ctx := t.Context()
	store, _, confirmed, signer := queueFixture(t)
	read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
	queueForRun(t, store, confirmed, signer, "queued")
	peer, key := incomingWriter(confirmed, 3)
	waiting, _ := sealIncoming(t, peer, confirmed.EpochKey, key, []byte("waiting"), [32]byte{1})
	if err := store.CommitExchange(ctx, confirmed, read().Generation, []replicastore.ExchangeEnvelope{{Wire: waiting}}, 0, 7); err != nil {
		t.Fatal(err)
	}

	log := syncrelay.NewLog(8, 8*syncrelay.MaxEnvelopeSize)
	// The saved relay prefix is intact, but the local journal has an additional dependency.
	other, otherKey := incomingWriter(confirmed, 4)
	wires := make([][]byte, 0, 7)
	entries := make([]replicastore.ExchangeEnvelope, 0, 7)
	for i := range 7 {
		wire, hash := sealIncoming(t, other, confirmed.EpochKey, otherKey, []byte{byte(i)})
		wires = append(wires, wire)
		entries = append(entries, replicastore.ExchangeEnvelope{Wire: wire})
		if _, err := log.Append(wire); err != nil {
			t.Fatal(err)
		}
		other.Seq++
		other.PrevHash = hash
	}
	if err := store.CommitExchange(ctx, confirmed, read().Generation, entries, 0, 7); err != nil {
		t.Fatal(err)
	}
	b := confirmed.Binding
	if err := store.DisconnectExchange(ctx, b, read().Generation); err != nil {
		t.Fatal(err)
	}
	before := read()
	wire, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, wires, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	remote := ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
		CheckpointHash: sha256.Sum256(wire), Wire: wire}
	result, err := PreviewReconnectMerge(ctx, store, confirmed, remote, log, 7)
	if !errors.Is(err, syncwire.ErrReplayPending) || !reflect.DeepEqual(result, ReconnectMergePreview{}) || !reflect.DeepEqual(read(), before) {
		t.Fatalf("pending local dependency produced result %+v, err %v, or changed the replica", result, err)
	}
}
