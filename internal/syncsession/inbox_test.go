package syncsession

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

func incomingWriter(confirmed replicastore.ExchangeContext, id byte) (syncwire.Header, ed25519.PrivateKey) {
	device, seed := [16]byte{id}, [ed25519.SeedSize]byte{id}
	signer := ed25519.NewKeyFromSeed(seed[:])
	confirmed.Signers[device] = signer.Public().(ed25519.PublicKey)
	return syncwire.Header{Type: 1, Version: 1, SpaceID: confirmed.Binding.SpaceID, Epoch: confirmed.Binding.Epoch, DeviceID: device, Seq: 1}, signer
}

func sealIncoming(t *testing.T, header syncwire.Header, key []byte, signer ed25519.PrivateKey, data []byte, parents ...[32]byte) ([]byte, [32]byte) {
	t.Helper()
	op := syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put, Data: data, Parents: parents}
	wire, hash, err := syncwire.SealOperation(header, op, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	return wire, hash
}

func TestAcceptPageWaitingSurvivesReopenAndEcho(t *testing.T) {
	store, path, confirmed, localSigner := queueFixture(t)
	parentWriter, parentSigner := incomingWriter(confirmed, 3)
	childWriter, childSigner := incomingWriter(confirmed, 4)
	parent, parentID := sealIncoming(t, parentWriter, confirmed.EpochKey, parentSigner, []byte("parent"))
	child, childID := sealIncoming(t, childWriter, confirmed.EpochKey, childSigner, []byte("child"), parentID)
	initial := readQueue(t, store, confirmed)
	if err := AcceptPage(t.Context(), store, confirmed, 7, []syncrelay.Entry{{Cursor: 8, Wire: child}}, 8); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := replicastore.Open(t.Context(), path, queueTestKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	waiting := readQueue(t, store, confirmed)
	if waiting.Generation != initial.Generation+1 || waiting.State.Cursor != 8 || len(waiting.State.Journal) != 1 ||
		len(waiting.Pending) != 1 || !bytes.Equal(waiting.Pending[0], child) || len(waiting.Snapshot) != 0 {
		t.Fatal("the waiting child and its cursor were not saved together")
	}
	page := []syncrelay.Entry{{Cursor: 9, Wire: parent}, {Cursor: 10, Wire: parent}}
	if err := AcceptPage(t.Context(), store, confirmed, 8, page, 10); err != nil {
		t.Fatal(err)
	}
	resolved := readQueue(t, store, confirmed)
	if resolved.State.Cursor != 10 || len(resolved.State.Journal) != 2 || len(resolved.Pending) != 0 ||
		resolved.Heads[childWriter.DeviceID].Hash != childID || len(resolved.Snapshot) != 1 ||
		len(resolved.Snapshot[0].Versions) != 1 || string(resolved.Snapshot[0].Versions[0].Data) != "child" {
		t.Fatal("the next page did not resolve the waiting child exactly once")
	}
	op := syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put, Parents: [][32]byte{childID}, Data: []byte("local")}
	local, err := QueueLocal(t.Context(), store, confirmed, localSigner, "test command", op)
	if err != nil {
		t.Fatal(err)
	}
	beforeEcho := readQueue(t, store, confirmed)
	page = []syncrelay.Entry{{Cursor: 11, Wire: local}, {Cursor: 12, Wire: child}}
	if err := AcceptPage(t.Context(), store, confirmed, 10, page, 12); err != nil {
		t.Fatal(err)
	}
	afterEcho := readQueue(t, store, confirmed)
	if afterEcho.Generation != beforeEcho.Generation+1 || afterEcho.State.Cursor != 12 ||
		afterEcho.State.SentSequence != beforeEcho.State.SentSequence || !reflect.DeepEqual(afterEcho.State.Journal, beforeEcho.State.Journal) ||
		!reflect.DeepEqual(afterEcho.ReplayResult, beforeEcho.ReplayResult) {
		t.Fatal("echo and repeat should advance only the stored read cursor and generation")
	}
}

func TestAcceptPageRejectsWholePage(t *testing.T) {
	store, _, confirmed, _ := queueFixture(t)
	header, signer := incomingWriter(confirmed, 3)
	first, firstID := sealIncoming(t, header, confirmed.EpochKey, signer, []byte("valid"))
	fork, _ := sealIncoming(t, header, confirmed.EpochKey, signer, []byte("fork"))
	header.Seq, header.PrevHash = 2, firstID
	badSignature, _ := sealIncoming(t, header, confirmed.EpochKey, signer, []byte("second"), firstID)
	badSignature[len(badSignature)-1] ^= 1
	var overQuota []syncrelay.Entry
	for i := uint64(0); i < 5; i++ {
		header.Seq = i + 2
		wire, _ := sealIncoming(t, header, confirmed.EpochKey, signer, make([]byte, 60<<10))
		overQuota = append(overQuota, syncrelay.Entry{Cursor: 8 + i, Wire: wire})
	}
	before := readQueue(t, store, confirmed)
	for _, test := range []struct {
		name        string
		after, next uint64
		entries     []syncrelay.Entry
		cause       error
	}{
		{"bad signature", 7, 9, []syncrelay.Entry{{Cursor: 8, Wire: first}, {Cursor: 9, Wire: badSignature}}, nil},
		{"fork", 7, 9, []syncrelay.Entry{{Cursor: 8, Wire: first}, {Cursor: 9, Wire: fork}}, syncwire.ErrChangeFork},
		{"pending quota", 7, 12, overQuota, syncwire.ErrReplayPendingLimit},
		{"stale cursor", 6, 7, []syncrelay.Entry{{Cursor: 7, Wire: first}}, ErrPageCursor},
		{"cursor gap", 7, 9, []syncrelay.Entry{{Cursor: 9, Wire: first}}, ErrInvalidPage},
		{"wrong next", 7, 9, []syncrelay.Entry{{Cursor: 8, Wire: first}}, ErrInvalidPage},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := AcceptPage(t.Context(), store, confirmed, test.after, test.entries, test.next)
			if err == nil || (test.cause != nil && !errors.Is(err, test.cause)) {
				t.Fatalf("expected page rejection, got %v", err)
			}
			if !reflect.DeepEqual(readQueue(t, store, confirmed), before) {
				t.Fatal("a rejected page changed the journal, cursor or generation")
			}
		})
	}
}
