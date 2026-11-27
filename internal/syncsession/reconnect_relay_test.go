package syncsession

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

func TestVerifyReconnectRelayLog(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, confirmed, _ := queueFixture(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	confirmed.Binding.RelayURL = server.URL
	store, err := replicastore.Create(ctx, filepath.Join(t.TempDir(), "replica.sqlite"), [replicastore.KeySize]byte{1})
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() replicastore.ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		require(err)
		return view
	}

	const count = syncrelay.MaxPageSize + 3
	matching := syncrelay.NewLog(count+1, (count+1)*syncrelay.MaxEnvelopeSize)
	short := syncrelay.NewLog(count, count*syncrelay.MaxEnvelopeSize)
	foreign := syncrelay.NewLog(count, count*syncrelay.MaxEnvelopeSize)
	appendWire := func(log *syncrelay.Log, wire []byte, want uint64) {
		t.Helper()
		got, err := log.Append(wire)
		if err != nil || got != want {
			t.Fatalf("append returned cursor %d, want %d: %v", got, want, err)
		}
	}
	header, peer := incomingWriter(confirmed, 3)
	for position := 1; position <= count; position++ {
		wire, hash := sealIncoming(t, header, confirmed.EpochKey, peer, []byte{byte(position)})
		appendWire(matching, wire, uint64(position))
		if position < count {
			appendWire(short, wire, uint64(position))
			appendWire(foreign, wire, uint64(position))
		}
		header.Seq++
		header.PrevHash = hash
	}
	appendWire(foreign, []byte("unknown instead of last envelope"), count)
	appendWire(matching, []byte("unknown after saved cursor"), count+1)

	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 0))
	for after := uint64(0); after < count; {
		page, err := matching.List(after, int(min(count-after, syncrelay.MaxPageSize)))
		require(err)
		next := after + uint64(len(page))
		require(AcceptPage(ctx, store, confirmed, after, page, next))
		after = next
	}
	require(store.DisconnectExchange(ctx, confirmed.Binding, read().Generation))
	assertRejected := func(reader reconnectReader, log *syncrelay.Log, want error) {
		t.Helper()
		got, err := VerifyReconnectRelayLog(ctx, reader, confirmed, log)
		if !errors.Is(err, want) || got != (ReconnectRelayVerification{}) {
			t.Fatalf("rejected log: got %+v and %v, want %v", got, err, want)
		}
	}
	assertRejected(store, matching, replicastore.ErrReconnectConfirmation)

	beforeConfirm := read()
	wire, err := replayRemovalCheckpoint(confirmed, beforeConfirm.State)
	require(err)
	defer clear(wire)
	b := confirmed.Binding
	hash := sha256.Sum256(wire)
	owner := replicastore.ReconnectConfirmation{Generation: beforeConfirm.Generation, CheckpointHash: hash}
	require(ConfirmReconnect(ctx, store, confirmed, ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch,
		MembershipHash: b.MembershipHash, CheckpointHash: hash, Wire: wire}, owner))
	before := read()

	proof, err := VerifyReconnectRelayLog(ctx, store, confirmed, matching)
	require(err)
	if proof != (ReconnectRelayVerification{replicaID: store.Identity(), log: matching, binding: b, generation: before.Generation,
		cursor: count, confirmation: owner}) {
		t.Fatal("verification lost the identity or state it checked")
	}
	assertRejected(store, short, ErrReconnectRelayLog)
	assertRejected(store, foreign, ErrReconnectRelayLog)
	invalid := before
	invalid.Generation++
	assertRejected(reconnectSnapshotReader{invalid}, matching, replicastore.ErrReconnectConfirmation)
	invalid = before
	invalid.Pending = [][]byte{{1}}
	assertRejected(reconnectSnapshotReader{invalid}, matching, ErrReconnectNotReady)
	invalid, state := before, *before.State
	state.Journal = append([]replicastore.ExchangeEnvelope{{Sequence: 1}}, state.Journal...)
	invalid.State = &state
	assertRejected(reconnectSnapshotReader{invalid}, matching, ErrReconnectNotReady)

	if got := read(); !reflect.DeepEqual(got, before) || requests.Load() != 0 {
		t.Fatal("verification changed SQLite state or called the relay over HTTPS")
	}
}

func TestVerifyReconnectRelayPrefixBounds(t *testing.T) {
	ctx := t.Context()
	noRead := func(uint64, int) ([]syncrelay.Entry, error) {
		t.Fatal("cursor zero must not read a page")
		return nil, nil
	}
	if err := verifyReconnectRelayPrefix(ctx, noRead, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{"wire": {}}
	gap := func(after uint64, limit int) ([]syncrelay.Entry, error) {
		if after != 0 || limit != 1 {
			t.Fatalf("list beyond the saved cursor: after %d, limit %d", after, limit)
		}
		return []syncrelay.Entry{{Cursor: 2, Wire: []byte("wire")}}, nil
	}
	if err := verifyReconnectRelayPrefix(ctx, gap, 1, seen, nil); !errors.Is(err, ErrReconnectRelayLog) {
		t.Fatalf("gap in relay positions: %v", err)
	}
}
