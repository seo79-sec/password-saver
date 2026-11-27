package syncsession

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

type reconnectSuffixFaultStore struct {
	*replicastore.Store
	fault  error
	commit bool
}

func (s reconnectSuffixFaultStore) ApplyReconnectSuffix(ctx context.Context, confirmed replicastore.ExchangeContext, expected int64, after, through uint64, wires [][]byte) error {
	if s.commit {
		if err := s.Store.ApplyReconnectSuffix(ctx, confirmed, expected, after, through, wires); err != nil {
			return err
		}
	}
	return s.fault
}

func TestReconcileReconnect(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	store, path, confirmed, signer := queueFixture(t)
	read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
	local := queueForRun(t, store, confirmed, signer, "sent before the cursor advanced")
	header, peer := incomingWriter(confirmed, 3)
	const through = 7 + syncrelay.MaxPageSize + 3
	wires := make([][]byte, 0, through)
	for position := 1; position <= through-1; position++ {
		wire, hash := sealIncoming(t, header, confirmed.EpochKey, peer, []byte{byte(position)})
		wires = append(wires, wire)
		header.Seq++
		header.PrevHash = hash
	}
	// The relay also contains an echo of a previously acknowledged local operation.
	wires = slices.Insert(wires, 7, local)
	logWith := func(wires [][]byte) *syncrelay.Log {
		t.Helper()
		log := syncrelay.NewLog(through+1, (through+1)*syncrelay.MaxEnvelopeSize)
		for index, wire := range wires {
			cursor, err := log.Append(wire)
			require(err)
			if cursor != uint64(index+1) {
				t.Fatalf("append cursor %d at index %d", cursor, index)
			}
		}
		return log
	}
	log := logWith(wires)
	// Establish a replica that already has the first seven relay entries.
	initial := make([]replicastore.ExchangeEnvelope, 7)
	for index, wire := range wires[:7] {
		initial[index].Wire = wire
	}
	require(store.CommitExchange(ctx, confirmed, read().Generation, initial, 1, 7))
	require(store.DisconnectExchange(ctx, confirmed.Binding, read().Generation))
	point := func(state *replicastore.ExchangeState) ReconnectCheckpoint {
		t.Helper()
		wire, err := replayRemovalCheckpoint(confirmed, state)
		require(err)
		t.Cleanup(func() { clear(wire) })
		b := confirmed.Binding
		return ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
			CheckpointHash: sha256.Sum256(wire), Wire: wire}
	}
	currentPoint := point(read().State)
	require(ConfirmReconnect(ctx, store, confirmed, currentPoint, replicastore.ReconnectConfirmation{
		Generation: read().Generation, CheckpointHash: currentPoint.CheckpointHash,
	}))
	before := read()
	candidate := *before.State
	candidate.Journal = slices.Clone(before.State.Journal)
	for _, wire := range wires[8:] {
		candidate.Journal = append(candidate.Journal, replicastore.ExchangeEnvelope{Wire: wire})
	}
	remote := point(&candidate)
	preview, err := PreviewReconnectDiff(ctx, store, confirmed, remote)
	require(err)
	owner := ReconnectReconciliation{Generation: preview.Generation, CheckpointHash: preview.CheckpointHash, Cursor: through}
	brokenPrefix := slices.Clone(wires)
	brokenPrefix[5] = []byte("unknown prefix entry")
	badSuffix := slices.Clone(wires)
	badSuffix[len(badSuffix)-1] = []byte("invalid envelope")
	last, err := syncwire.Parse(wires[len(wires)-1])
	require(err)
	different, _ := sealIncoming(t, last.Header, confirmed.EpochKey, peer, []byte("different valid envelope"))
	differentSuffix := slices.Clone(wires)
	differentSuffix[len(differentSuffix)-1] = different
	waiting, _ := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("missing previous envelope"))
	waitingSuffix := slices.Clone(wires)
	waitingSuffix[len(waitingSuffix)-1] = waiting
	otherEpoch := remote
	otherEpoch.Epoch++
	stale := owner
	stale.Generation--
	for _, test := range []struct {
		name   string
		log    *syncrelay.Log
		remote ReconnectCheckpoint
		owner  ReconnectReconciliation
		want   error
	}{
		{"short suffix", logWith(wires[:len(wires)-1]), remote, owner, ErrReconnectRelayLog},
		{"wrong prefix", logWith(brokenPrefix), remote, owner, ErrReconnectRelayLog},
		{"invalid suffix", logWith(badSuffix), remote, owner, nil},
		{"different checkpoint", logWith(differentSuffix), remote, owner, ErrReconnectCheckpoint},
		{"missing dependency", logWith(waitingSuffix), remote, owner, syncwire.ErrReplayPending},
		{"other epoch", log, otherEpoch, owner, ErrReconnectCheckpoint},
		{"stale generation", log, remote, stale, replicastore.ErrGeneration},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ReconcileReconnect(ctx, store, confirmed, test.remote, test.log, test.owner)
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) || !reflect.DeepEqual(read(), before) {
				t.Fatalf("failed catch-up changed the replica or returned an unexpected error: %v", err)
			}
		})
	}
	injected := errors.New("failure before commit")
	if err := ReconcileReconnect(ctx, reconnectSuffixFaultStore{Store: store, fault: injected}, confirmed, remote, log, owner); !errors.Is(err, injected) || !reflect.DeepEqual(read(), before) {
		t.Fatalf("failed commit changed the replica: %v", err)
	}
	_, err = log.Append([]byte("outside the reviewed cursor"))
	require(err)
	if err := ReconcileReconnect(ctx, reconnectSuffixFaultStore{Store: store, fault: replicastore.ErrCommitUnknown, commit: true}, confirmed, remote, log, owner); !errors.Is(err, replicastore.ErrCommitUnknown) {
		t.Fatalf("lost commit returned %v", err)
	}
	require(store.Close())
	store, err = replicastore.Open(ctx, path, queueTestKey)
	require(err)
	defer store.Close()
	require(ReconcileReconnect(ctx, store, confirmed, remote, log, owner))
	after := read()
	candidate.Cursor, candidate.ReconnectConfirmation = through, nil
	if after.Generation != before.Generation+1 || !reflect.DeepEqual(after.State, &candidate) {
		t.Fatal("catch-up changed journal metadata, confirmation or cursor unexpectedly")
	}
	inspection, err := InspectReconnect(ctx, store, confirmed, remote)
	require(err)
	if inspection.Comparison != ReconnectMatch {
		t.Fatalf("reopened replica did not match the reviewed checkpoint: %+v", inspection)
	}
	session := NewSession(store, confirmed, nil)
	session.SetAccess(true, true)
	if err := session.RunOnce(ctx); !errors.Is(err, replicastore.ErrExchangeDisconnected) {
		t.Fatalf("catch-up enabled exchange: %v", err)
	}
}

func TestReconcileReconnectRejectsUnsentOperation(t *testing.T) {
	ctx := t.Context()
	store, _, confirmed, signer := queueFixture(t)
	queueForRun(t, store, confirmed, signer, "unsent")
	if err := store.DisconnectExchange(ctx, confirmed.Binding, readQueue(t, store, confirmed).Generation); err != nil {
		t.Fatal(err)
	}
	before := readQueue(t, store, confirmed)
	remote, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, nil, confirmed.Binding.SpaceID, confirmed.Binding.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(remote)
	point := ReconnectCheckpoint{SpaceID: confirmed.Binding.SpaceID, Epoch: confirmed.Binding.Epoch,
		MembershipHash: confirmed.Binding.MembershipHash, CheckpointHash: sha256.Sum256(remote), Wire: remote}
	owner := ReconnectReconciliation{Generation: before.Generation, CheckpointHash: point.CheckpointHash, Cursor: 8}
	log := syncrelay.NewLog(8, syncrelay.MaxEnvelopeSize)
	if err := ReconcileReconnect(ctx, store, confirmed, point, log, owner); !errors.Is(err, ErrReconnectNotReady) || !reflect.DeepEqual(readQueue(t, store, confirmed), before) {
		t.Fatalf("catch-up with an unsent operation changed the replica: %v", err)
	}
}
