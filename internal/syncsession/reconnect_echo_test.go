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
)

func TestReconcileReconnectAcknowledgesExactLocalEchoes(t *testing.T) {
	for _, test := range []struct {
		name            string
		initialPeer     int
		receivesNewPeer bool
	}{
		{"both echoes in saved prefix", 5, false},
		{"echo after saved cursor", 6, false},
		{"echo and new peer operation", 6, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			require := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, path, confirmed, signer := queueFixture(t)
			read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
			first := queueForRun(t, store, confirmed, signer, "first unacknowledged send")
			second := queueForRun(t, store, confirmed, signer, "second unacknowledged send")
			header, peer := incomingWriter(confirmed, 3)
			initial := make([]replicastore.ExchangeEnvelope, 0, test.initialPeer)
			log := syncrelay.NewLog(9, 9*syncrelay.MaxEnvelopeSize)
			appendWire := func(log *syncrelay.Log, wire []byte) uint64 {
				t.Helper()
				cursor, err := log.Append(wire)
				require(err)
				return cursor
			}
			for i := range test.initialPeer {
				wire, hash := sealIncoming(t, header, confirmed.EpochKey, peer, []byte{byte(i)})
				initial = append(initial, replicastore.ExchangeEnvelope{Wire: wire})
				appendWire(log, wire)
				header.Seq++
				header.PrevHash = hash
			}
			appendWire(log, first)
			secondCursor := appendWire(log, second)
			through := secondCursor
			const savedCursor = 7
			require(store.CommitExchange(ctx, confirmed, read().Generation, initial, 0, savedCursor))
			require(store.DisconnectExchange(ctx, confirmed.Binding, read().Generation))
			before := read()

			peerWire, _ := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("new peer operation"))
			expected := *before.State
			if test.receivesNewPeer {
				expected.Journal = append(slices.Clone(expected.Journal), replicastore.ExchangeEnvelope{Wire: peerWire})
				through = appendWire(log, peerWire)
			}
			wire, err := replayRemovalCheckpoint(confirmed, &expected)
			require(err)
			defer clear(wire)
			b := confirmed.Binding
			remote := ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
				CheckpointHash: sha256.Sum256(wire), Wire: wire}
			preview, err := PreviewReconnectDiff(ctx, store, confirmed, remote)
			require(err)
			wantComparison := ReconnectMatch
			if test.receivesNewPeer {
				wantComparison = ReconnectMismatch
			}
			if preview.Unsent != 2 || preview.Comparison != wantComparison {
				t.Fatalf("unexpected initial review: %+v", preview)
			}
			owner := ReconnectReconciliation{Generation: preview.Generation, CheckpointHash: preview.CheckpointHash, Cursor: through}

			if secondCursor > savedCursor {
				partial := owner
				partial.Cursor = savedCursor
				if err := ReconcileReconnect(ctx, store, confirmed, remote, log, partial); !errors.Is(err, ErrReconnectNotReady) || !reflect.DeepEqual(read(), before) {
					t.Fatalf("echo beyond the reviewed cursor changed the replica: %v", err)
				}
				missing := syncrelay.NewLog(9, 9*syncrelay.MaxEnvelopeSize)
				for _, entry := range initial {
					appendWire(missing, entry.Wire)
				}
				appendWire(missing, first)
				appendWire(missing, peerWire)
				if test.receivesNewPeer {
					appendWire(missing, []byte("unrelated relay entry"))
				}
				if err := ReconcileReconnect(ctx, store, confirmed, remote, missing, owner); !errors.Is(err, ErrReconnectNotReady) || !reflect.DeepEqual(read(), before) {
					t.Fatalf("unrelated envelope acknowledged a local send: %v", err)
				}
			}
			fault := reconnectSuffixFaultStore{Store: store, commit: true, fault: replicastore.ErrCommitUnknown}
			if err := ReconcileReconnect(ctx, fault, confirmed, remote, log, owner); !errors.Is(err, replicastore.ErrCommitUnknown) {
				t.Fatalf("lost commit response returned %v", err)
			}
			require(store.Close())
			store, err = replicastore.Open(ctx, path, queueTestKey)
			require(err)
			defer store.Close()
			require(ReconcileReconnect(ctx, store, confirmed, remote, log, owner))
			after := read()
			expected.Cursor, expected.SentSequence = through, 2
			if after.Generation != before.Generation+1 || !reflect.DeepEqual(after.State, &expected) {
				t.Fatal("reconciliation did not atomically acknowledge both sends and record the reviewed cursor")
			}
			require(ConfirmReconnect(ctx, store, confirmed, remote, replicastore.ReconnectConfirmation{
				Generation: after.Generation, CheckpointHash: remote.CheckpointHash,
			}))
			proof, err := VerifyReconnectRelayLog(ctx, store, confirmed, log)
			require(err)
			pulls := 0
			relay := runRelay{
				push: func(context.Context, []byte) (uint64, error) {
					t.Fatal("exchange resent an acknowledged local envelope")
					return 0, nil
				},
				pull: func(_ context.Context, after uint64, _ int) ([]syncrelay.Entry, uint64, error) {
					pulls++
					if after != through {
						t.Fatalf("pull started at %d, want %d", after, through)
					}
					return nil, after, nil
				},
			}
			session, err := NewReconnectSession(ctx, store, confirmed, log, proof, func(*syncrelay.Log) (Relay, error) {
				return relay, nil
			})
			require(err)
			session.SetAccess(true, true)
			require(session.RunOnce(ctx))
			if pulls != 1 {
				t.Fatalf("expected one pull, got %d", pulls)
			}
		})
	}
}
