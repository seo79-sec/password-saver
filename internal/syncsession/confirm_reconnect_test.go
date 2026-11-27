package syncsession

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

func TestConfirmReconnect(t *testing.T) {
	for _, test := range []struct {
		name string
		want error
	}{
		{"matching", nil},
		{"stale generation", replicastore.ErrGeneration},
		{"different hash", replicastore.ErrReconnectConfirmation},
		{"earlier checkpoint", ErrReconnectNotReady},
		{"unacknowledged operation", ErrReconnectNotReady},
		{"pending dependency", ErrReconnectNotReady},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			require := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, _, confirmed, signer := queueFixture(t)
			point := func() ReconnectCheckpoint {
				t.Helper()
				wire, err := replayRemovalCheckpoint(confirmed, readQueue(t, store, confirmed).State)
				require(err)
				t.Cleanup(func() { clear(wire) })
				b := confirmed.Binding
				return ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
					CheckpointHash: sha256.Sum256(wire), Wire: wire}
			}
			earlier := point()
			queueForRun(t, store, confirmed, signer, "local")
			if test.name != "unacknowledged operation" {
				require(store.CommitExchange(ctx, confirmed, readQueue(t, store, confirmed).Generation, nil, 1, 7))
			}
			remote := point()
			if test.name == "pending dependency" {
				header, peer := incomingWriter(confirmed, 3)
				_, predecessor := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("missing"))
				header.Seq, header.PrevHash = 2, predecessor
				waiting, _ := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("waiting"))
				require(AcceptPage(ctx, store, confirmed, 7, []syncrelay.Entry{{Cursor: 8, Wire: waiting}}, 8))
			}
			require(store.DisconnectExchange(ctx, confirmed.Binding, readQueue(t, store, confirmed).Generation))
			before := readQueue(t, store, confirmed)
			if test.name == "earlier checkpoint" {
				remote = earlier
			}
			inspection, err := InspectReconnect(ctx, store, confirmed, remote)
			require(err)
			owner := replicastore.ReconnectConfirmation{Generation: inspection.Generation, CheckpointHash: remote.CheckpointHash}
			switch test.name {
			case "stale generation":
				owner.Generation--
			case "different hash":
				owner.CheckpointHash[0] ^= 1
			}

			if err := ConfirmReconnect(ctx, store, confirmed, remote, owner); !errors.Is(err, test.want) {
				t.Fatalf("confirmation: got %v, want %v", err, test.want)
			}
			expected := before
			if test.want == nil {
				expected.Generation++
				expected.State.ReconnectConfirmation = &owner
				require(ConfirmReconnect(ctx, store, confirmed, remote, owner))
				fresh := owner
				fresh.Generation++
				if err := ConfirmReconnect(ctx, store, confirmed, remote, fresh); !errors.Is(err, replicastore.ErrReconnectConfirmation) {
					t.Fatalf("alternative confirmation: %v", err)
				}
				// A nil transport fails the test if RunOnce attempts any network call.
				session := NewSession(store, confirmed, nil)
				session.SetAccess(true, true)
				if err := session.RunOnce(ctx); !errors.Is(err, replicastore.ErrExchangeDisconnected) {
					t.Fatalf("run after confirmation: %v", err)
				}
			}
			if got := readQueue(t, store, confirmed); !reflect.DeepEqual(got, expected) {
				t.Fatal("confirmation unexpectedly changed exchange state")
			}
		})
	}
}
