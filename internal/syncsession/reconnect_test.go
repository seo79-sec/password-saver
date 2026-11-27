package syncsession

import (
	"bytes"
	"context"
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

type reconnectSnapshotReader struct {
	view replicastore.ExchangeView
}

func (r reconnectSnapshotReader) ReadExchange(context.Context, replicastore.ExchangeContext) (replicastore.ExchangeView, error) {
	return r.view, nil
}

func TestInspectReconnect(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		pending int
	}{{"complete journal", 0}, {"unresolved incoming envelope", 1}} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := t.Context()
			require := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, _, confirmed, signer := queueFixture(t)
			var requests atomic.Int32
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(relay.Close)
			confirmed.Binding.RelayURL = relay.URL
			store, err := replicastore.Create(ctx, filepath.Join(t.TempDir(), "replica.sqlite"), [replicastore.KeySize]byte{1})
			require(err)
			t.Cleanup(func() { _ = store.Close() })
			require(store.CommitExchange(ctx, confirmed, readQueue(t, store, confirmed).Generation, nil, 0, 7))

			point := func(wire []byte) ReconnectCheckpoint {
				b := confirmed.Binding
				return ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
					CheckpointHash: sha256.Sum256(wire), Wire: wire}
			}
			checkpoint := func() ReconnectCheckpoint {
				t.Helper()
				wire, err := replayRemovalCheckpoint(confirmed, readQueue(t, store, confirmed).State)
				require(err)
				t.Cleanup(func() { clear(wire) })
				return point(wire)
			}
			earlier := checkpoint()
			if got, err := InspectReconnect(ctx, store, confirmed, earlier); !errors.Is(err, ErrReconnectRequiresDisconnect) || got != (ReconnectInspection{}) {
				t.Fatalf("connected replica: %+v, %v", got, err)
			}
			queueForRun(t, store, confirmed, signer, "acknowledged")
			queueForRun(t, store, confirmed, signer, "offline edit")
			require(store.CommitExchange(ctx, confirmed, readQueue(t, store, confirmed).Generation, nil, 1, 7))
			matching := checkpoint()

			if scenario.pending != 0 {
				header, peer := incomingWriter(confirmed, 3)
				_, predecessor := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("missing"))
				header.Seq, header.PrevHash = 2, predecessor
				waiting, _ := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("waiting"))
				require(AcceptPage(ctx, store, confirmed, 7, []syncrelay.Entry{{Cursor: 8, Wire: waiting}}, 8))
			}
			require(store.DisconnectExchange(ctx, confirmed.Binding, readQueue(t, store, confirmed).Generation))
			before := readQueue(t, store, confirmed)
			compare := func(reader reconnectReader, input replicastore.ExchangeContext, remote ReconnectCheckpoint, want ReconnectComparison) {
				t.Helper()
				got, err := InspectReconnect(ctx, reader, input, remote)
				expected := ReconnectInspection{Generation: before.Generation, Unsent: 1, Pending: scenario.pending, Comparison: want}
				if err != nil || got != expected {
					t.Fatalf("inspection %+v, want %+v: %v", got, expected, err)
				}
			}
			if scenario.pending != 0 {
				compare(store, confirmed, matching, ReconnectDeferred)
				compare(store, confirmed, earlier, ReconnectDeferred)
			} else {
				compare(store, confirmed, matching, ReconnectMatch)
				compare(store, confirmed, earlier, ReconnectMismatch)

				// The activated metadata supplies the writer even if the caller has no writer map.
				activated, state := before, *before.State
				writer := confirmed.Signers[confirmed.Binding.DeviceID]
				state.ActivatedRemoval = &replicastore.ActivatedRemoval{SigningPub: [32]byte(writer)}
				activated.State = &state
				withoutSigners := confirmed
				withoutSigners.Signers = nil
				compare(reconnectSnapshotReader{activated}, withoutSigners, matching, ReconnectMatch)
			}

			tampered := matching
			tampered.Wire = bytes.Clone(matching.Wire)
			tampered.Wire[len(tampered.Wire)-1] ^= 1
			space, epoch, membership := matching, matching, matching
			space.SpaceID[0] ^= 1
			epoch.Epoch++
			membership.MembershipHash[0] ^= 1
			for name, remote := range map[string]ReconnectCheckpoint{
				"tampered bytes": tampered, "other space": space, "other epoch": epoch, "other membership": membership,
				"wrong source epoch with correct hash": point(confirmed.Checkpoint), "malformed with correct hash": point([]byte{0xff}),
			} {
				if got, err := InspectReconnect(ctx, store, confirmed, remote); !errors.Is(err, ErrReconnectCheckpoint) || got != (ReconnectInspection{}) {
					t.Fatalf("%s: got %+v, %v", name, got, err)
				}
			}
			if after := readQueue(t, store, confirmed); !after.State.Disconnected || !reflect.DeepEqual(after, before) || requests.Load() != 0 {
				t.Fatal("inspection changed the replica or contacted the relay")
			}
		})
	}
}
