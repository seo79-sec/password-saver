package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

type previewReader struct {
	*replicastore.Store
	reads int
}

func (r *previewReader) ReadExchange(ctx context.Context, confirmed replicastore.ExchangeContext) (replicastore.ExchangeView, error) {
	r.reads++
	return r.Store.ReadExchange(ctx, confirmed)
}

func TestPreviewReconnectDiff(t *testing.T) {
	for _, mode := range []string{"confirmed", "unsent", "pending"} {
		t.Run(mode, func(t *testing.T) {
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
			store, err := replicastore.Create(ctx, filepath.Join(t.TempDir(), "preview.sqlite"), queueTestKey)
			require(err)
			t.Cleanup(func() { _ = store.Close() })
			read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
			require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 7))

			seal := func(h syncwire.Header, signer ed25519.PrivateKey, id byte, action syncmerge.Action, data string, parents ...[32]byte) ([]byte, [32]byte) {
				t.Helper()
				op := syncwire.LocalOperation{RecordID: [16]byte{id}, Action: action, Data: []byte(data), Parents: parents}
				wire, digest, err := syncwire.SealOperation(h, op, confirmed.EpochKey, signer)
				require(err)
				return wire, digest
			}
			writer, peer := incomingWriter(confirmed, 3)
			root, parent := seal(writer, peer, 2, syncmerge.Put, "base")
			writer.Seq, writer.PrevHash = 2, parent
			edit, _ := seal(writer, peer, 2, syncmerge.Put, "private edit", parent)
			other, otherPeer := incomingWriter(confirmed, 4)
			deletion, _ := seal(other, otherPeer, 2, syncmerge.Delete, "", parent)
			remoteWriter, remotePeer := incomingWriter(confirmed, 5)
			remoteOnly, _ := seal(remoteWriter, remotePeer, 3, syncmerge.Put, "private remote")
			require(AcceptPage(ctx, store, confirmed, 7, []syncrelay.Entry{
				{Cursor: 8, Wire: root}, {Cursor: 9, Wire: edit}, {Cursor: 10, Wire: deletion},
			}, 10))
			_, err = QueueLocal(ctx, store, confirmed, signer, "local", syncwire.LocalOperation{
				RecordID: [16]byte{1}, Action: syncmerge.Put, Data: []byte("private local"),
			})
			require(err)
			unsent, pending := 0, 0
			if mode == "unsent" {
				unsent = 1
			} else {
				require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 1, 10))
			}
			b := confirmed.Binding
			point := func(wire []byte) ReconnectCheckpoint {
				return ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch, MembershipHash: b.MembershipHash,
					CheckpointHash: sha256.Sum256(wire), Wire: wire}
			}
			local, err := replayRemovalCheckpoint(confirmed, read().State)
			require(err)
			defer clear(local)
			remote, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, [][]byte{root, edit, remoteOnly}, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
			require(err)
			defer clear(remote)
			if mode == "pending" {
				remoteWriter.Seq, remoteWriter.PrevHash = 2, sha256.Sum256(remoteOnly)
				waiting, _ := seal(remoteWriter, remotePeer, 3, syncmerge.Put, "waiting")
				require(AcceptPage(ctx, store, confirmed, 10, []syncrelay.Entry{{Cursor: 11, Wire: waiting}}, 11))
				pending = 1
			}
			require(store.DisconnectExchange(ctx, b, read().Generation))
			if mode == "confirmed" {
				require(ConfirmReconnect(ctx, store, confirmed, point(local),
					replicastore.ReconnectConfirmation{Generation: read().Generation, CheckpointHash: sha256.Sum256(local)}))
			}
			before := read()
			reader := &previewReader{Store: store}
			preview := func(checkpoint ReconnectCheckpoint, want ReconnectComparison, records []ReconnectRecordDiff) {
				t.Helper()
				count := reader.reads
				got, err := PreviewReconnectDiff(ctx, reader, confirmed, checkpoint)
				expected := ReconnectDiff{ReconnectInspection: ReconnectInspection{Generation: before.Generation,
					Unsent: unsent, Pending: pending, Comparison: want}, CheckpointHash: checkpoint.CheckpointHash, Records: records}
				if err != nil || reader.reads != count+1 || !reflect.DeepEqual(got, expected) {
					t.Fatalf("preview got %+v, want %+v in one read: %v", got, expected, err)
				}
			}
			switch mode {
			case "pending":
				preview(point(remote), ReconnectDeferred, nil)
			default:
				preview(point(local), ReconnectMatch, nil)
				ids := func(id byte) string { idBytes := [16]byte{id}; return hex.EncodeToString(idBytes[:]) }
				preview(point(remote), ReconnectMismatch, []ReconnectRecordDiff{
					{ID: ids(1), Side: ReconnectLocalOnly, Local: ReconnectVersionCounts{Versions: 1}},
					{ID: ids(2), Side: ReconnectBoth, Local: ReconnectVersionCounts{Versions: 2, Deletions: 1}, Remote: ReconnectVersionCounts{Versions: 1}},
					{ID: ids(3), Side: ReconnectRemoteOnly, Remote: ReconnectVersionCounts{Versions: 1}},
				})
				// Keep accepted history but remove the writer heads from the canonical array.
				var fields []cbor.RawMessage
				require(cbor.Unmarshal(local, &fields))
				fields[3] = cbor.RawMessage{0xa0}
				sameSnapshot, err := cbor.Marshal(fields)
				require(err)
				defer clear(sameSnapshot)
				preview(point(sameSnapshot), ReconnectMismatch, nil)
			}
			tampered := point(remote)
			tampered.Wire = bytes.Clone(remote)
			tampered.Wire[len(remote)-1] ^= 1
			foreign := point(remote)
			foreign.SpaceID[0] ^= 1
			for _, invalid := range []ReconnectCheckpoint{tampered, foreign} {
				got, err := PreviewReconnectDiff(ctx, reader, confirmed, invalid)
				if !errors.Is(err, ErrReconnectCheckpoint) || !reflect.DeepEqual(got, ReconnectDiff{}) {
					t.Fatalf("invalid checkpoint returned %+v, %v", got, err)
				}
			}
			if got := read(); !reflect.DeepEqual(got, before) || requests.Load() != 0 {
				t.Fatal("preview changed the exchange or contacted the relay")
			}
		})
	}
}
