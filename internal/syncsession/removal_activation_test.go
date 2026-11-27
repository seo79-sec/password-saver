package syncsession

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncwire"
)

func TestPrepareRemovalActivation(t *testing.T) {
	ctx := t.Context()
	require := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	initial, fingerprint, owner, err := syncpair.NewSpace()
	require(t, err)
	now := time.Now()
	request, _, peerKeys, err := syncpair.NewRequest(fingerprint, now)
	require(t, err)
	parsed, _, err := syncpair.ParseRequest(request, now)
	require(t, err)
	peer := parsed.Header
	previous, err := owner.AddMember(initial, fingerprint, syncpair.Member{DeviceID: peer.DeviceID, SigningPub: peer.SigningPub, ExchangePub: peer.ExchangePub})
	require(t, err)
	old, err := syncpair.VerifySignedMembership(previous, fingerprint)
	require(t, err)
	h := old.Header
	epochKey := [32]byte{1}
	base, err := syncwire.NewReceiver(h.SpaceID, h.Epoch-1, epochKey[:], nil).MarshalCheckpoint()
	require(t, err)
	binding := replicastore.ExchangeBinding{SpaceID: h.SpaceID, DeviceID: h.OwnerID, Epoch: h.Epoch,
		MembershipHash: sha256.Sum256(previous), CheckpointHash: sha256.Sum256(base), RelayURL: "https://relay.test"}
	confirmed := replicastore.ExchangeContext{Binding: binding, Checkpoint: base, EpochKey: epochKey[:],
		Signers: map[[16]byte]ed25519.PublicKey{h.OwnerID: h.Members[0].SigningPub[:], peer.DeviceID: peer.SigningPub[:]}}
	header := syncwire.Header{Type: 1, Version: 1, SpaceID: h.SpaceID, Epoch: h.Epoch, DeviceID: h.OwnerID, Seq: 1}
	put := syncwire.LocalOperation{RecordID: [16]byte{1}, Action: syncmerge.Put, Data: []byte("initial")}
	ownerSigner := owner.DeviceSigningKey()
	defer clear(ownerSigner)
	parent, hash, err := syncwire.SealOperation(header, put, epochKey[:], ownerSigner)
	require(t, err)
	put.Parents, put.Data = [][32]byte{hash}, []byte("edit")
	header.Seq, header.PrevHash = 2, hash
	edit, _, err := syncwire.SealOperation(header, put, epochKey[:], ownerSigner)
	require(t, err)
	seed, exchangePrivate := peerKeys.PrivateBytes()
	peerSigner := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	clear(exchangePrivate)
	defer clear(peerSigner)
	header.DeviceID, header.Seq, header.PrevHash = peer.DeviceID, 1, [32]byte{}
	deletion, _, err := syncwire.SealOperation(header,
		syncwire.LocalOperation{RecordID: put.RecordID, Parents: put.Parents, Action: syncmerge.Delete}, epochKey[:], peerSigner)
	require(t, err)
	entries := []replicastore.ExchangeEnvelope{
		{Wire: parent, Sequence: 1, CommandID: "initial", CommandHash: sha256.Sum256(parent)},
		{Wire: edit, Sequence: 2, CommandID: "edit", CommandHash: sha256.Sum256(edit)},
		{Wire: deletion},
	}
	replay := func(wires ...[]byte) []byte {
		t.Helper()
		checkpoint, err := syncwire.ReplayCheckpoint(base, wires, h.SpaceID, h.Epoch, epochKey[:], confirmed.Signers)
		require(t, err)
		return checkpoint
	}
	complete, earlier := replay(parent, edit, deletion), replay(parent, edit)
	defer clear(complete)
	defer clear(earlier)
	for _, test := range []struct {
		name       string
		checkpoint []byte
		wantErr    error
	}{
		{"frozen journal", complete, nil},
		{"validly signed earlier checkpoint", earlier, ErrRemovalCheckpointMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, storeKey := filepath.Join(t.TempDir(), "replica.sqlite"), [replicastore.KeySize]byte{2}
			store, err := replicastore.Create(ctx, path, storeKey)
			require(t, err)
			t.Cleanup(func() { _ = store.Close() })
			view, err := store.ReadExchange(ctx, confirmed)
			require(t, err)
			require(t, store.CommitExchange(ctx, confirmed, view.Generation, entries, 2, 3))
			if _, err := PrepareRemovalActivation(ctx, store, confirmed, previous, fingerprint, owner); !errors.Is(err, ErrRemovalNotStaged) {
				t.Fatalf("unstaged removal: %v", err)
			}
			candidate, err := PrepareRemoval(ctx, store, confirmed, previous, fingerprint, owner, peer.DeviceID)
			require(t, err)
			if test.wantErr != nil {
				key, encrypted, err := owner.SealRemovalCheckpoint(previous, candidate.Membership, fingerprint, test.checkpoint)
				require(t, err)
				defer clear(key[:])
				candidate.Checkpoint = encrypted
				candidate.KeyPackage, err = owner.SealRemovalKeyPackage(previous, candidate.Membership, fingerprint, encrypted, key)
				require(t, err)
			}
			require(t, store.StageRemoval(ctx, binding, previous, fingerprint, owner, candidate))
			if _, err := NewRemovalSession(ctx, store, binding, fingerprint, owner, nil, nil, nil); !errors.Is(err, ErrRemovalRelayPaused) {
				t.Fatalf("staged removal reached relay setup: %v", err)
			}
			require(t, store.Close())
			store, err = replicastore.Open(ctx, path, storeKey)
			require(t, err)
			before, err := store.ReadExchange(ctx, confirmed)
			require(t, err)
			result, err := PrepareRemovalActivation(ctx, store, confirmed, previous, fingerprint, owner)
			defer clear(result.EpochKey[:])
			defer clear(result.Checkpoint)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || !reflect.DeepEqual(result, RemovalActivation{}) {
					t.Fatalf("mismatched checkpoint returned data or wrong error: %v", err)
				}
			} else {
				require(t, err)
				if result.Generation != candidate.Generation+1 || result.Generation != before.Generation ||
					!bytes.Equal(result.Membership, candidate.Membership) || !bytes.Equal(result.Checkpoint, complete) {
					t.Fatal("activation inputs differ from the staged generation or exact artifacts")
				}
				verified, err := syncpair.OpenRemovalCheckpointBytes(candidate.Checkpoint, previous, result.Membership, fingerprint, result.EpochKey)
				require(t, err)
				defer clear(verified)
				if !bytes.Equal(verified, result.Checkpoint) {
					t.Fatal("returned epoch key does not open the same checkpoint")
				}
				restored, err := syncwire.RestoreCheckpoint(result.Checkpoint, h.SpaceID, h.Epoch+1, result.EpochKey[:],
					map[[16]byte]ed25519.PublicKey{h.OwnerID: h.Members[0].SigningPub[:]})
				require(t, err)
				snapshot := restored.Snapshot()
				if !reflect.DeepEqual(snapshot, before.Snapshot) || len(snapshot) != 1 || len(snapshot[0].Versions) != 2 ||
					snapshot[0].Versions[0].Action == snapshot[0].Versions[1].Action {
					t.Fatalf("restored checkpoint lost the edit/deletion conflict: %+v", snapshot)
				}
			}
			after, err := store.ReadExchange(ctx, confirmed)
			require(t, err)
			if !reflect.DeepEqual(after, before) {
				t.Fatal("preparation changed the staged transition or frozen replica")
			}

			if test.wantErr == nil {
				run := func(confirmed replicastore.ExchangeContext) {
					session := NewSession(store, confirmed, nil)
					session.SetAccess(true, true)
					if err := session.RunOnce(ctx); !errors.Is(err, ErrRemovalRelayPaused) {
						t.Fatalf("relay exchange was not paused: %v", err)
					}
				}
				run(confirmed)
				next, err := ActivateRemoval(ctx, store, confirmed, previous, fingerprint, owner)
				require(t, err)
				clear(next.Checkpoint)
				clear(next.EpochKey)
				require(t, store.Close())
				store, err = replicastore.Open(ctx, path, storeKey)
				require(t, err)
				active, err := store.ReadActivatedRemoval(ctx)
				require(t, err)
				if active == nil || active.ID != sha256.Sum256(candidate.Checkpoint) {
					t.Fatal("committed transition identifier was not recovered")
				}
				previousOnly := replicastore.ExchangeContext{Binding: active.Previous}
				next, err = ActivateRemoval(ctx, store, previousOnly, active.PreviousMembership, fingerprint, owner)
				require(t, err)
				defer clear(next.Checkpoint)
				defer clear(next.EpochKey)
				restored, err := store.ReadExchange(ctx, next)
				require(t, err)
				if !reflect.DeepEqual(restored.Snapshot, before.Snapshot) {
					t.Fatal("activated epoch lost the edit/deletion conflict")
				}
				wire, err := QueueLocal(ctx, store, next, ownerSigner, "new epoch",
					syncwire.LocalOperation{RecordID: [16]byte{2}, Action: syncmerge.Put, Data: []byte("new")})
				require(t, err)
				envelope, err := syncwire.Parse(wire)
				require(t, err)
				if envelope.Header.Seq != 1 || envelope.Header.Epoch != h.Epoch+1 {
					t.Fatal("first local envelope did not start the new epoch at sequence 1")
				}
				run(next)
				withEdit, err := store.ReadExchange(ctx, next)
				require(t, err)
				retried, err := ActivateRemoval(ctx, store, previousOnly, active.PreviousMembership, fingerprint, owner)
				require(t, err)
				defer clear(retried.Checkpoint)
				defer clear(retried.EpochKey)
				afterRetry, err := store.ReadExchange(ctx, retried)
				require(t, err)
				if !reflect.DeepEqual(afterRetry, withEdit) {
					t.Fatal("activation retry reset the new epoch's local edits")
				}
				testRemovalRelayResume(t, store, binding, fingerprint, owner, peer.DeviceID, wire)
			}
		})
	}
}
