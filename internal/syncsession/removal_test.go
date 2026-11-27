package syncsession

import (
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
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

func TestPrepareRemoval(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	initial, fingerprint, ownerKeys, err := syncpair.NewSpace()
	require(err)
	now := time.Now()
	request, _, peerKeys, err := syncpair.NewRequest(fingerprint, now)
	require(err)
	parsed, _, err := syncpair.ParseRequest(request, now)
	require(err)
	peer := parsed.Header
	previous, err := ownerKeys.AddMember(initial, fingerprint, syncpair.Member{
		DeviceID: peer.DeviceID, SigningPub: peer.SigningPub, ExchangePub: peer.ExchangePub,
	})
	require(err)
	membership, err := syncpair.VerifySignedMembership(previous, fingerprint)
	require(err)
	h := membership.Header
	owner := h.Members[0]
	epochKey := [32]byte{1}
	signers := map[[16]byte]ed25519.PublicKey{
		owner.DeviceID: owner.SigningPub[:], peer.DeviceID: peer.SigningPub[:],
	}
	checkpoint, err := syncwire.NewReceiver(h.SpaceID, h.Epoch-1, epochKey[:], nil).MarshalCheckpoint()
	require(err)
	confirmed := replicastore.ExchangeContext{
		Binding: replicastore.ExchangeBinding{
			SpaceID: h.SpaceID, DeviceID: owner.DeviceID, Epoch: h.Epoch,
			MembershipHash: sha256.Sum256(previous), CheckpointHash: sha256.Sum256(checkpoint),
			RelayURL: "https://relay.test",
		},
		Checkpoint: checkpoint, EpochKey: epochKey[:], Signers: signers,
	}
	store, err := replicastore.Create(ctx, filepath.Join(t.TempDir(), "replica.sqlite"), [replicastore.KeySize]byte{2})
	require(err)
	t.Cleanup(func() { require(store.Close()) })
	read := func() replicastore.ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		require(err)
		return view
	}
	assertUnchanged := func(before replicastore.ExchangeView) {
		t.Helper()
		after := read()
		if !reflect.DeepEqual(after, before) {
			t.Fatal("preparation changed the committed replica")
		}
	}
	reject := func(binding replicastore.ExchangeContext, source []byte, want error) {
		t.Helper()
		before := read()
		candidate, err := PrepareRemoval(ctx, store, binding, source, fingerprint, ownerKeys, peer.DeviceID)
		if err == nil || (want != nil && !errors.Is(err, want)) || !reflect.DeepEqual(candidate, RemovalCandidate{}) {
			t.Fatalf("preparation returned %+v, %v, wanted a zero candidate and %v", candidate, err, want)
		}
		assertUnchanged(before)
	}

	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 0))
	reject(confirmed, initial, nil)
	nonOwner := confirmed
	nonOwner.Binding.DeviceID = peer.DeviceID
	reject(nonOwner, previous, nil)

	recordID := [16]byte{10}
	put := syncwire.LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: []byte("initial")}
	signer := ownerKeys.DeviceSigningKey()
	parent, err := QueueLocal(ctx, store, confirmed, signer, "first", put)
	require(err)
	put.Parents, put.Data = [][32]byte{sha256.Sum256(parent)}, []byte("edited")
	_, err = QueueLocal(ctx, store, confirmed, signer, "second", put)
	require(err)
	reject(confirmed, previous, ErrRemovalUnsent)
	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 2, 0))

	seed, _ := peerKeys.PrivateBytes()
	peerSigner := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(peerSigner)
	header := syncwire.Header{Type: 1, Version: 1, SpaceID: h.SpaceID, Epoch: h.Epoch, DeviceID: peer.DeviceID, Seq: 1}
	dependency, hash, err := syncwire.SealOperation(header,
		syncwire.LocalOperation{RecordID: [16]byte{11}, Action: syncmerge.Put, Data: []byte("another record")}, epochKey[:], peerSigner)
	require(err)
	header.Seq, header.PrevHash = 2, hash
	deletion, _, err := syncwire.SealOperation(header,
		syncwire.LocalOperation{RecordID: recordID, Parents: put.Parents, Action: syncmerge.Delete}, epochKey[:], peerSigner)
	require(err)
	require(AcceptPage(ctx, store, confirmed, 0, []syncrelay.Entry{{Cursor: 1, Wire: deletion}}, 1))
	reject(confirmed, previous, ErrRemovalPending)
	pendingState := read().State
	journal := make([][]byte, len(pendingState.Journal))
	for i, entry := range pendingState.Journal {
		journal[i] = entry.Wire
	}
	if snapshot, err := syncwire.ReplayCheckpoint(checkpoint, journal, h.SpaceID, h.Epoch, epochKey[:], signers); !errors.Is(err, syncwire.ErrReplayPending) || snapshot != nil {
		t.Fatalf("replay exported an incomplete checkpoint: %d bytes, %v", len(snapshot), err)
	}
	require(AcceptPage(ctx, store, confirmed, 1, []syncrelay.Entry{{Cursor: 2, Wire: dependency}}, 2))

	before := read()
	candidate, err := PrepareRemoval(ctx, store, confirmed, previous, fingerprint, ownerKeys, peer.DeviceID)
	require(err)
	if candidate.Generation != before.Generation {
		t.Fatalf("candidate generation %d, want %d", candidate.Generation, before.Generation)
	}
	key, err := ownerKeys.OpenRemovalKeyPackage(candidate.KeyPackage, previous, candidate.Membership, fingerprint, candidate.Checkpoint)
	require(err)
	defer clear(key[:])
	restored, err := syncpair.OpenRemovalCheckpoint(candidate.Checkpoint, previous, candidate.Membership, fingerprint, key)
	require(err)
	snapshot := restored.Snapshot()
	if !reflect.DeepEqual(snapshot, before.Snapshot) || len(snapshot) != 2 || len(snapshot[0].Versions) != 2 ||
		snapshot[0].Versions[0].Action == snapshot[0].Versions[1].Action {
		t.Fatalf("restored snapshot lost the edit/deletion conflict: %+v", snapshot)
	}
	assertUnchanged(before)
}
