package replicastore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

func TestApplyReconnectSuffixCommitBoundary(t *testing.T) {
	testReconnectApplyCommitBoundary(t, false)
}

func TestApplyReconnectMergeCommitBoundary(t *testing.T) {
	testReconnectApplyCommitBoundary(t, true)
}

func testReconnectApplyCommitBoundary(t *testing.T, merge bool) {
	t.Helper()
	ctx := t.Context()
	store, path := newStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := ExchangeBinding{SpaceID: [16]byte{1}, DeviceID: [16]byte{2}, Epoch: 2,
		MembershipHash: sha256.Sum256([]byte("membership")), RelayURL: "https://relay.example.invalid"}
	peer := [16]byte{3}
	localSigner := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	peerSeed := [ed25519.SeedSize]byte{3}
	peerSigner := ed25519.NewKeyFromSeed(peerSeed[:])
	signers := map[[16]byte]ed25519.PublicKey{
		binding.DeviceID: localSigner.Public().(ed25519.PublicKey),
		peer:             peerSigner.Public().(ed25519.PublicKey),
	}
	key := make([]byte, 32)
	checkpoint, err := syncwire.NewReceiver(binding.SpaceID, 1, key, signers).MarshalCheckpoint()
	check(err)
	binding.CheckpointHash = sha256.Sum256(checkpoint)
	confirmed := ExchangeContext{Binding: binding, Checkpoint: checkpoint, EpochKey: key, Signers: signers}
	readExchange := func() ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		check(err)
		return view
	}
	check(store.CommitExchange(ctx, confirmed, readExchange().Generation, nil, 0, 0))
	check(store.DisconnectExchange(ctx, binding, readExchange().Generation))
	check(store.ConfirmReconnect(ctx, binding, ReconnectConfirmation{
		Generation: readExchange().Generation, CheckpointHash: sha256.Sum256([]byte("reviewed point")),
	}))
	before := readExchange()
	header := syncwire.Header{Type: 1, Version: 1, SpaceID: binding.SpaceID, Epoch: binding.Epoch, DeviceID: peer, Seq: 1}
	wire, _, err := syncwire.SealOperation(header, syncwire.LocalOperation{
		RecordID: [16]byte{4}, Action: syncmerge.Put, Data: []byte("peer operation"),
	}, key, peerSigner)
	check(err)
	receipt := ReconnectMergeReceipt{
		Generation: before.Generation, Cursor: 1,
		CheckpointHash: sha256.Sum256([]byte("peer checkpoint")),
		MergeHash:      sha256.Sum256([]byte("merged checkpoint")),
		RelayHash:      sha256.Sum256(wire),
	}
	apply := func(generation int64) error {
		if merge {
			approval := receipt
			approval.Generation = generation
			return store.ApplyReconnectMerge(ctx, confirmed, approval, 0, 0, [][]byte{wire})
		}
		return store.ApplyReconnectSuffix(ctx, confirmed, generation, 0, 1, 0, [][]byte{wire})
	}
	if err := apply(before.Generation - 1); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale transaction returned %v", err)
	}
	injected := errors.New("interrupted commit")
	store.beforeCommit = func() error { return injected }
	if err := apply(before.Generation); !errors.Is(err, injected) || !reflect.DeepEqual(readExchange(), before) {
		t.Fatalf("interruption before commit changed the replica: %v", err)
	}
	store.beforeCommit = nil
	store.afterCommit = func() error { return injected }
	if err := apply(before.Generation); !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("interruption after commit returned %v", err)
	}
	check(store.Close())
	store = reopen(t, path)
	after := readExchange()
	if after.Generation != before.Generation+1 || !after.State.Disconnected || after.State.ReconnectConfirmation != nil ||
		after.State.Cursor != 1 || len(after.State.Journal) != 1 || after.State.SentSequence != 0 || len(after.Snapshot) != 1 {
		t.Fatal("catch-up was not persisted atomically")
	}
	if merge {
		if after.State.ReconnectMergeReceipt == nil || *after.State.ReconnectMergeReceipt != receipt {
			t.Fatal("merge receipt was not persisted")
		}
		check(apply(before.Generation))
		if !reflect.DeepEqual(readExchange(), after) {
			t.Fatal("exact retry wrote the merge twice")
		}
		receipt.MergeHash[0] ^= 1
		err := store.ApplyReconnectMerge(ctx, confirmed, receipt, 1, 0, nil)
		if !errors.Is(err, ErrGeneration) || !reflect.DeepEqual(readExchange(), after) {
			t.Fatalf("different receipt was accepted as an exact retry: %v", err)
		}
	}
}
