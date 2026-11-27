package replicastore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

func TestDisconnectExchange(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ownerPub, owner, err := ed25519.GenerateKey(rand.Reader)
	require(err)
	peerPub, peer, err := ed25519.GenerateKey(rand.Reader)
	require(err)
	ownerID, peerID, space := [16]byte{1}, [16]byte{2}, [16]byte{3}
	epochKey := [32]byte{1}
	checkpoint, err := syncwire.NewReceiver(space, 1, epochKey[:], nil).MarshalCheckpoint()
	require(err)
	binding := ExchangeBinding{SpaceID: space, DeviceID: ownerID, Epoch: 2,
		MembershipHash: [32]byte{1}, CheckpointHash: sha256.Sum256(checkpoint), RelayURL: "https://relay.test"}
	confirmed := ExchangeContext{Binding: binding, Checkpoint: checkpoint, EpochKey: epochKey[:],
		Signers: map[[16]byte]ed25519.PublicKey{ownerID: ownerPub, peerID: peerPub}}
	path, key := filepath.Join(t.TempDir(), "replica.sqlite"), [KeySize]byte{2}
	store, err := Create(ctx, path, key)
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		require(err)
		return view
	}
	assertView := func(want ExchangeView) {
		t.Helper()
		if got := read(); !reflect.DeepEqual(got, want) {
			t.Fatalf("exchange view changed: got generation %d, want %d", got.Generation, want.Generation)
		}
	}

	header := syncwire.Header{Type: 1, Version: 1, SpaceID: space, Epoch: 2, DeviceID: ownerID, Seq: 1}
	operation := syncwire.LocalOperation{RecordID: [16]byte{1}, Action: syncmerge.Put, Data: []byte("original")}
	parent, hash, err := syncwire.SealOperation(header, operation, epochKey[:], owner)
	require(err)
	header.Seq, header.PrevHash = 2, hash
	operation.Parents, operation.Data = [][32]byte{hash}, []byte("edited offline")
	edit, _, err := syncwire.SealOperation(header, operation, epochKey[:], owner)
	require(err)
	header.DeviceID, header.Seq, header.PrevHash = peerID, 1, [32]byte{}
	operation.Action, operation.Data = syncmerge.Delete, nil
	deletion, _, err := syncwire.SealOperation(header, operation, epochKey[:], peer)
	require(err)
	entries := []ExchangeEnvelope{
		{Wire: parent, Sequence: 1, CommandID: "first", CommandHash: sha256.Sum256(parent)},
		{Wire: edit, Sequence: 2, CommandID: "second", CommandHash: sha256.Sum256(edit)},
		{Wire: deletion},
	}
	require(store.CommitExchange(ctx, confirmed, read().Generation, entries, 1, 8))
	before := read()
	if before.State.Disconnected || len(before.Snapshot) != 1 || len(before.Snapshot[0].Versions) != 2 ||
		before.State.SentSequence >= before.State.Journal[1].Sequence {
		t.Fatal("expected a connected replica with a conflict and an unacknowledged edit")
	}
	expectedGeneration := before.Generation
	disconnect := func() error { return store.DisconnectExchange(ctx, binding, expectedGeneration) }
	foreign := binding
	foreign.SpaceID[0] ^= 1
	if err := store.DisconnectExchange(ctx, foreign, expectedGeneration); !errors.Is(err, ErrExchange) {
		t.Fatalf("foreign binding: %v", err)
	}
	assertView(before)
	if err := store.DisconnectExchange(ctx, binding, expectedGeneration-1); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale generation: %v", err)
	}
	assertView(before)

	injected := errors.New("injected commit failure")
	store.beforeCommit = func() error { return injected }
	if err := disconnect(); !errors.Is(err, injected) || errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("disconnect before commit: %v", err)
	}
	assertView(before)
	store.beforeCommit = nil
	store.afterCommit = func() error { return injected }
	if err := disconnect(); !errors.Is(err, injected) || !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("disconnect after commit: %v", err)
	}
	require(store.Close())
	store, err = Open(ctx, path, key)
	require(err)

	expected := before
	expected.Generation++
	expected.State.Disconnected = true
	assertView(expected)
	store.beforeCommit = func() error { return injected }
	require(disconnect())
	require(store.DisconnectExchange(ctx, binding, expected.Generation))
	if err := store.DisconnectExchange(ctx, foreign, expectedGeneration); !errors.Is(err, ErrExchange) {
		t.Fatalf("foreign binding after disconnect: %v", err)
	}
	if err := store.CommitExchange(ctx, confirmed, expected.Generation, nil, 2, 9); !errors.Is(err, ErrExchangeDisconnected) {
		t.Fatalf("commit after disconnect: %v", err)
	}
	if err := store.StageRemoval(ctx, binding, nil, [32]byte{}, nil, RemovalCandidate{}); !errors.Is(err, ErrExchangeDisconnected) {
		t.Fatalf("stage removal after disconnect: %v", err)
	}
	if err := store.ActivateRemoval(ctx, binding, nil, [32]byte{}, expected.Generation, RemovalCandidate{}, ExchangeContext{}); !errors.Is(err, ErrExchangeDisconnected) {
		t.Fatalf("activate removal after disconnect: %v", err)
	}
	assertView(expected)
}
