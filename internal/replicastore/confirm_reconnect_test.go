package replicastore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"password-saver/internal/syncwire"
)

func TestConfirmReconnectPersistsOnce(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require(err)
	space, owner, epochKey := [16]byte{1}, [16]byte{2}, [32]byte{3}
	checkpoint, err := syncwire.NewReceiver(space, 1, epochKey[:], nil).MarshalCheckpoint()
	require(err)
	binding := ExchangeBinding{SpaceID: space, DeviceID: owner, Epoch: 2, MembershipHash: [32]byte{1},
		CheckpointHash: sha256.Sum256(checkpoint), RelayURL: "https://relay.test"}
	confirmed := ExchangeContext{Binding: binding, Checkpoint: checkpoint, EpochKey: epochKey[:],
		Signers: map[[16]byte]ed25519.PublicKey{owner: pub}}
	wire, err := syncwire.ReplayCheckpoint(checkpoint, nil, space, 2, epochKey[:], confirmed.Signers)
	require(err)
	defer clear(wire)
	path, key := filepath.Join(t.TempDir(), "replica.sqlite"), [KeySize]byte{1}
	store, err := Create(ctx, path, key)
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		require(err)
		return view
	}
	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 7))
	ownerDecision := ReconnectConfirmation{Generation: read().Generation, CheckpointHash: sha256.Sum256(wire)}
	if err := store.ConfirmReconnect(ctx, binding, ownerDecision); !errors.Is(err, ErrExchange) {
		t.Fatalf("connected exchange: %v", err)
	}
	require(store.DisconnectExchange(ctx, binding, ownerDecision.Generation))
	before := read()
	if err := store.ConfirmReconnect(ctx, binding, ownerDecision); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale generation: %v", err)
	}
	ownerDecision.Generation = before.Generation
	foreign := binding
	foreign.DeviceID[0] ^= 1
	if err := store.ConfirmReconnect(ctx, foreign, ownerDecision); !errors.Is(err, ErrExchange) {
		t.Fatalf("foreign binding: %v", err)
	}
	save := func() error { return store.ConfirmReconnect(ctx, binding, ownerDecision) }
	injected := errors.New("injected confirmation commit failure")
	store.beforeCommit = func() error { return injected }
	if err := save(); !errors.Is(err, injected) || !reflect.DeepEqual(read(), before) {
		t.Fatalf("before commit changed the exchange: %v", err)
	}
	store.beforeCommit = nil
	store.afterCommit = func() error { return injected }
	if err := save(); !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("expected uncertain commit: %v", err)
	}
	require(store.Close())
	store, err = Open(ctx, path, key)
	require(err)
	store.beforeCommit = func() error { return injected }
	require(save())
	other := ownerDecision
	other.CheckpointHash[0] ^= 1
	if err := store.ConfirmReconnect(ctx, binding, other); !errors.Is(err, ErrReconnectConfirmation) {
		t.Fatalf("different confirmation: %v", err)
	}
	before.Generation++
	before.State.ReconnectConfirmation = &ownerDecision
	if !reflect.DeepEqual(read(), before) {
		t.Fatal("reopened exchange lost the confirmation or changed other state")
	}

	id := [16]byte{1}
	reconnect := func() error {
		return store.ReconnectExchange(ctx, binding, before.Generation, before.State.Cursor, ownerDecision, id)
	}
	if err := reconnect(); !errors.Is(err, injected) || !reflect.DeepEqual(read(), before) {
		t.Fatalf("reconnect before commit changed the exchange: %v", err)
	}
	store.beforeCommit = nil
	store.afterCommit = func() error { return injected }
	if err := reconnect(); !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("expected uncertain reconnect commit: %v", err)
	}
	before.Generation++
	before.State.Disconnected, before.State.ReconnectConfirmation, before.State.ReconnectID = false, nil, id
	if err := reconnect(); err == nil || !reflect.DeepEqual(read(), before) {
		t.Fatalf("used confirmation changed the exchange: %v", err)
	}
}
