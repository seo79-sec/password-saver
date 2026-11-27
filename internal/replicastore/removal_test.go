package replicastore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncwire"
)

func TestStageRemoval(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	initial, fingerprint, owner, err := syncpair.NewSpace()
	require(err)
	now := time.Now()
	request, _, _, err := syncpair.NewRequest(fingerprint, now)
	require(err)
	parsed, _, err := syncpair.ParseRequest(request, now)
	require(err)
	peer := parsed.Header
	previous, err := owner.AddMember(initial, fingerprint, syncpair.Member{DeviceID: peer.DeviceID, SigningPub: peer.SigningPub, ExchangePub: peer.ExchangePub})
	require(err)
	membership, err := syncpair.VerifySignedMembership(previous, fingerprint)
	require(err)
	h := membership.Header
	epochKey := [32]byte{1}
	checkpoint, err := syncwire.NewReceiver(h.SpaceID, h.Epoch-1, epochKey[:], nil).MarshalCheckpoint()
	require(err)
	binding := ExchangeBinding{SpaceID: h.SpaceID, DeviceID: h.OwnerID, Epoch: h.Epoch,
		MembershipHash: sha256.Sum256(previous), CheckpointHash: sha256.Sum256(checkpoint), RelayURL: "https://relay.test"}
	confirmed := ExchangeContext{Binding: binding, Checkpoint: checkpoint, EpochKey: epochKey[:],
		Signers: map[[16]byte]ed25519.PublicKey{h.OwnerID: h.Members[0].SigningPub[:], peer.DeviceID: peer.SigningPub[:]}}
	path, storeKey := filepath.Join(t.TempDir(), "replica.sqlite"), [KeySize]byte{2}
	store, err := Create(ctx, path, storeKey)
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() ExchangeView {
		t.Helper()
		view, err := store.ReadExchange(ctx, confirmed)
		require(err)
		return view
	}

	header := syncwire.Header{Type: 1, Version: 1, SpaceID: h.SpaceID, Epoch: h.Epoch, DeviceID: h.OwnerID, Seq: 1}
	wire, _, err := syncwire.SealOperation(header, syncwire.LocalOperation{RecordID: [16]byte{1}, Action: syncmerge.Put, Data: []byte("edit")}, epochKey[:], owner.DeviceSigningKey())
	require(err)
	entries := []ExchangeEnvelope{{Wire: wire, CommandID: "edit", CommandHash: sha256.Sum256([]byte("edit")), Sequence: 1}}
	require(store.CommitExchange(ctx, confirmed, read().Generation, entries, 1, 4))
	before := read()
	if before.State.Removal != nil {
		t.Fatal("expected the old exchange state without a staged transition")
	}
	snapshot, err := syncwire.ReplayCheckpoint(checkpoint, [][]byte{wire}, h.SpaceID, h.Epoch, epochKey[:], confirmed.Signers)
	require(err)
	current, err := owner.RemoveMember(previous, fingerprint, peer.DeviceID)
	require(err)
	makeCandidate := func() RemovalCandidate {
		t.Helper()
		key, sealed, err := owner.SealRemovalCheckpoint(previous, current, fingerprint, snapshot)
		require(err)
		defer clear(key[:])
		pkg, err := owner.SealRemovalKeyPackage(previous, current, fingerprint, sealed, key)
		require(err)
		return RemovalCandidate{Generation: before.Generation, Membership: current, Checkpoint: sealed, KeyPackage: pkg}
	}
	candidate, alternative := makeCandidate(), makeCandidate()
	stage := func(c RemovalCandidate) error {
		return store.StageRemoval(ctx, binding, previous, fingerprint, owner, c)
	}
	assertView := func(want ExchangeView) {
		t.Helper()
		if got := read(); !reflect.DeepEqual(got, want) {
			t.Fatalf("exchange changed: generation %d, cursor %d, journal length %d", got.Generation, got.State.Cursor, len(got.State.Journal))
		}
	}
	if err := store.StageRemoval(ctx, binding, initial, fingerprint, owner, candidate); !errors.Is(err, ErrExchange) {
		t.Fatalf("wrong predecessor: %v", err)
	}
	assertView(before)
	stale := candidate
	stale.Generation--
	if err := stage(stale); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale generation: %v", err)
	}
	assertView(before)
	for _, field := range []string{"membership", "checkpoint", "package"} {
		t.Run(field, func(t *testing.T) {
			copy := RemovalCandidate{Generation: candidate.Generation, Membership: bytes.Clone(candidate.Membership),
				Checkpoint: bytes.Clone(candidate.Checkpoint), KeyPackage: bytes.Clone(candidate.KeyPackage)}
			artifact := map[string][]byte{"membership": copy.Membership, "checkpoint": copy.Checkpoint, "package": copy.KeyPackage}[field]
			artifact[len(artifact)-1] ^= 1
			if err := stage(copy); err == nil {
				t.Fatal("accepted a changed artifact")
			}
			assertView(before)
		})
	}
	oversized := candidate
	oversized.Checkpoint = make([]byte, maxStateSize/4*3)
	if err := stage(oversized); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized transition: %v", err)
	}
	assertView(before)
	oversized.Checkpoint = oversized.Checkpoint[:len(oversized.Checkpoint)-len(candidate.Membership)-len(candidate.KeyPackage)]
	combined := &state{Exchange: &ExchangeState{Binding: binding, Removal: &oversized}}
	if _, err := combined.encode(); !errors.Is(err, ErrLimit) {
		t.Fatalf("encoded state limit: %v", err)
	}

	injected := errors.New("injected commit failure")
	store.beforeCommit = func() error { return injected }
	if err := stage(candidate); !errors.Is(err, injected) || errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("before commit: %v", err)
	}
	assertView(before)
	store.beforeCommit = nil
	store.afterCommit = func() error { return injected }
	if err := stage(candidate); !errors.Is(err, ErrCommitUnknown) || !errors.Is(err, injected) {
		t.Fatalf("after commit: %v", err)
	}
	require(store.Close())
	store, err = Open(ctx, path, storeKey)
	require(err)

	expected := before
	expected.Generation++
	expected.State.Removal = &candidate
	assertView(expected)
	store.beforeCommit = func() error { return injected }
	require(stage(candidate))
	if err := stage(alternative); !errors.Is(err, ErrRemovalStaged) {
		t.Fatalf("competing candidate: %v", err)
	}
	if err := store.CommitExchange(ctx, confirmed, expected.Generation, []ExchangeEnvelope{{Wire: wire}}, 1, 5); !errors.Is(err, ErrRemovalStaged) {
		t.Fatalf("late old-epoch write: %v", err)
	}
	assertView(expected)
}
