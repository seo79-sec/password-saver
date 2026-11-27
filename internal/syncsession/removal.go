package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncwire"
)

var (
	// ErrRemovalPending means incoming envelopes still need their dependencies.
	ErrRemovalPending = syncwire.ErrReplayPending
	// ErrRemovalUnsent means local operations still need to be sent or reviewed.
	ErrRemovalUnsent = errors.New("removal requires resolving unsent local operations")
	// ErrRemovalNotStaged means the replica has no staged removal to activate.
	ErrRemovalNotStaged = errors.New("replica removal transition is not staged")
	// ErrRemovalCheckpointMismatch means the signed checkpoint differs from the frozen journal.
	ErrRemovalCheckpointMismatch = errors.New("removal checkpoint does not match the frozen journal")
)

// RemovalCandidate contains the artifacts and the generation for an atomic transition.
type RemovalCandidate = replicastore.RemovalCandidate

// PrepareRemoval builds a candidate from one confirmed SQLite generation.
func PrepareRemoval(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, previous []byte, fingerprint [32]byte, keys *syncpair.SpaceKeys, removed [16]byte) (RemovalCandidate, error) {
	confirmed, view, err := readRemovalExchange(ctx, store, confirmed, previous, fingerprint)
	if err != nil {
		return RemovalCandidate{}, err
	}
	state := view.State
	if len(view.Pending) > 0 {
		return RemovalCandidate{}, ErrRemovalPending
	}
	for _, entry := range state.Journal {
		if entry.Sequence > state.SentSequence {
			return RemovalCandidate{}, ErrRemovalUnsent
		}
	}

	current, err := keys.RemoveMember(previous, fingerprint, removed)
	if err != nil {
		return RemovalCandidate{}, err
	}
	checkpoint, err := replayRemovalCheckpoint(confirmed, state)
	if err != nil {
		return RemovalCandidate{}, err
	}
	defer clear(checkpoint)

	epochKey, encrypted, err := keys.SealRemovalCheckpoint(previous, current, fingerprint, checkpoint)
	defer clear(epochKey[:])
	if err != nil {
		return RemovalCandidate{}, err
	}
	keyPackage, err := keys.SealRemovalKeyPackage(previous, current, fingerprint, encrypted, epochKey)
	if err != nil {
		return RemovalCandidate{}, err
	}
	return RemovalCandidate{Generation: view.Generation, Membership: current, Checkpoint: encrypted, KeyPackage: keyPackage}, nil
}

// RemovalActivation holds verified inputs for the next transaction.
// The caller owns the result and must clear EpochKey and Checkpoint when done.
type RemovalActivation struct {
	Generation int64
	Membership []byte
	Checkpoint []byte
	EpochKey   [32]byte
}

// PrepareRemovalActivation verifies the staged transition against the frozen
// journal and returns the generation that must be used to activate it.
func PrepareRemovalActivation(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, previous []byte, fingerprint [32]byte, keys *syncpair.SpaceKeys) (RemovalActivation, error) {
	confirmed, view, err := readRemovalExchange(ctx, store, confirmed, previous, fingerprint)
	if err != nil {
		return RemovalActivation{}, err
	}
	staged := view.State.Removal
	if staged == nil {
		return RemovalActivation{}, ErrRemovalNotStaged
	}
	if _, err := syncpair.VerifyRemoval(staged.Membership, previous, fingerprint); err != nil {
		return RemovalActivation{}, err
	}
	epochKey, err := keys.OpenRemovalKeyPackage(staged.KeyPackage, previous, staged.Membership, fingerprint, staged.Checkpoint)
	defer clear(epochKey[:])
	if err != nil {
		return RemovalActivation{}, err
	}
	expected, err := replayRemovalCheckpoint(confirmed, view.State)
	if err != nil {
		return RemovalActivation{}, err
	}
	defer clear(expected)
	checkpoint, err := syncpair.OpenRemovalCheckpointBytes(staged.Checkpoint, previous, staged.Membership, fingerprint, epochKey)
	if err != nil {
		return RemovalActivation{}, err
	}
	if !bytes.Equal(checkpoint, expected) {
		clear(checkpoint)
		return RemovalActivation{}, ErrRemovalCheckpointMismatch
	}
	return RemovalActivation{Generation: view.Generation, Membership: staged.Membership, Checkpoint: checkpoint, EpochKey: epochKey}, nil
}

func replayRemovalCheckpoint(confirmed replicastore.ExchangeContext, state *replicastore.ExchangeState) ([]byte, error) {
	journal := make([][]byte, len(state.Journal))
	for i, entry := range state.Journal {
		journal[i] = entry.Wire
	}
	binding := confirmed.Binding
	return syncwire.ReplayCheckpoint(confirmed.Checkpoint, journal, binding.SpaceID, binding.Epoch, confirmed.EpochKey, confirmed.Signers)
}
func readRemovalExchange(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, previous []byte, fingerprint [32]byte) (replicastore.ExchangeContext, replicastore.ExchangeView, error) {
	binding := confirmed.Binding
	if sha256.Sum256(previous) != binding.MembershipHash {
		return replicastore.ExchangeContext{}, replicastore.ExchangeView{}, errors.New("signed membership does not match the exchange binding")
	}
	membership, err := syncpair.VerifySignedMembership(previous, fingerprint)
	if err != nil {
		return replicastore.ExchangeContext{}, replicastore.ExchangeView{}, err
	}
	h := membership.Header
	if h.SpaceID != binding.SpaceID || h.Epoch != binding.Epoch || h.OwnerID != binding.DeviceID {
		return replicastore.ExchangeContext{}, replicastore.ExchangeView{}, errors.New("removal requires the bound space, epoch and owner device")
	}
	confirmed.Signers = make(map[[16]byte]ed25519.PublicKey, len(h.Members))
	for _, member := range h.Members {
		confirmed.Signers[member.DeviceID] = ed25519.PublicKey(member.SigningPub[:])
	}

	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return replicastore.ExchangeContext{}, replicastore.ExchangeView{}, err
	}
	state := view.State
	if state == nil || state.Binding != binding {
		return replicastore.ExchangeContext{}, replicastore.ExchangeView{}, errors.New("removal requires a confirmed exchange state")
	}
	return confirmed, view, nil
}
