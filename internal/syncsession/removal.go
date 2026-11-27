package syncsession

import (
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
)

// RemovalCandidate contains the artifacts and the generation for an atomic transition.
type RemovalCandidate struct {
	Generation int64
	Membership []byte
	Checkpoint []byte
	KeyPackage []byte
}

// PrepareRemoval builds a candidate from one confirmed SQLite generation.
func PrepareRemoval(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, previous []byte, fingerprint [32]byte, keys *syncpair.SpaceKeys, removed [16]byte) (RemovalCandidate, error) {
	binding := confirmed.Binding
	if sha256.Sum256(previous) != binding.MembershipHash {
		return RemovalCandidate{}, errors.New("signed membership does not match the exchange binding")
	}
	membership, err := syncpair.VerifySignedMembership(previous, fingerprint)
	if err != nil {
		return RemovalCandidate{}, err
	}
	h := membership.Header
	if h.SpaceID != binding.SpaceID || h.Epoch != binding.Epoch || h.OwnerID != binding.DeviceID {
		return RemovalCandidate{}, errors.New("removal requires the bound space, epoch and owner device")
	}
	confirmed.Signers = make(map[[16]byte]ed25519.PublicKey, len(h.Members))
	for _, member := range h.Members {
		confirmed.Signers[member.DeviceID] = ed25519.PublicKey(member.SigningPub[:])
	}

	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return RemovalCandidate{}, err
	}
	state := view.State
	if state == nil || state.Binding != binding {
		return RemovalCandidate{}, errors.New("removal requires a confirmed exchange state")
	}
	if len(view.Pending) > 0 {
		return RemovalCandidate{}, ErrRemovalPending
	}
	journal := make([][]byte, len(state.Journal))
	for i, entry := range state.Journal {
		if entry.Sequence > state.SentSequence {
			return RemovalCandidate{}, ErrRemovalUnsent
		}
		journal[i] = entry.Wire
	}

	current, err := keys.RemoveMember(previous, fingerprint, removed)
	if err != nil {
		return RemovalCandidate{}, err
	}
	checkpoint, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, journal, binding.SpaceID, binding.Epoch, confirmed.EpochKey, confirmed.Signers)
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
