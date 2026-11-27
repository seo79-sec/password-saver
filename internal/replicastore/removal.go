package replicastore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"

	"password-saver/internal/syncpair"
)

// ErrRemovalStaged means a transition is already fixed and the old epoch is frozen.
var ErrRemovalStaged = errors.New("replica removal transition already staged")

// RemovalCandidate contains the artifacts and the generation for an atomic transition.
type RemovalCandidate struct {
	Generation int64
	Membership []byte
	Checkpoint []byte
	KeyPackage []byte
}

func (c RemovalCandidate) validate() error {
	if c.Generation < 1 || len(c.Membership) == 0 || len(c.Checkpoint) == 0 || len(c.KeyPackage) == 0 {
		return ErrExchange
	}
	// The JSON encoding expands these byte slices to base64.
	remaining := maxStateSize / 4 * 3
	for _, wire := range [][]byte{c.Membership, c.Checkpoint, c.KeyPackage} {
		if len(wire) > remaining {
			return ErrLimit
		}
		remaining -= len(wire)
	}
	return nil
}

// StageRemoval verifies and fixes one transition without activating the new epoch.
func (s *Store) StageRemoval(ctx context.Context, binding ExchangeBinding, previous []byte, fingerprint [32]byte, owner *syncpair.SpaceKeys, candidate RemovalCandidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, _, err := s.load(ctx, tx)
	if err != nil {
		return storageError(err)
	}
	if identity != s.identity {
		return ErrAuthentication
	}
	if data.Exchange != nil && data.Exchange.Disconnected {
		return ErrExchangeDisconnected
	}
	exchange := data.Exchange
	if exchange == nil || exchange.Binding != binding || binding.MembershipHash != sha256.Sum256(previous) {
		return ErrExchange
	}
	staged := exchange.Removal
	if staged != nil {
		if staged.Generation != candidate.Generation {
			return ErrGeneration
		}
		if !staged.equal(candidate) {
			return ErrRemovalStaged
		}
	} else {
		if generation != candidate.Generation {
			return ErrGeneration
		}
		if generation == math.MaxInt64 {
			return ErrLimit
		}
	}
	if err := candidate.validate(); err != nil {
		return err
	}

	membership, err := syncpair.VerifyRemoval(candidate.Membership, previous, fingerprint)
	if err != nil {
		return err
	}
	h := membership.Header
	if h.SpaceID != binding.SpaceID || h.Epoch-1 != binding.Epoch || h.OwnerID != binding.DeviceID {
		return ErrExchange
	}
	key, err := owner.OpenRemovalKeyPackage(candidate.KeyPackage, previous, candidate.Membership, fingerprint, candidate.Checkpoint)
	defer clear(key[:])
	if err != nil {
		return err
	}
	if _, err := syncpair.OpenRemovalCheckpoint(candidate.Checkpoint, previous, candidate.Membership, fingerprint, key); err != nil {
		return err
	}
	if staged != nil {
		return nil
	}

	exchange.Removal = &candidate
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return storageError(err)
	}
	return s.commit(tx)
}

// ActivatedRemoval preserves the authenticated transition needed to reopen the epoch.
type ActivatedRemoval struct {
	ID                 [32]byte // SHA-256 of the exact encrypted checkpoint.
	Previous           ExchangeBinding
	PreviousMembership []byte
	Transition         RemovalCandidate
	SigningPub         [32]byte
	EpochKeyHash       [32]byte
}

// ReadActivatedRemoval reads the committed transition without requiring an epoch key.
func (s *Store) ReadActivatedRemoval(ctx context.Context) (*ActivatedRemoval, error) {
	_, data, _, err := s.readState(ctx)
	if err != nil || data.Exchange == nil {
		return nil, err
	}
	return data.Exchange.ActivatedRemoval, nil
}

// ActivateRemoval replaces the frozen epoch with a new empty journal in one commit.
func (s *Store) ActivateRemoval(ctx context.Context, previous ExchangeBinding, signedPrevious []byte, fingerprint [32]byte, expected int64, candidate RemovalCandidate, next ExchangeContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, _, err := s.load(ctx, tx)
	if err != nil {
		return storageError(err)
	}
	if identity != s.identity {
		return ErrAuthentication
	}
	if data.Exchange != nil && data.Exchange.Disconnected {
		return ErrExchangeDisconnected
	}
	e := data.Exchange
	if e == nil || previous.MembershipHash != sha256.Sum256(signedPrevious) {
		return ErrExchange
	}
	if expected < 2 || candidate.Generation != expected-1 {
		return ErrGeneration
	}
	active := e.ActivatedRemoval
	if active != nil {
		if active.Previous != previous || e.Binding != next.Binding || !active.Transition.equal(candidate) {
			return ErrRemovalStaged
		}
	} else {
		if e.Binding != previous {
			return ErrExchange
		}
		if generation != expected {
			return ErrGeneration
		}
		if e.Removal == nil || !e.Removal.equal(candidate) {
			return ErrRemovalStaged
		}
		if generation == math.MaxInt64 {
			return ErrLimit
		}
	}

	membership, err := syncpair.VerifyRemoval(candidate.Membership, signedPrevious, fingerprint)
	if err != nil {
		return err
	}
	h := membership.Header
	want := previous
	want.Epoch = h.Epoch
	want.MembershipHash = sha256.Sum256(candidate.Membership)
	want.CheckpointHash = sha256.Sum256(next.Checkpoint)
	writer := h.Members[0].SigningPub
	if previous.SpaceID != h.SpaceID || previous.DeviceID != h.OwnerID || previous.Epoch != h.Epoch-1 ||
		next.Binding != want || len(next.EpochKey) != 32 || len(next.Signers) != 1 ||
		!bytes.Equal(next.Signers[h.OwnerID], writer[:]) {
		return ErrExchange
	}
	checkpoint, err := syncpair.OpenRemovalCheckpointBytes(candidate.Checkpoint, signedPrevious, candidate.Membership, fingerprint, [32]byte(next.EpochKey))
	if err != nil {
		return err
	}
	defer clear(checkpoint)
	if !bytes.Equal(checkpoint, next.Checkpoint) {
		return ErrExchange
	}
	if active != nil {
		return nil
	}
	data.Exchange = &ExchangeState{Binding: want, ActivatedRemoval: &ActivatedRemoval{
		ID: sha256.Sum256(candidate.Checkpoint), Previous: previous, PreviousMembership: signedPrevious,
		Transition: candidate, SigningPub: writer, EpochKeyHash: sha256.Sum256(next.EpochKey),
	}}
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return storageError(err)
	}
	return s.commit(tx)
}

func (c RemovalCandidate) equal(other RemovalCandidate) bool {
	return c.Generation == other.Generation && bytes.Equal(c.Membership, other.Membership) &&
		bytes.Equal(c.Checkpoint, other.Checkpoint) && bytes.Equal(c.KeyPackage, other.KeyPackage)
}
