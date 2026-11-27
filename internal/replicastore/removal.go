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
	exchange := data.Exchange
	if exchange == nil || exchange.Binding != binding || binding.MembershipHash != sha256.Sum256(previous) {
		return ErrExchange
	}
	staged := exchange.Removal
	if staged != nil {
		if staged.Generation != candidate.Generation {
			return ErrGeneration
		}
		if !bytes.Equal(staged.Membership, candidate.Membership) || !bytes.Equal(staged.Checkpoint, candidate.Checkpoint) ||
			!bytes.Equal(staged.KeyPackage, candidate.KeyPackage) {
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
