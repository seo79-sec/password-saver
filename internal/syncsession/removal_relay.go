package syncsession

import (
	"context"
	"crypto/sha256"
	"errors"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncrelay"
)

// NewRemovalSession reconnects a locally activated removal epoch to the test relay.
// It starts locked with exchange disabled. The factory must connect to the pair it
// receives and can be called again with that same pair after an error.
func NewRemovalSession(ctx context.Context, store *replicastore.Store, previous replicastore.ExchangeBinding, fingerprint [32]byte, keys *syncpair.SpaceKeys, oldLog *syncrelay.Log, oldAccess *syncrelay.DeviceAccess, factory func(*syncrelay.Log, *syncrelay.DeviceAccess) (Relay, error)) (*Session, error) {
	active, err := store.ReadActivatedRemoval(ctx)
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, ErrRemovalRelayPaused
	}
	owner, removed, err := removalRelayDevices(active, previous, fingerprint)
	if err != nil {
		return nil, err
	}
	if factory == nil {
		return nil, errors.New("removal relay factory is required")
	}

	confirmed, err := ActivateRemoval(ctx, store, replicastore.ExchangeContext{Binding: previous}, active.PreviousMembership, fingerprint, keys)
	if err != nil {
		return nil, err
	}
	connected := false
	defer func() {
		if !connected {
			clear(confirmed.Checkpoint)
			clear(confirmed.EpochKey)
		}
	}()

	log, access, err := syncrelay.RotateForRemoval(oldLog, oldAccess, owner, removed)
	if err != nil {
		return nil, err
	}
	relay, err := factory(log, access)
	if err != nil {
		return nil, err
	}
	if relay == nil {
		return nil, errors.New("removal relay factory returned no transport")
	}
	session := NewSession(store, confirmed, relay)
	session.removalID = active.ID
	connected = true
	return session, nil
}

func removalRelayDevices(active *replicastore.ActivatedRemoval, previous replicastore.ExchangeBinding, fingerprint [32]byte) (owner, removed [16]byte, err error) {
	if active.Previous != previous || active.ID == [32]byte{} ||
		active.ID != sha256.Sum256(active.Transition.Checkpoint) ||
		previous.MembershipHash != sha256.Sum256(active.PreviousMembership) {
		return owner, removed, replicastore.ErrExchange
	}
	current, err := syncpair.VerifyRemoval(active.Transition.Membership, active.PreviousMembership, fingerprint)
	if err != nil {
		return owner, removed, err
	}
	old, err := syncpair.VerifySignedMembership(active.PreviousMembership, fingerprint)
	if err != nil {
		return owner, removed, err
	}
	h := old.Header
	if h.SpaceID != previous.SpaceID || h.Epoch != previous.Epoch || h.OwnerID != previous.DeviceID {
		return owner, removed, replicastore.ErrExchange
	}
	return current.Header.OwnerID, h.Members[1].DeviceID, nil
}
