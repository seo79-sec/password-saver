package syncsession

import (
	"context"
	"crypto/rand"
	"errors"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

type reconnectSessionStore interface {
	ExchangeStore
	replicaIdentity
	ReconnectExchange(context.Context, replicastore.ExchangeBinding, int64, uint64, replicastore.ReconnectConfirmation, [16]byte) error
}

// NewReconnectSession consumes a verified relay prefix and starts a locked session
// with exchange disabled. The factory must connect to the provided local log.
func NewReconnectSession(ctx context.Context, store reconnectSessionStore, confirmed replicastore.ExchangeContext, log *syncrelay.Log, proof ReconnectRelayVerification, factory func(*syncrelay.Log) (Relay, error)) (*Session, error) {
	if log == nil || proof.log != log || proof.replicaID == [16]byte{} || proof.replicaID != store.Identity() {
		return nil, ErrReconnectRelayLog
	}
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return nil, err
	}
	e := view.State
	if e == nil || !e.Disconnected || e.Binding != proof.binding || confirmed.Binding != proof.binding || e.Cursor != proof.cursor {
		return nil, replicastore.ErrExchange
	}
	if e.Removal != nil {
		return nil, ErrRemovalRelayPaused
	}
	if view.Generation != proof.generation {
		return nil, replicastore.ErrGeneration
	}
	if e.ReconnectConfirmation == nil || *e.ReconnectConfirmation != proof.confirmation {
		return nil, replicastore.ErrReconnectConfirmation
	}
	if factory == nil {
		return nil, errors.New("reconnect relay factory is required")
	}
	relay, err := factory(log)
	if err != nil {
		return nil, err
	}
	if relay == nil {
		return nil, errors.New("reconnect relay factory returned no transport")
	}

	// Identify this write so recovery cannot claim another caller's commit.
	var id [16]byte
	rand.Read(id[:])
	if err := store.ReconnectExchange(ctx, proof.binding, proof.generation, proof.cursor, proof.confirmation, id); err != nil {
		if !errors.Is(err, replicastore.ErrCommitUnknown) {
			return nil, err
		}
		readback, readErr := store.ReadExchange(context.WithoutCancel(ctx), confirmed)
		if readErr != nil {
			return nil, errors.Join(err, readErr)
		}
		if state := readback.State; state == nil || state.Disconnected || state.ReconnectID != id {
			return nil, err
		}
	}
	session := NewSession(store, confirmed, relay)
	session.reconnectID = id
	if e.ActivatedRemoval != nil {
		session.removalID = e.ActivatedRemoval.ID
	}
	return session, nil
}
