package main

import (
	"time"

	cryptov2 "password-saver/crypto/v2"
)

func (a *App) wrapReplicaKey(replicaID [16]byte, key [cryptov2.ReplicaKeySize]byte) ([]byte, error) {
	defer clear(key[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	session, err := a.replicaKeySessionLocked()
	if err != nil {
		return nil, err
	}
	return session.WrapReplicaKey(replicaID, key)
}

func (a *App) openReplicaKey(replicaID [16]byte, wrapped []byte) ([cryptov2.ReplicaKeySize]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, err := a.replicaKeySessionLocked()
	if err != nil {
		return [cryptov2.ReplicaKeySize]byte{}, err
	}
	return session.OpenReplicaKey(replicaID, wrapped)
}

// The caller holds a.mu through the key operation, serializing it with login,
// logout, TOTP verification and DEK replacement.
func (a *App) replicaKeySessionLocked() (*cryptov2.Session, error) {
	session := a.v2Session
	if session != nil && a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout {
		a.logoutLocked()
		return nil, ErrVaultSessionClosed
	}
	if session == nil || a.vault == nil || a.isLockedLocked() {
		return nil, ErrVaultSessionClosed
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.crypto == nil {
		return nil, ErrVaultSessionClosed
	}
	return session.crypto, nil
}
