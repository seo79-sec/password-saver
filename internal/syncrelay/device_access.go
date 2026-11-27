package syncrelay

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
)

// DeviceAccess holds the active token hashes for one test space.
type DeviceAccess struct {
	mu          sync.RWMutex
	tokenHashes map[[16]byte][sha256.Size]byte
}

// NewDeviceAccess copies the SHA-256 hashes of the devices' raw 32-byte tokens.
func NewDeviceAccess(tokenHashes map[[16]byte][sha256.Size]byte) (*DeviceAccess, error) {
	if len(tokenHashes) == 0 {
		return nil, errors.New("device access requires at least one token hash")
	}
	access := &DeviceAccess{tokenHashes: make(map[[16]byte][sha256.Size]byte, len(tokenHashes))}
	seen := make(map[[sha256.Size]byte]bool, len(tokenHashes))
	for id, hash := range tokenHashes {
		if id == [16]byte{} || hash == [sha256.Size]byte{} || seen[hash] {
			return nil, errors.New("device access requires nonzero IDs and distinct nonzero token hashes")
		}
		seen[hash] = true
		access.tokenHashes[id] = hash
	}
	return access, nil
}

// Revoke removes the device's access and waits for any authorized log calls.
func (a *DeviceAccess) Revoke(deviceID [16]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokenHashes, deviceID)
}

// lockAuthorized returns the unlock function on success. Hold the read lock
// across a log call so it and Revoke have a definite order.
func (a *DeviceAccess) lockAuthorized(digest [sha256.Size]byte) func() {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	match := 0
	for _, hash := range a.tokenHashes {
		match |= subtle.ConstantTimeCompare(digest[:], hash[:])
	}
	if match == 1 {
		return a.mu.RUnlock
	}
	a.mu.RUnlock()
	return nil
}
