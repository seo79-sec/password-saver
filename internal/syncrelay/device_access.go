package syncrelay

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
)

// DeviceAccess holds the active token hashes for one test space.
type DeviceAccess struct {
	log         *Log
	rotation    *removalRotation
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
// across a log call to order it against revocation and rotation.
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

// ErrRemovalRotation reports that the relay pair or removal IDs cannot be rotated.
var ErrRemovalRotation = errors.New("invalid relay removal rotation")

type removalRotation struct {
	owner, removed [16]byte
	log            *Log
	access         *DeviceAccess
}

// RotateForRemoval retires the old pair and returns an empty log with owner-only
// access and the same quotas. Exact retries return the same successor pair.
func RotateForRemoval(log *Log, access *DeviceAccess, owner, removed [16]byte) (*Log, *DeviceAccess, error) {
	if log == nil || access == nil {
		return nil, nil, ErrRemovalRotation
	}
	access.mu.Lock()
	defer access.mu.Unlock()
	if owner == [16]byte{} || removed == [16]byte{} || owner == removed {
		return nil, nil, ErrRemovalRotation
	}
	if rotated := access.rotation; rotated != nil {
		if access.log != log || rotated.owner != owner || rotated.removed != removed {
			return nil, nil, ErrRemovalRotation
		}
		return rotated.log, rotated.access, nil
	}

	ownerHash, ownerActive := access.tokenHashes[owner]
	_, removedActive := access.tokenHashes[removed]
	if !ownerActive || len(access.tokenHashes) > 2 || (len(access.tokenHashes) == 2 && !removedActive) ||
		!access.bindLog(log) {
		return nil, nil, ErrRemovalRotation
	}
	nextLog := NewLog(log.maxEntries, log.maxBytes)
	nextAccess := &DeviceAccess{log: nextLog, tokenHashes: map[[16]byte][sha256.Size]byte{owner: ownerHash}}
	nextLog.access = nextAccess
	access.rotation = &removalRotation{owner: owner, removed: removed, log: nextLog, access: nextAccess}
	clear(access.tokenHashes)
	return nextLog, nextAccess, nil
}

// bindLog is called with DeviceAccess.mu held, before taking the log lock.
func (a *DeviceAccess) bindLog(log *Log) bool {
	if a.log != nil {
		return a.log == log
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if log.access != nil {
		return false
	}
	a.log, log.access = log, a
	return true
}
