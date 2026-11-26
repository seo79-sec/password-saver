package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
)

// RemoveMember signs the removal of deviceID from the caller's pinned membership.
// Only the second device can be removed.
func (keys *SpaceKeys) RemoveMember(previous []byte, confirmed [32]byte, deviceID [16]byte) ([]byte, error) {
	h, err := removalPredecessor(previous, confirmed)
	if err != nil {
		return nil, err
	}
	if deviceID != h.Members[1].DeviceID {
		return nil, errors.New("only the second device can be removed")
	}
	if keys == nil || len(keys.controller) != ed25519.PrivateKeySize || !bytes.Equal(h.ControllerPub[:], keys.controller[ed25519.SeedSize:]) {
		return nil, errors.New("controller key does not match membership")
	}
	h.Revision++
	h.Epoch++
	h.PrevHash = sha256.Sum256(previous)
	h.Members = h.Members[:1]
	return signMembership(h, keys.controller)
}

// VerifyRemoval checks a signed removal against the exact signed bytes of the
// caller's previously pinned membership and the confirmed controller fingerprint.
func VerifyRemoval(wire, previous []byte, confirmed [32]byte) (Membership, error) {
	old, err := removalPredecessor(previous, confirmed)
	if err != nil {
		return Membership{}, err
	}
	current, err := verifySignedMembership(wire, confirmed)
	if err != nil {
		return Membership{}, err
	}
	h := current.Header
	if len(h.Members) != 1 || h.SpaceID != old.SpaceID || h.OwnerID != old.OwnerID ||
		h.ControllerPub != old.ControllerPub || h.Members[0] != old.Members[0] ||
		h.Revision != old.Revision+1 || h.Epoch != old.Epoch+1 || h.PrevHash != sha256.Sum256(previous) {
		return Membership{}, errors.New("invalid membership removal transition")
	}
	return current, nil
}

func removalPredecessor(previous []byte, confirmed [32]byte) (MembershipHeader, error) {
	pinned, err := verifySignedMembership(previous, confirmed)
	if err != nil {
		return MembershipHeader{}, err
	}
	h := pinned.Header
	if len(h.Members) != 2 {
		return MembershipHeader{}, errors.New("removal requires a pinned membership with two devices")
	}
	if h.Revision == math.MaxUint64 || h.Epoch == math.MaxUint64 {
		return MembershipHeader{}, errors.New("membership revision or epoch exhausted")
	}
	return h, nil
}
