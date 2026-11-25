package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	membershipVersion           = 1
	maxMembershipSize           = 512
	membershipDomain            = "PasswordSaver/sync/pair/membership/v1"
	controllerFingerprintDomain = "PasswordSaver/sync/pair/controller/fingerprint/v1"
)

// Member holds a device ID and its Ed25519 and X25519 public keys.
type Member struct {
	_           struct{} `cbor:",toarray"`
	DeviceID    [16]byte
	SigningPub  [32]byte
	ExchangePub [32]byte
}

// MembershipHeader is the signed space state, with the owner listed first.
type MembershipHeader struct {
	_             struct{} `cbor:",toarray"`
	Version       uint64
	SpaceID       [16]byte
	Revision      uint64
	Epoch         uint64
	PrevHash      [32]byte
	OwnerID       [16]byte
	ControllerPub [32]byte
	Members       []Member
}

// Membership is the public wire object [H, Signature].
type Membership struct {
	_         struct{} `cbor:",toarray"`
	Header    MembershipHeader
	Signature [ed25519.SignatureSize]byte
}

// SpaceKeys keeps the owner's device keys and separate controller key in Go.
type SpaceKeys struct {
	device     *DeviceKeys
	controller ed25519.PrivateKey
}

// DeviceSigningKey returns a copy of the owner's key used for changes.
func (k *SpaceKeys) DeviceSigningKey() ed25519.PrivateKey { return bytes.Clone(k.device.signing) }

// CanonicalBytes returns the complete signed membership file.
func (m Membership) CanonicalBytes() ([]byte, error) { return encMode.Marshal(m) }

// VerifySignedMembership verifies the signature and pinned fingerprint of a standalone membership.
func VerifySignedMembership(wire []byte, confirmed [32]byte) (Membership, error) {
	return verifySignedMembership(wire, confirmed)
}

// ControllerFingerprint computes SHA-256 over the domain, space ID and controller public key.
func ControllerFingerprint(spaceID [16]byte, controllerPub [32]byte) [32]byte {
	input := append([]byte(controllerFingerprintDomain), spaceID[:]...)
	return sha256.Sum256(append(input, controllerPub[:]...))
}

// NewSpace generates a space, its owner and their keys, and signs revision 1.
func NewSpace() (wire []byte, fingerprint [32]byte, keys *SpaceKeys, err error) {
	device, err := generateDeviceKeys()
	if err != nil {
		return nil, fingerprint, nil, err
	}
	public, controller, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fingerprint, nil, err
	}
	owner := Member{DeviceID: randomID(), SigningPub: [32]byte(device.signing.Public().(ed25519.PublicKey)),
		ExchangePub: [32]byte(device.exchange.PublicKey().Bytes())}
	header := MembershipHeader{Version: membershipVersion, SpaceID: randomID(), Revision: 1, Epoch: 1,
		OwnerID: owner.DeviceID, ControllerPub: [32]byte(public), Members: []Member{owner}}
	wire, err = signMembership(header, controller)
	if err != nil {
		return nil, fingerprint, nil, err
	}
	return wire, ControllerFingerprint(header.SpaceID, header.ControllerPub), &SpaceKeys{device: device, controller: controller}, nil
}

// AddMember signs the transition from a verified initial membership to two devices.
// The caller supplies the new member after confirming its identity.
func (keys *SpaceKeys) AddMember(previous []byte, confirmed [32]byte, member Member) ([]byte, error) {
	initial, err := VerifyMembership(previous, nil, confirmed)
	if err != nil {
		return nil, err
	}
	h := initial.Header
	if keys == nil || len(keys.controller) != ed25519.PrivateKeySize || !bytes.Equal(h.ControllerPub[:], keys.controller[ed25519.SeedSize:]) {
		return nil, errors.New("controller key does not match membership")
	}
	h.Revision++
	h.Epoch++
	h.PrevHash = sha256.Sum256(previous)
	h.Members = append(h.Members, member)
	return signMembership(h, keys.controller)
}

func signMembership(h MembershipHeader, controller ed25519.PrivateKey) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	encoded, err := encMode.Marshal(h)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(controller, append([]byte(membershipDomain), encoded...))
	return encMode.Marshal(Membership{Header: h, Signature: [64]byte(sig)})
}

func verifySignedMembership(wire []byte, confirmed [32]byte) (Membership, error) {
	var current Membership
	if len(wire) > maxMembershipSize {
		return current, errors.New("membership exceeds size limit")
	}
	if err := decMode.Unmarshal(wire, &current); err != nil {
		return Membership{}, err
	}
	canonical, err := encMode.Marshal(current)
	if err != nil || !bytes.Equal(wire, canonical) {
		return Membership{}, errors.New("non-canonical membership")
	}
	h := current.Header
	if err := h.validate(); err != nil {
		return Membership{}, err
	}
	if ControllerFingerprint(h.SpaceID, h.ControllerPub) != confirmed {
		return Membership{}, errors.New("membership controller fingerprint mismatch")
	}
	encoded, err := encMode.Marshal(h)
	if err != nil {
		return Membership{}, err
	}
	if !ed25519.Verify(h.ControllerPub[:], append([]byte(membershipDomain), encoded...), current.Signature[:]) {
		return Membership{}, errors.New("invalid membership signature")
	}
	return current, nil
}

// VerifyMembership checks a signed membership against a previously confirmed
// controller fingerprint. Pass nil for previous when verifying the initial membership.
func VerifyMembership(wire, previous []byte, confirmed [32]byte) (Membership, error) {
	current, err := verifySignedMembership(wire, confirmed)
	if err != nil {
		return Membership{}, err
	}
	h := current.Header
	if previous == nil {
		if h.Revision != 1 || h.Epoch != 1 || h.PrevHash != [32]byte{} || len(h.Members) != 1 {
			return Membership{}, errors.New("invalid initial membership")
		}
		return current, nil
	}
	initial, err := VerifyMembership(previous, nil, confirmed)
	if err != nil {
		return Membership{}, err
	}
	old := initial.Header
	if h.SpaceID != old.SpaceID || h.ControllerPub != old.ControllerPub || h.OwnerID != old.OwnerID ||
		h.Members[0] != old.Members[0] || h.Revision != old.Revision+1 || h.Epoch != old.Epoch+1 ||
		h.PrevHash != sha256.Sum256(previous) || len(h.Members) != 2 {
		return Membership{}, errors.New("invalid membership transition")
	}
	return current, nil
}

func (h MembershipHeader) validate() error {
	if h.Version != membershipVersion || h.SpaceID == [16]byte{} || h.ControllerPub == [32]byte{} ||
		len(h.Members) < 1 || len(h.Members) > 2 || h.OwnerID != h.Members[0].DeviceID {
		return errors.New("invalid membership header")
	}
	ids := map[[16]byte]bool{{}: true}
	keys := map[[32]byte]bool{{}: true, h.ControllerPub: true}
	for _, member := range h.Members {
		if ids[member.DeviceID] || keys[member.SigningPub] || keys[member.ExchangePub] || member.SigningPub == member.ExchangePub {
			return errors.New("zero or duplicate membership ID or public key")
		}
		ids[member.DeviceID] = true
		keys[member.SigningPub], keys[member.ExchangePub] = true, true
	}
	return nil
}
