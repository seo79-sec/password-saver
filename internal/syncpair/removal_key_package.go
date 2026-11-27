package syncpair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
)

const (
	removalKeyPackageVersion         = 1
	removalKeyPackageMaxSize         = 384
	removalKeyPackageCiphertextSize  = 32 + 16 // Epoch key and AES-GCM tag.
	removalKeyPackageHPKEDomain      = "PasswordSaver/sync/removal/key-package/hpke/v1"
	removalKeyPackageSignatureDomain = "PasswordSaver/sync/removal/key-package/sign/v1"
)

type removalKeyPackageHeader struct {
	_              struct{} `cbor:",toarray"`
	Version        uint64
	SpaceID        [16]byte
	Revision       uint64
	Epoch          uint64
	RecipientID    [16]byte
	RecipientPub   [32]byte
	MembershipHash [32]byte
	CheckpointHash [32]byte
}

type signedRemovalKeyPackage struct {
	_          struct{} `cbor:",toarray"`
	Header     removalKeyPackageHeader
	Enc        [32]byte
	Ciphertext []byte
	Signature  [ed25519.SignatureSize]byte
}

// SealRemovalKeyPackage encrypts the checkpoint's epoch key to the remaining owner.
func (keys *SpaceKeys) SealRemovalKeyPackage(previous, current []byte, confirmed [32]byte, checkpoint []byte, epochKey [32]byte) ([]byte, error) {
	membership, err := VerifyRemoval(current, previous, confirmed)
	if err != nil {
		return nil, err
	}
	h := membership.Header
	if keys == nil || len(keys.controller) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid controller key")
	}
	controller := ed25519.NewKeyFromSeed(keys.controller[:ed25519.SeedSize])
	defer clear(controller)
	if !bytes.Equal(controller[ed25519.SeedSize:], h.ControllerPub[:]) {
		return nil, errors.New("controller key does not match membership")
	}
	if _, err := OpenRemovalCheckpoint(checkpoint, previous, current, confirmed, epochKey); err != nil {
		return nil, err
	}

	pkg := signedRemovalKeyPackage{Header: removalKeyPackageBinding(h, current, checkpoint)}
	aad, err := encMode.Marshal(pkg.Header)
	if err != nil {
		return nil, err
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pkg.Header.RecipientPub[:])
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(removalKeyPackageHPKEDomain))
	if err != nil {
		return nil, err
	}
	pkg.Enc = [32]byte(enc)
	pkg.Ciphertext, err = sender.Seal(aad, epochKey[:])
	if err != nil {
		return nil, err
	}
	message, err := pkg.signatureInput()
	if err != nil {
		return nil, err
	}
	pkg.Signature = [ed25519.SignatureSize]byte(ed25519.Sign(controller, message))
	return encMode.Marshal(pkg)
}

// OpenRemovalKeyPackage authenticates the package against the removal and the
// exact encrypted checkpoint before decrypting the epoch key.
func (keys *DeviceKeys) OpenRemovalKeyPackage(wire, previous, current []byte, confirmed [32]byte, checkpoint []byte) ([32]byte, error) {
	var epochKey [32]byte
	if len(wire) > removalKeyPackageMaxSize || len(checkpoint) > removalCheckpointMaxEnvelopeSize {
		return epochKey, errors.New("removal key package or checkpoint exceeds size limit")
	}
	var pkg signedRemovalKeyPackage
	if err := decodeCanonicalPairing(wire, &pkg); err != nil {
		return epochKey, err
	}
	membership, err := VerifyRemoval(current, previous, confirmed)
	if err != nil {
		return epochKey, err
	}
	h := membership.Header
	if pkg.Header != removalKeyPackageBinding(h, current, checkpoint) || len(pkg.Ciphertext) != removalKeyPackageCiphertextSize {
		return epochKey, errors.New("invalid removal key package binding or ciphertext length")
	}
	owner := h.Members[0]
	if keys == nil || keys.exchange == nil || len(keys.signing) != ed25519.PrivateKeySize ||
		!bytes.Equal(keys.exchange.PublicKey().Bytes(), owner.ExchangePub[:]) ||
		!bytes.Equal(keys.signing[ed25519.SeedSize:], owner.SigningPub[:]) {
		return epochKey, errors.New("removal key package does not match the recipient keys")
	}
	message, err := pkg.signatureInput()
	if err != nil {
		return epochKey, err
	}
	if !ed25519.Verify(h.ControllerPub[:], message, pkg.Signature[:]) {
		return epochKey, errors.New("invalid removal key package signature")
	}
	aad, err := encMode.Marshal(pkg.Header)
	if err != nil {
		return epochKey, err
	}
	private, err := hpke.NewDHKEMPrivateKey(keys.exchange)
	if err != nil {
		return epochKey, err
	}
	recipient, err := hpke.NewRecipient(pkg.Enc[:], private, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(removalKeyPackageHPKEDomain))
	if err != nil {
		return epochKey, err
	}
	plaintext, err := recipient.Open(aad, pkg.Ciphertext)
	if err != nil {
		return epochKey, err
	}
	defer clear(plaintext)
	if len(plaintext) != len(epochKey) {
		return epochKey, errors.New("invalid removal epoch key length")
	}
	return [32]byte(plaintext), nil
}

func removalKeyPackageBinding(h MembershipHeader, current, checkpoint []byte) removalKeyPackageHeader {
	owner := h.Members[0]
	return removalKeyPackageHeader{
		Version: removalKeyPackageVersion, SpaceID: h.SpaceID, Revision: h.Revision, Epoch: h.Epoch,
		RecipientID: owner.DeviceID, RecipientPub: owner.ExchangePub,
		MembershipHash: sha256.Sum256(current), CheckpointHash: sha256.Sum256(checkpoint),
	}
}

func (pkg signedRemovalKeyPackage) signatureInput() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(removalKeyPackageSignatureDomain)
	err := encMode.NewEncoder(&buffer).Encode([]any{pkg.Header, pkg.Enc, pkg.Ciphertext})
	return buffer.Bytes(), err
}
