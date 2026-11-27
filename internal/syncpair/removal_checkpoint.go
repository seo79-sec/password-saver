package syncpair

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"password-saver/internal/syncwire"
)

const (
	removalCheckpointVersion            = 1
	removalCheckpointKeyDomain          = "PasswordSaver/sync/removal/checkpoint/key/v1"
	removalCheckpointSignatureDomain    = "PasswordSaver/sync/removal/checkpoint/sign/v1"
	removalCheckpointMaxEnvelopeSize    = maxCheckpointSize + 256
	removalCheckpointEncryptionOverhead = 12 + 16 // GCM nonce and tag
)

type removalCheckpointHeader struct {
	_              struct{} `cbor:",toarray"`
	Version        uint64
	SpaceID        [16]byte
	Revision       uint64
	Epoch          uint64
	MembershipHash [32]byte
}

type signedRemovalCheckpoint struct {
	_          struct{} `cbor:",toarray"`
	Header     removalCheckpointHeader
	Ciphertext []byte // GCM prepends the nonce.
	Signature  [ed25519.SignatureSize]byte
}

// SealRemovalCheckpoint validates a MarshalCheckpoint snapshot against the signed
// removal and returns a fresh epoch key and the controller-signed encrypted snapshot.
func (keys *SpaceKeys) SealRemovalCheckpoint(previous, current []byte, confirmed [32]byte, checkpoint []byte) ([32]byte, []byte, error) {
	var epochKey [32]byte
	if len(checkpoint) > maxCheckpointSize {
		return epochKey, nil, errors.New("removal checkpoint exceeds size limit")
	}
	membership, err := VerifyRemoval(current, previous, confirmed)
	if err != nil {
		return epochKey, nil, err
	}
	h := membership.Header
	if keys == nil || len(keys.controller) != ed25519.PrivateKeySize {
		return epochKey, nil, errors.New("invalid controller key")
	}
	controller := ed25519.NewKeyFromSeed(keys.controller[:ed25519.SeedSize])
	defer clear(controller)
	if !bytes.Equal(controller[ed25519.SeedSize:], h.ControllerPub[:]) {
		return epochKey, nil, errors.New("controller key does not match membership")
	}

	rand.Read(epochKey[:])
	if _, err := restoreRemovalCheckpoint(checkpoint, h, epochKey); err != nil {
		return [32]byte{}, nil, err
	}
	envelope := signedRemovalCheckpoint{Header: removalCheckpointBinding(h, current)}
	aad, err := encMode.Marshal(envelope.Header)
	if err != nil {
		return [32]byte{}, nil, err
	}
	gcm, err := removalCheckpointAEAD(epochKey)
	if err != nil {
		return [32]byte{}, nil, err
	}
	envelope.Ciphertext = gcm.Seal(nil, nil, checkpoint, aad)
	envelope.Signature = [ed25519.SignatureSize]byte(ed25519.Sign(controller, removalCheckpointSignatureInput(aad, envelope.Ciphertext)))
	wire, err := encMode.Marshal(envelope)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return epochKey, wire, nil
}

// OpenRemovalCheckpoint authenticates the envelope against the signed removal
// and restores a fresh receiver whose writers come from the new membership.
func OpenRemovalCheckpoint(wire, previous, current []byte, confirmed, epochKey [32]byte) (*syncwire.Receiver, error) {
	receiver, checkpoint, err := openRemovalCheckpoint(wire, previous, current, confirmed, epochKey)
	clear(checkpoint)
	return receiver, err
}

// OpenRemovalCheckpointBytes returns the original canonical checkpoint after
// authentication and validation by RestoreCheckpoint. The caller must clear it when done.
func OpenRemovalCheckpointBytes(wire, previous, current []byte, confirmed, epochKey [32]byte) ([]byte, error) {
	_, checkpoint, err := openRemovalCheckpoint(wire, previous, current, confirmed, epochKey)
	return checkpoint, err
}

func openRemovalCheckpoint(wire, previous, current []byte, confirmed, epochKey [32]byte) (*syncwire.Receiver, []byte, error) {
	if len(wire) > removalCheckpointMaxEnvelopeSize {
		return nil, nil, errors.New("removal checkpoint envelope exceeds size limit")
	}
	var envelope signedRemovalCheckpoint
	if err := decodeCanonicalPairing(wire, &envelope); err != nil {
		return nil, nil, err
	}
	membership, err := VerifyRemoval(current, previous, confirmed)
	if err != nil {
		return nil, nil, err
	}
	h := membership.Header
	if envelope.Header != removalCheckpointBinding(h, current) ||
		len(envelope.Ciphertext) <= removalCheckpointEncryptionOverhead ||
		len(envelope.Ciphertext) > maxCheckpointSize+removalCheckpointEncryptionOverhead {
		return nil, nil, errors.New("invalid removal checkpoint header or ciphertext size")
	}
	aad, err := encMode.Marshal(envelope.Header)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(h.ControllerPub[:], removalCheckpointSignatureInput(aad, envelope.Ciphertext), envelope.Signature[:]) {
		return nil, nil, errors.New("invalid removal checkpoint signature")
	}
	gcm, err := removalCheckpointAEAD(epochKey)
	if err != nil {
		return nil, nil, err
	}
	checkpoint, err := gcm.Open(nil, nil, envelope.Ciphertext, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt removal checkpoint: %w", err)
	}
	receiver, err := restoreRemovalCheckpoint(checkpoint, h, epochKey)
	if err != nil {
		clear(checkpoint)
		return nil, nil, err
	}
	return receiver, checkpoint, nil
}
func removalCheckpointBinding(h MembershipHeader, current []byte) removalCheckpointHeader {
	return removalCheckpointHeader{Version: removalCheckpointVersion, SpaceID: h.SpaceID,
		Revision: h.Revision, Epoch: h.Epoch, MembershipHash: sha256.Sum256(current)}
}

func removalCheckpointAEAD(epochKey [32]byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, epochKey[:], nil, removalCheckpointKeyDomain, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func removalCheckpointSignatureInput(aad, ciphertext []byte) []byte {
	// The CBOR header is self-delimiting, and the ciphertext includes its nonce.
	input := make([]byte, 0, len(removalCheckpointSignatureDomain)+len(aad)+len(ciphertext))
	input = append(input, removalCheckpointSignatureDomain...)
	input = append(input, aad...)
	return append(input, ciphertext...)
}

func restoreRemovalCheckpoint(checkpoint []byte, h MembershipHeader, epochKey [32]byte) (*syncwire.Receiver, error) {
	signers := make(map[[16]byte]ed25519.PublicKey, len(h.Members))
	for _, member := range h.Members {
		signers[member.DeviceID] = ed25519.PublicKey(member.SigningPub[:])
	}
	return syncwire.RestoreCheckpoint(checkpoint, h.SpaceID, h.Epoch, epochKey[:], signers)
}
