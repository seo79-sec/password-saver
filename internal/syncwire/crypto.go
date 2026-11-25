package syncwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	changeKeyDomain       = "PasswordSaver/sync/change/key/v1"
	changeAADDomain       = "PasswordSaver/sync/change/aad/v1\x00"
	changeSignatureDomain = "PasswordSaver/sync/change/sign/v1\x00"
	epochKeySize          = 32
	maxPlaintextSize      = 65_536
)

var (
	errChangeSignature = errors.New("invalid change envelope signature")
	errChangeDecrypt   = errors.New("change envelope authentication failed")
)

// Seal encrypts a change payload and signs the resulting header and ciphertext.
// The epoch key must contain 32 bytes.
func Seal(header Header, plaintext, epochKey []byte, signer ed25519.PrivateKey) (Envelope, error) {
	if len(plaintext) == 0 || len(plaintext) > maxPlaintextSize {
		return Envelope{}, errors.New("change payload length is out of range")
	}
	if len(signer) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid change signer private key length")
	}
	aead, err := changeAEAD(header, epochKey)
	if err != nil {
		return Envelope{}, err
	}
	aad, err := changeAAD(header)
	if err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{Header: header, Ciphertext: aead.Seal(nil, nil, plaintext, aad)}
	if err := envelope.validate(); err != nil {
		return Envelope{}, err
	}
	signed, err := changeSignatureInput(envelope)
	if err != nil {
		return Envelope{}, err
	}
	copy(envelope.Signature[:], ed25519.Sign(signer, signed))
	return envelope, nil
}

// Open authenticates an envelope against a caller's trusted signers and decrypts it.
// Use Parse on incoming wire bytes before calling Open.
func Open(envelope Envelope, expectedSpaceID [16]byte, expectedEpoch uint64, epochKey []byte, trustedSigners map[[16]byte]ed25519.PublicKey) ([]byte, error) {
	if err := envelope.validate(); err != nil {
		return nil, err
	}
	header := envelope.Header
	if header.SpaceID != expectedSpaceID || header.Epoch != expectedEpoch {
		return nil, errors.New("change envelope belongs to a different space or epoch")
	}
	signer, ok := trustedSigners[header.DeviceID]
	if !ok {
		return nil, errors.New("unknown change envelope signer")
	}
	if len(signer) != ed25519.PublicKeySize {
		return nil, errors.New("invalid change signer public key length")
	}
	signed, err := changeSignatureInput(envelope)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signer, signed, envelope.Signature[:]) {
		return nil, errChangeSignature
	}
	aead, err := changeAEAD(header, epochKey)
	if err != nil {
		return nil, err
	}
	aad, err := changeAAD(header)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, envelope.Ciphertext, aad)
	if err != nil {
		return nil, errChangeDecrypt
	}
	return plaintext, nil
}

func changeAEAD(header Header, epochKey []byte) (cipher.AEAD, error) {
	if len(epochKey) != epochKeySize {
		return nil, errors.New("invalid change epoch key length")
	}
	info, err := encMode.Marshal([]any{changeKeyDomain, header.SpaceID, header.Epoch, header.DeviceID})
	if err != nil {
		return nil, fmt.Errorf("encode change key context: %w", err)
	}
	key, err := hkdf.Key(sha256.New, epochKey, nil, string(info), 32)
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

func changeAAD(header Header) ([]byte, error) {
	encoded, err := encMode.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("encode change header: %w", err)
	}
	return append([]byte(changeAADDomain), encoded...), nil
}

func changeSignatureInput(envelope Envelope) ([]byte, error) {
	encoded, err := encMode.Marshal([]any{envelope.Header, envelope.Ciphertext})
	if err != nil {
		return nil, fmt.Errorf("encode signed change: %w", err)
	}
	return append([]byte(changeSignatureDomain), encoded...), nil
}
