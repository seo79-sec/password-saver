package replicastore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const (
	schemaVersion = 1
	saltSize      = 32
	identitySize  = 16
	// NewGCMWithRandomNonce prefixes a 12-byte nonce and appends a 16-byte tag.
	envelopeOverhead = saltSize + 12 + 16
	keyContext       = "PasswordSaver/replicastore/state/key/v1"
	aadContext       = "PasswordSaver/replicastore/state\x00"
)

func stateAAD(identity [identitySize]byte, generation int64) []byte {
	aad := append([]byte(aadContext), identity[:]...)
	aad = binary.BigEndian.AppendUint32(aad, schemaVersion)
	return binary.BigEndian.AppendUint64(aad, uint64(generation))
}

func stateAEAD(key *[KeySize]byte, salt []byte) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, key[:], salt, keyContext, KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func sealState(key *[KeySize]byte, identity [identitySize]byte, generation int64, plaintext []byte) ([]byte, error) {
	envelope := make([]byte, saltSize, len(plaintext)+envelopeOverhead)
	rand.Read(envelope)
	aead, err := stateAEAD(key, envelope)
	if err != nil {
		return nil, err
	}
	return aead.Seal(envelope, nil, plaintext, stateAAD(identity, generation)), nil
}

func openState(key *[KeySize]byte, identity [identitySize]byte, generation int64, envelope []byte) ([]byte, error) {
	if len(envelope) < envelopeOverhead || len(envelope) > maxStateSize+envelopeOverhead {
		return nil, ErrCorrupt
	}
	aead, err := stateAEAD(key, envelope[:saltSize])
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nil, envelope[saltSize:], stateAAD(identity, generation))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
