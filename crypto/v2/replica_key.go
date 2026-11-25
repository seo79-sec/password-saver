package cryptov2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

const (
	ReplicaKeySize        = 32
	replicaKeyWrapVersion = 1
	replicaKeyWrapInfo    = "PasswordSaver/v3/replica-key-wrap/key/v1"
	replicaKeyWrapDomain  = "PasswordSaver/v3/replica-key-wrap\x00"
	replicaKeyHeaderSize  = 1 + SaltSize
	// Version, salt, and the AES-GCM envelope with its 12-byte nonce and 16-byte tag.
	replicaKeyWrapSize = replicaKeyHeaderSize + 12 + ReplicaKeySize + 16
)

var ErrInvalidReplicaKeyWrap = errors.New("invalid replica key wrapper")

// WrapReplicaKey seals an independently generated random key for replicaID.
func (s *Session) WrapReplicaKey(replicaID [16]byte, key [ReplicaKeySize]byte) ([]byte, error) {
	defer clear(key[:])
	if s == nil {
		return nil, ErrSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.engine == nil || len(s.dek) != DEKSize {
		return nil, ErrSessionClosed
	}
	wrapped := make([]byte, replicaKeyHeaderSize, replicaKeyWrapSize)
	wrapped[0] = replicaKeyWrapVersion
	salt := wrapped[1:]
	if err := s.engine.randomBytes(salt); err != nil {
		return nil, err
	}
	aead, err := replicaKeyWrapAEAD(s.dek, salt)
	if err != nil {
		return nil, err
	}
	return aead.Seal(wrapped, nil, key[:], replicaKeyWrapAAD(wrapped[0], replicaID)), nil
}

// OpenReplicaKey authenticates wrapped for replicaID and returns a key that
// the caller must clear after use.
func (s *Session) OpenReplicaKey(replicaID [16]byte, wrapped []byte) ([ReplicaKeySize]byte, error) {
	var key [ReplicaKeySize]byte
	if s == nil {
		return key, ErrSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.engine == nil || len(s.dek) != DEKSize {
		return key, ErrSessionClosed
	}
	if len(wrapped) != replicaKeyWrapSize || wrapped[0] != replicaKeyWrapVersion {
		return key, ErrInvalidReplicaKeyWrap
	}
	aead, err := replicaKeyWrapAEAD(s.dek, wrapped[1:replicaKeyHeaderSize])
	if err != nil {
		return key, err
	}
	defer clear(key[:])
	if _, err := aead.Open(key[:0], nil, wrapped[replicaKeyHeaderSize:], replicaKeyWrapAAD(wrapped[0], replicaID)); err != nil {
		return [ReplicaKeySize]byte{}, ErrAuthentication
	}
	return key, nil
}

func replicaKeyWrapAEAD(dek, salt []byte) (cipher.AEAD, error) {
	kek, err := hkdf.Key(sha256.New, dek, salt, replicaKeyWrapInfo, ReplicaKeySize)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func replicaKeyWrapAAD(version byte, replicaID [16]byte) []byte {
	aad := append([]byte(replicaKeyWrapDomain), version)
	return append(aad, replicaID[:]...)
}
