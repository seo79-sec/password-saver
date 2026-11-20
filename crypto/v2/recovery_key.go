package cryptov2

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	RecoverySlotVersion = 1
	recoveryKeyPrefix   = "PSRK1-"
	recoveryKeyDomain   = "PasswordSaver/v2/RECOVERY-KEK/v1"
)

var (
	ErrRecoveryKeyUnavailable = errors.New("v2 recovery key was not configured")
	ErrRecoveryKeyInvalid     = errors.New("v2 recovery key authentication failed")
	// The recovery wrapper authenticated, but the payload did not. Callers
	// may offer an explicit authenticated backup repair in this case.
	ErrRecoveryPayload = errors.New("v2 recovery wrapper opened but payload authentication failed")
)

// RecoverySlot is an optional v2 DEK wrapper. Its version fixes HKDF-SHA256 as
// the KDF. The container's AEAD applies to both wrappers.
type RecoverySlot struct {
	Version    uint16 `json:"version"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	WrappedDEK string `json:"wrappedDEK"`
}

// EncryptWithRecoveryKey creates a new DEK and an independent random recovery
// key. The returned key is the only copy of the printable secret.
func (e *Engine) EncryptWithRecoveryKey(password string, plaintext []byte) ([]byte, string, error) {
	if e == nil {
		return nil, "", ErrInvalidParameters
	}
	key := make([]byte, DEKSize)
	defer wipe(key)
	if err := e.randomBytes(key); err != nil {
		return nil, "", err
	}
	encoded, err := e.encrypt(password, plaintext, key)
	if err != nil {
		return nil, "", err
	}
	return encoded, recoveryKeyPrefix + base64.RawURLEncoding.EncodeToString(key), nil
}

func (e *Engine) DecryptWithRecoveryKey(encodedKey string, serialized []byte) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidParameters
	}
	key, err := decodeRecoveryKey(encodedKey)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	v, err := e.validateContainer(serialized)
	if err != nil {
		return nil, err
	}
	slot := v.container.Recovery
	if slot == nil {
		return nil, ErrRecoveryKeyUnavailable
	}
	salt, nonce, wrapped, err := recoverySlotFields(slot, v.algorithm)
	if err != nil {
		return nil, err
	}
	kek, err := hkdf.Key(sha256.New, key, salt, recoveryKeyDomain, DEKSize)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	dek, err := openAEAD(v.algorithm, kek, nonce, wrapped, recoveryWrapAAD(v.container, slot.Version, salt, nonce))
	if err != nil || len(dek) != DEKSize {
		wipe(dek)
		return nil, ErrRecoveryKeyInvalid
	}
	defer wipe(dek)
	plaintext, err := v.openPayload(dek)
	if err != nil {
		return nil, errors.Join(ErrRecoveryPayload, err)
	}
	return plaintext, nil
}

func decodeRecoveryKey(encoded string) ([]byte, error) {
	value, found := strings.CutPrefix(encoded, recoveryKeyPrefix)
	if !found || len(value) != base64.RawURLEncoding.EncodedLen(DEKSize) {
		return nil, ErrRecoveryKeyInvalid
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != DEKSize || base64.RawURLEncoding.EncodeToString(key) != value {
		wipe(key)
		return nil, ErrRecoveryKeyInvalid
	}
	return key, nil
}

func (e *Engine) wrapRecoveryKey(container Container, algorithm AEADAlgorithm, dek, key []byte) (*RecoverySlot, error) {
	salt := make([]byte, SaltSize)
	if err := e.randomBytes(salt); err != nil {
		return nil, err
	}
	nonce, err := e.generateNonce(algorithm)
	if err != nil {
		return nil, err
	}
	kek, err := hkdf.Key(sha256.New, key, salt, recoveryKeyDomain, DEKSize)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	wrapped, err := sealAEAD(algorithm, kek, nonce, dek, recoveryWrapAAD(container, RecoverySlotVersion, salt, nonce))
	if err != nil {
		return nil, err
	}
	return &RecoverySlot{
		Version: RecoverySlotVersion, Salt: base64.StdEncoding.EncodeToString(salt),
		Nonce: base64.StdEncoding.EncodeToString(nonce), WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

func recoverySlotFields(slot *RecoverySlot, algorithm AEADAlgorithm) (salt, nonce, wrapped []byte, err error) {
	if slot == nil {
		return nil, nil, nil, nil
	}
	if slot.Version != RecoverySlotVersion {
		return nil, nil, nil, ErrUnsupportedFormat
	}
	salt, saltErr := decodeCanonicalBase64(slot.Salt, SaltSize)
	nonce, nonceErr := decodeCanonicalBase64(slot.Nonce, algorithm.NonceSize())
	wrapped, wrapErr := decodeCanonicalBase64(slot.WrappedDEK, DEKSize+algorithm.TagSize())
	if saltErr != nil || len(salt) != SaltSize || nonceErr != nil || algorithm.ValidateNonce(nonce) != nil ||
		wrapErr != nil || len(wrapped) != DEKSize+algorithm.TagSize() {
		return nil, nil, nil, ErrInvalidContainer
	}
	return salt, nonce, wrapped, nil
}

func recoveryWrapAAD(container Container, version uint16, salt, nonce []byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("PasswordSaver/v2/RECOVERY-DEK-WRAP\x00")
	writeField(&buffer, []byte(container.Format))
	_ = binary.Write(&buffer, binary.BigEndian, container.Version)
	writeField(&buffer, []byte(container.AEAD))
	_ = binary.Write(&buffer, binary.BigEndian, version)
	writeField(&buffer, salt)
	writeField(&buffer, nonce)
	return buffer.Bytes()
}
