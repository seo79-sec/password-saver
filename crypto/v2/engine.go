// Package cryptov2 implements an isolated version-2 authenticated container.
// It is intentionally not wired into the version-1 vault or application flows.
package cryptov2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	FormatID      = "passwordsaver-v2"
	FormatVersion = 2
	AEADAES256GCM = "aes-256-gcm"
	KDFArgon2id   = "argon2id"

	SaltSize             = 32
	DEKSize              = 32
	MaxPlaintextSize     = 32 << 20
	MaxContainerSize     = 44 << 20
	MinArgonMemoryKiB    = 19 * 1024
	MaxArgonMemoryKiB    = 256 * 1024
	MinArgonTime         = 2
	MaxArgonTime         = 6
	MinArgonThreads      = 1
	MaxArgonThreads      = 8
	Argon2idVersion      = argon2.Version
	defaultArgonTime     = 3
	defaultArgonMemory   = 64 * 1024
	defaultArgonThreads  = 4
	maxAlgorithmIDLength = 64
)

var (
	ErrInvalidContainer     = errors.New("invalid v2 container")
	ErrUnsupportedFormat    = errors.New("unsupported v2 container format or version")
	ErrUnsupportedAlgorithm = errors.New("unsupported v2 cryptographic algorithm")
	ErrAuthentication       = errors.New("v2 authentication failed")
	ErrInvalidParameters    = errors.New("invalid v2 cryptographic parameters")
	ErrInputTooLarge        = errors.New("v2 input exceeds size limit")
	ErrPasswordTooShort     = errors.New("master password must contain at least 12 bytes")
)

// AEADAlgorithm describes a registered authenticated-encryption algorithm.
// Implementations must return a fresh cipher.AEAD from New for each operation.
type AEADAlgorithm interface {
	ID() string
	KeySize() int
	NonceSize() int
	TagSize() int
	New(key []byte) (cipher.AEAD, error)
}

// AES256GCM is the only algorithm implemented by this stage.
type AES256GCM struct{}

func (AES256GCM) ID() string     { return AEADAES256GCM }
func (AES256GCM) KeySize() int   { return DEKSize }
func (AES256GCM) NonceSize() int { return 12 }
func (AES256GCM) TagSize() int   { return 16 }
func (AES256GCM) New(key []byte) (cipher.AEAD, error) {
	if len(key) != DEKSize {
		return nil, fmt.Errorf("%w: AES-256-GCM requires a 32-byte key", ErrInvalidParameters)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// KDFConfig selects resource-bounded Argon2id parameters for new containers.
type KDFConfig struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// KDFMetadata is serialized in the container and authenticated as AAD.
type KDFMetadata struct {
	ID        string `json:"id"`
	Version   uint32 `json:"version"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memoryKiB"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
}

// Container is the canonical JSON wire representation. AEAD tags are appended
// to WrappedDEK and Ciphertext by cipher.AEAD.Seal and stored in those fields.
type Container struct {
	Format     string      `json:"format"`
	Version    uint16      `json:"version"`
	AEAD       string      `json:"aead"`
	KDF        KDFMetadata `json:"kdf"`
	WrapNonce  string      `json:"wrapNonce"`
	WrappedDEK string      `json:"wrappedDEK"`
	Nonce      string      `json:"nonce"`
	Ciphertext string      `json:"ciphertext"`
}

// Options configures an Engine. Random is injectable for deterministic failure
// tests; production callers should leave it nil to use crypto/rand.Reader.
type Options struct {
	Random      io.Reader
	KDF         KDFConfig
	AlgorithmID string
}

// Engine implements an authenticated, versioned envelope-encryption format.
// Each Encrypt call creates a fresh DEK and fresh KDF salt. The DEK is used for
// one payload Seal, and the derived KEK is used for one DEK-wrapping Seal.
type Engine struct {
	random      io.Reader
	randomMu    sync.Mutex
	kdf         KDFConfig
	algorithmID string
	algorithms  map[string]AEADAlgorithm
}

// NewEngine creates an AES-256-GCM engine and optionally registers additional
// AEAD implementations for future formats. AES-256-GCM remains registered for
// reading existing v2 containers. An unregistered ID is never accepted.
func NewEngine(options Options, additional ...AEADAlgorithm) (*Engine, error) {
	if options.KDF == (KDFConfig{}) {
		options.KDF = KDFConfig{Time: defaultArgonTime, MemoryKiB: defaultArgonMemory, Threads: defaultArgonThreads}
	}
	if err := validateKDFConfig(options.KDF); err != nil {
		return nil, err
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	algorithms := map[string]AEADAlgorithm{AEADAES256GCM: AES256GCM{}}
	for _, algorithm := range additional {
		if algorithm == nil || !validAlgorithmID(algorithm.ID()) || algorithm.KeySize() != DEKSize || algorithm.NonceSize() <= 0 || algorithm.TagSize() <= 0 {
			return nil, fmt.Errorf("%w: invalid AEAD registration", ErrInvalidParameters)
		}
		if _, exists := algorithms[algorithm.ID()]; exists {
			return nil, fmt.Errorf("%w: duplicate AEAD ID %q", ErrInvalidParameters, algorithm.ID())
		}
		algorithms[algorithm.ID()] = algorithm
	}
	selected := options.AlgorithmID
	if selected == "" {
		selected = AEADAES256GCM
	}
	if _, ok := algorithms[selected]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, selected)
	}
	return &Engine{random: options.Random, kdf: options.KDF, algorithmID: selected, algorithms: algorithms}, nil
}

// Encrypt serializes plaintext into a v2 envelope. It never modifies v1 files.
func (e *Engine) Encrypt(masterPassword string, plaintext []byte) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidParameters
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrInputTooLarge
	}
	if len(masterPassword) < 12 {
		return nil, ErrPasswordTooShort
	}
	algorithm := e.algorithms[e.algorithmID]
	if algorithm == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	if algorithm.KeySize() != DEKSize || algorithm.NonceSize() <= 0 || algorithm.TagSize() <= 0 {
		return nil, ErrInvalidParameters
	}

	salt := make([]byte, SaltSize)
	dek := make([]byte, DEKSize)
	wrapNonce := make([]byte, algorithm.NonceSize())
	nonce := make([]byte, algorithm.NonceSize())
	for _, value := range [][]byte{salt, dek, wrapNonce, nonce} {
		if err := e.randomBytes(value); err != nil {
			wipe(dek)
			return nil, fmt.Errorf("secure random generation failed: %w", err)
		}
	}
	defer wipe(dek)

	passwordBytes := []byte(masterPassword)
	defer wipe(passwordBytes)
	kek := deriveKEK(passwordBytes, salt, e.kdf)
	defer wipe(kek)

	metadata := Container{
		Format:  FormatID,
		Version: FormatVersion,
		AEAD:    algorithm.ID(),
		KDF: KDFMetadata{
			ID: KDFArgon2id, Version: Argon2idVersion,
			Time: e.kdf.Time, MemoryKiB: e.kdf.MemoryKiB, Threads: e.kdf.Threads,
			Salt: base64.StdEncoding.EncodeToString(salt),
		},
	}
	wrapAAD := makeWrapAAD(metadata, salt, wrapNonce)
	wrappedDEK, err := sealAEAD(algorithm, kek, wrapNonce, dek, wrapAAD)
	if err != nil {
		return nil, err
	}
	metadata.WrapNonce = base64.StdEncoding.EncodeToString(wrapNonce)
	metadata.WrappedDEK = base64.StdEncoding.EncodeToString(wrappedDEK)
	metadata.Nonce = base64.StdEncoding.EncodeToString(nonce)
	payloadAAD := makePayloadAAD(metadata, salt, wrapNonce, wrappedDEK, nonce)
	ciphertext, err := sealAEAD(algorithm, dek, nonce, plaintext, payloadAAD)
	if err != nil {
		return nil, err
	}
	metadata.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	serialized, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	if len(serialized) > MaxContainerSize {
		return nil, ErrInputTooLarge
	}
	return serialized, nil
}

// Decrypt parses, validates, authenticates, and opens a v2 container. Structural
// and KDF resource limits are checked before any Argon2id work is performed.
func (e *Engine) Decrypt(masterPassword string, serialized []byte) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidParameters
	}
	if len(serialized) > MaxContainerSize {
		return nil, ErrInputTooLarge
	}
	if len(masterPassword) < 12 {
		return nil, ErrPasswordTooShort
	}
	container, err := parseContainer(serialized)
	if err != nil {
		return nil, err
	}
	if container.Format != FormatID || container.Version != FormatVersion {
		return nil, ErrUnsupportedFormat
	}
	if container.KDF.ID != KDFArgon2id || container.KDF.Version != Argon2idVersion {
		return nil, ErrUnsupportedFormat
	}
	if err := validateKDFConfig(KDFConfig{Time: container.KDF.Time, MemoryKiB: container.KDF.MemoryKiB, Threads: container.KDF.Threads}); err != nil {
		return nil, err
	}
	algorithm := e.algorithms[container.AEAD]
	if algorithm == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, container.AEAD)
	}
	if algorithm.KeySize() != DEKSize || algorithm.NonceSize() <= 0 || algorithm.TagSize() <= 0 {
		return nil, ErrInvalidParameters
	}
	salt, err := decodeCanonicalBase64(container.KDF.Salt, SaltSize)
	if err != nil || len(salt) != SaltSize {
		return nil, ErrInvalidContainer
	}
	wrapNonce, err := decodeCanonicalBase64(container.WrapNonce, algorithm.NonceSize())
	if err != nil || len(wrapNonce) != algorithm.NonceSize() {
		return nil, ErrInvalidContainer
	}
	nonce, err := decodeCanonicalBase64(container.Nonce, algorithm.NonceSize())
	if err != nil || len(nonce) != algorithm.NonceSize() {
		return nil, ErrInvalidContainer
	}
	wrappedDEK, err := decodeCanonicalBase64(container.WrappedDEK, DEKSize+algorithm.TagSize())
	if err != nil || len(wrappedDEK) != DEKSize+algorithm.TagSize() {
		return nil, ErrInvalidContainer
	}
	maxCiphertext := MaxPlaintextSize + algorithm.TagSize()
	ciphertext, err := decodeCanonicalBase64(container.Ciphertext, maxCiphertext)
	if err != nil || len(ciphertext) < algorithm.TagSize() || len(ciphertext) > maxCiphertext {
		return nil, ErrInvalidContainer
	}

	passwordBytes := []byte(masterPassword)
	defer wipe(passwordBytes)
	kek := deriveKEK(passwordBytes, salt, KDFConfig{Time: container.KDF.Time, MemoryKiB: container.KDF.MemoryKiB, Threads: container.KDF.Threads})
	defer wipe(kek)
	dek, err := openAEAD(algorithm, kek, wrapNonce, wrappedDEK, makeWrapAAD(container, salt, wrapNonce))
	if err != nil || len(dek) != DEKSize {
		wipe(dek)
		return nil, ErrAuthentication
	}
	defer wipe(dek)
	plaintext, err := openAEAD(algorithm, dek, nonce, ciphertext, makePayloadAAD(container, salt, wrapNonce, wrappedDEK, nonce))
	if err != nil {
		wipe(plaintext)
		return nil, ErrAuthentication
	}
	if len(plaintext) > MaxPlaintextSize {
		wipe(plaintext)
		return nil, ErrInputTooLarge
	}
	return plaintext, nil
}

func parseContainer(serialized []byte) (Container, error) {
	var container Container
	if len(serialized) == 0 || len(serialized) > MaxContainerSize {
		return container, ErrInputTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(serialized))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&container); err != nil {
		return Container{}, fmt.Errorf("%w: %v", ErrInvalidContainer, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Container{}, ErrInvalidContainer
	}
	canonical, err := json.Marshal(container)
	if err != nil || !bytes.Equal(canonical, serialized) {
		return Container{}, ErrInvalidContainer
	}
	if !validAlgorithmID(container.AEAD) || !validAlgorithmID(container.KDF.ID) {
		return Container{}, ErrInvalidContainer
	}
	return container, nil
}

func validateKDFConfig(config KDFConfig) error {
	if config.Time < MinArgonTime || config.Time > MaxArgonTime ||
		config.MemoryKiB < MinArgonMemoryKiB || config.MemoryKiB > MaxArgonMemoryKiB ||
		config.Threads < MinArgonThreads || config.Threads > MaxArgonThreads {
		return fmt.Errorf("%w: Argon2id values outside accepted bounds", ErrInvalidParameters)
	}
	return nil
}

func deriveKEK(password, salt []byte, config KDFConfig) []byte {
	return argon2.IDKey(password, salt, config.Time, config.MemoryKiB, config.Threads, DEKSize)
}

func (e *Engine) randomBytes(destination []byte) error {
	e.randomMu.Lock()
	defer e.randomMu.Unlock()
	_, err := io.ReadFull(e.random, destination)
	return err
}

func sealAEAD(algorithm AEADAlgorithm, key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != algorithm.KeySize() || len(nonce) != algorithm.NonceSize() {
		return nil, ErrInvalidParameters
	}
	aead, err := algorithm.New(key)
	if err != nil {
		return nil, err
	}
	if aead == nil || aead.NonceSize() != algorithm.NonceSize() || aead.Overhead() != algorithm.TagSize() {
		return nil, ErrInvalidParameters
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func openAEAD(algorithm AEADAlgorithm, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != algorithm.KeySize() || len(nonce) != algorithm.NonceSize() || len(ciphertext) < algorithm.TagSize() {
		return nil, ErrInvalidParameters
	}
	aead, err := algorithm.New(key)
	if err != nil {
		return nil, err
	}
	if aead == nil || aead.NonceSize() != algorithm.NonceSize() || aead.Overhead() != algorithm.TagSize() {
		return nil, ErrInvalidParameters
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func makeWrapAAD(container Container, salt, wrapNonce []byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("PasswordSaver/v2/DEK-WRAP\x00")
	writeField(&buffer, []byte(container.Format))
	_ = binary.Write(&buffer, binary.BigEndian, container.Version)
	writeField(&buffer, []byte(container.AEAD))
	writeField(&buffer, []byte(container.KDF.ID))
	_ = binary.Write(&buffer, binary.BigEndian, container.KDF.Version)
	_ = binary.Write(&buffer, binary.BigEndian, container.KDF.Time)
	_ = binary.Write(&buffer, binary.BigEndian, container.KDF.MemoryKiB)
	buffer.WriteByte(container.KDF.Threads)
	writeField(&buffer, salt)
	writeField(&buffer, wrapNonce)
	return buffer.Bytes()
}

func makePayloadAAD(container Container, salt, wrapNonce, wrappedDEK, nonce []byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("PasswordSaver/v2/PAYLOAD\x00")
	writeField(&buffer, makeWrapAAD(container, salt, wrapNonce))
	writeField(&buffer, wrappedDEK)
	writeField(&buffer, nonce)
	return buffer.Bytes()
}

func writeField(buffer *bytes.Buffer, value []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	_, _ = buffer.Write(value)
}

func decodeCanonicalBase64(encoded string, maximumDecoded int) ([]byte, error) {
	maximumEncoded := base64.StdEncoding.EncodedLen(maximumDecoded)
	if len(encoded) > maximumEncoded {
		return nil, ErrInputTooLarge
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > maximumDecoded || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrInvalidContainer
	}
	return decoded, nil
}

func validAlgorithmID(value string) bool {
	if len(value) == 0 || len(value) > maxAlgorithmIDLength {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
