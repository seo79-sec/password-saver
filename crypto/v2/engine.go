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
	GenerateNonce(random io.Reader) ([]byte, error)
	ValidateNonce(nonce []byte) error
	New(key []byte) (cipher.AEAD, error)
}

// AES256GCM is the only algorithm implemented by this stage.
type AES256GCM struct{}

func (AES256GCM) ID() string     { return AEADAES256GCM }
func (AES256GCM) KeySize() int   { return DEKSize }
func (AES256GCM) NonceSize() int { return 12 }
func (AES256GCM) TagSize() int   { return 16 }
func (a AES256GCM) GenerateNonce(random io.Reader) ([]byte, error) {
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	return nonce, a.ValidateNonce(nonce)
}
func (a AES256GCM) ValidateNonce(nonce []byte) error {
	if len(nonce) != a.NonceSize() {
		return fmt.Errorf("%w: AES-256-GCM nonce must be 12 bytes", ErrInvalidParameters)
	}
	return nil
}
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

// RFC9058MGMNoncePolicy implements MGM's nonce shape rules for a provider that
// implements the mode: exactly one block, with the most significant bit clear
// because the ICN value occupies only n-1 bits.
// It does not implement MGM or provide a complete MGM algorithm provider.
type RFC9058MGMNoncePolicy struct {
	BlockSize int
}

func (p RFC9058MGMNoncePolicy) GenerateNonce(random io.Reader) ([]byte, error) {
	if p.BlockSize <= 0 {
		return nil, ErrInvalidParameters
	}
	nonce := make([]byte, p.BlockSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	nonce[0] &= 0x7f
	return nonce, p.ValidateNonce(nonce)
}

func (p RFC9058MGMNoncePolicy) ValidateNonce(nonce []byte) error {
	if p.BlockSize <= 0 || len(nonce) != p.BlockSize || nonce[0]&0x80 != 0 {
		return fmt.Errorf("%w: invalid RFC 9058 MGM nonce", ErrInvalidParameters)
	}
	return nil
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
	for _, value := range [][]byte{salt, dek} {
		if err := e.randomBytes(value); err != nil {
			wipe(dek)
			return nil, fmt.Errorf("secure random generation failed: %w", err)
		}
	}
	wrapNonce, err := e.generateNonce(algorithm)
	if err != nil {
		wipe(dek)
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}
	nonce, err := e.generateNonce(algorithm)
	if err != nil {
		wipe(dek)
		return nil, fmt.Errorf("secure random generation failed: %w", err)
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
	payloadAAD := makePayloadAAD(metadata, nonce)
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
	opened, err := e.openContainer(masterPassword, serialized)
	if err != nil {
		return nil, err
	}
	wipe(opened.dek)
	return opened.plaintext, nil
}

// ChangeMasterPassword authenticates the complete current container, then
// rewraps its existing DEK with a new Argon2id salt and KEK. Payload ciphertext
// and nonce are preserved byte-for-byte. It does not write files.
func (e *Engine) ChangeMasterPassword(serialized []byte, currentPassword, newPassword string) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidParameters
	}
	if len(newPassword) < 12 {
		return nil, ErrPasswordTooShort
	}
	opened, err := e.openContainer(currentPassword, serialized)
	if err != nil {
		return nil, err
	}
	defer wipe(opened.dek)
	wipe(opened.plaintext)

	algorithm := e.algorithms[opened.container.AEAD]
	if algorithm == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	salt := make([]byte, SaltSize)
	if err := e.randomBytes(salt); err != nil {
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}
	wrapNonce, err := e.generateNonce(algorithm)
	if err != nil {
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}
	passwordBytes := []byte(newPassword)
	defer wipe(passwordBytes)
	kdfConfig := KDFConfig{Time: opened.container.KDF.Time, MemoryKiB: opened.container.KDF.MemoryKiB, Threads: opened.container.KDF.Threads}
	kek := deriveKEK(passwordBytes, salt, kdfConfig)
	defer wipe(kek)

	rotated := opened.container
	rotated.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
	rotated.WrapNonce = base64.StdEncoding.EncodeToString(wrapNonce)
	wrapAAD := makeWrapAAD(rotated, salt, wrapNonce)
	wrappedDEK, err := sealAEAD(algorithm, kek, wrapNonce, opened.dek, wrapAAD)
	if err != nil {
		return nil, err
	}
	rotated.WrappedDEK = base64.StdEncoding.EncodeToString(wrappedDEK)
	result, err := json.Marshal(rotated)
	if err != nil {
		return nil, err
	}
	if len(result) > MaxContainerSize {
		return nil, ErrInputTooLarge
	}
	return result, nil
}

type openedContainer struct {
	container Container
	dek       []byte
	plaintext []byte
}

func (e *Engine) openContainer(masterPassword string, serialized []byte) (openedContainer, error) {
	var opened openedContainer
	if len(serialized) > MaxContainerSize {
		return opened, ErrInputTooLarge
	}
	if len(masterPassword) < 12 {
		return opened, ErrPasswordTooShort
	}
	container, err := parseContainer(serialized)
	if err != nil {
		return opened, err
	}
	if container.Format != FormatID || container.Version != FormatVersion {
		return opened, ErrUnsupportedFormat
	}
	if container.KDF.ID != KDFArgon2id || container.KDF.Version != Argon2idVersion {
		return opened, ErrUnsupportedFormat
	}
	kdfConfig := KDFConfig{Time: container.KDF.Time, MemoryKiB: container.KDF.MemoryKiB, Threads: container.KDF.Threads}
	if err := validateKDFConfig(kdfConfig); err != nil {
		return opened, err
	}
	algorithm := e.algorithms[container.AEAD]
	if algorithm == nil {
		return opened, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, container.AEAD)
	}
	if algorithm.KeySize() != DEKSize || algorithm.NonceSize() <= 0 || algorithm.TagSize() <= 0 {
		return opened, ErrInvalidParameters
	}
	salt, err := decodeCanonicalBase64(container.KDF.Salt, SaltSize)
	if err != nil || len(salt) != SaltSize {
		return opened, ErrInvalidContainer
	}
	wrapNonce, err := decodeCanonicalBase64(container.WrapNonce, algorithm.NonceSize())
	if err != nil || algorithm.ValidateNonce(wrapNonce) != nil {
		return opened, ErrInvalidContainer
	}
	nonce, err := decodeCanonicalBase64(container.Nonce, algorithm.NonceSize())
	if err != nil || algorithm.ValidateNonce(nonce) != nil {
		return opened, ErrInvalidContainer
	}
	wrappedDEK, err := decodeCanonicalBase64(container.WrappedDEK, DEKSize+algorithm.TagSize())
	if err != nil || len(wrappedDEK) != DEKSize+algorithm.TagSize() {
		return opened, ErrInvalidContainer
	}
	maxCiphertext := MaxPlaintextSize + algorithm.TagSize()
	ciphertext, err := decodeCanonicalBase64(container.Ciphertext, maxCiphertext)
	if err != nil || len(ciphertext) < algorithm.TagSize() || len(ciphertext) > maxCiphertext {
		return opened, ErrInvalidContainer
	}

	passwordBytes := []byte(masterPassword)
	defer wipe(passwordBytes)
	kek := deriveKEK(passwordBytes, salt, kdfConfig)
	defer wipe(kek)
	dek, err := openAEAD(algorithm, kek, wrapNonce, wrappedDEK, makeWrapAAD(container, salt, wrapNonce))
	if err != nil || len(dek) != DEKSize {
		wipe(dek)
		return opened, ErrAuthentication
	}
	plaintext, err := openAEAD(algorithm, dek, nonce, ciphertext, makePayloadAAD(container, nonce))
	if err != nil {
		wipe(dek)
		wipe(plaintext)
		return opened, ErrAuthentication
	}
	if len(plaintext) > MaxPlaintextSize {
		wipe(dek)
		wipe(plaintext)
		return opened, ErrInputTooLarge
	}
	return openedContainer{container: container, dek: dek, plaintext: plaintext}, nil
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
	_, err := io.ReadFull(engineRandomReader{engine: e}, destination)
	return err
}

func (e *Engine) generateNonce(algorithm AEADAlgorithm) ([]byte, error) {
	nonce, err := algorithm.GenerateNonce(engineRandomReader{engine: e})
	if err != nil {
		return nil, err
	}
	if len(nonce) != algorithm.NonceSize() || algorithm.ValidateNonce(nonce) != nil {
		return nil, ErrInvalidParameters
	}
	return nonce, nil
}

type engineRandomReader struct{ engine *Engine }

func (r engineRandomReader) Read(buffer []byte) (int, error) {
	r.engine.randomMu.Lock()
	defer r.engine.randomMu.Unlock()
	return r.engine.random.Read(buffer)
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

func makePayloadAAD(container Container, nonce []byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("PasswordSaver/v2/PAYLOAD\x00")
	writeField(&buffer, []byte(container.Format))
	_ = binary.Write(&buffer, binary.BigEndian, container.Version)
	writeField(&buffer, []byte(container.AEAD))
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
