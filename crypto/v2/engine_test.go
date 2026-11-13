package cryptov2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const testPassword = "v2-test-only-master-password"

func testEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(Options{KDF: KDFConfig{Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	engine := testEngine(t)
	plaintext := []byte(`{"accounts":[{"password":"synthetic-only-secret"}]}`)
	serialized, err := engine.Encrypt(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("synthetic-only-secret")) {
		t.Fatal("serialized v2 container contains clear-text password")
	}
	container := decodeTestContainer(t, serialized)
	wrapNonce, _ := base64.StdEncoding.DecodeString(container.WrapNonce)
	payloadNonce, _ := base64.StdEncoding.DecodeString(container.Nonce)
	if len(wrapNonce) != (AES256GCM{}).NonceSize() || len(payloadNonce) != (AES256GCM{}).NonceSize() {
		t.Fatalf("unexpected nonce lengths: wrap=%d payload=%d", len(wrapNonce), len(payloadNonce))
	}
	opened, err := engine.Decrypt(testPassword, serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypted payload = %q, want %q", opened, plaintext)
	}
	wipe(opened)
}

func TestWrongMasterPasswordAndCiphertextOrTagTampering(t *testing.T) {
	engine := testEngine(t)
	serialized, err := engine.Encrypt(testPassword, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Decrypt("different-test-master-password", serialized); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong password error = %v, want authentication failure", err)
	}

	for _, field := range []string{"ciphertext", "wrappedDEK"} {
		t.Run(field, func(t *testing.T) {
			container := decodeTestContainer(t, serialized)
			var encoded string
			if field == "ciphertext" {
				encoded = container.Ciphertext
			} else {
				encoded = container.WrappedDEK
			}
			raw, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 0x80 // damage the appended AEAD tag
			encoded = base64.StdEncoding.EncodeToString(raw)
			if field == "ciphertext" {
				container.Ciphertext = encoded
			} else {
				container.WrappedDEK = encoded
			}
			modified := marshalTestContainer(t, container)
			if _, err := engine.Decrypt(testPassword, modified); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("tampered %s error = %v, want authentication failure", field, err)
			}
		})
	}
}

func TestChangeMasterPasswordRewrapsOnlyDEK(t *testing.T) {
	engine := testEngine(t)
	plaintext := []byte("synthetic payload for password rotation")
	original, err := engine.Encrypt(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	originalContainer := decodeTestContainer(t, original)

	rotated, err := engine.ChangeMasterPassword(original, testPassword, "new-v2-test-master-password")
	if err != nil {
		t.Fatal(err)
	}
	rotatedContainer := decodeTestContainer(t, rotated)
	if rotatedContainer.Ciphertext != originalContainer.Ciphertext {
		t.Fatal("ciphertext changed during master-password rotation")
	}
	if rotatedContainer.Nonce != originalContainer.Nonce {
		t.Fatal("payload nonce changed during master-password rotation")
	}
	if rotatedContainer.KDF.Salt == originalContainer.KDF.Salt || rotatedContainer.WrapNonce == originalContainer.WrapNonce || rotatedContainer.WrappedDEK == originalContainer.WrappedDEK {
		t.Fatal("rotation did not generate a fresh salt, wrap nonce, and DEK wrapper")
	}
	if _, err := engine.Decrypt(testPassword, rotated); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old password error = %v, want authentication failure", err)
	}
	opened, err := engine.Decrypt("new-v2-test-master-password", rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("rotated payload = %q, want %q", opened, plaintext)
	}
	wipe(opened)
}

func TestChangeMasterPasswordRejectsUnauthenticatedSource(t *testing.T) {
	engine := testEngine(t)
	original, err := engine.Encrypt(testPassword, []byte("synthetic payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ChangeMasterPassword(original, "wrong-v2-test-master-password", "new-v2-test-master-password"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong current password error = %v, want authentication failure", err)
	}
	container := decodeTestContainer(t, original)
	ciphertext, _ := base64.StdEncoding.DecodeString(container.Ciphertext)
	ciphertext[len(ciphertext)-1] ^= 1
	container.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	if _, err := engine.ChangeMasterPassword(marshalTestContainer(t, container), testPassword, "new-v2-test-master-password"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered source error = %v, want authentication failure", err)
	}
}

func TestAlgorithmSpecificNoncePolicyIsUsed(t *testing.T) {
	algorithm := testMGMNonceAlgorithm{policy: RFC9058MGMNoncePolicy{BlockSize: 16}}
	engine, err := NewEngine(Options{
		KDF:         KDFConfig{Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1},
		AlgorithmID: algorithm.ID(),
	}, algorithm)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := engine.Encrypt(testPassword, []byte("algorithm-specific nonce test"))
	if err != nil {
		t.Fatal(err)
	}
	container := decodeTestContainer(t, serialized)
	for label, encoded := range map[string]string{"wrap": container.WrapNonce, "payload": container.Nonce} {
		nonce, _ := base64.StdEncoding.DecodeString(encoded)
		if len(nonce) != 16 || nonce[0]&0x80 != 0 {
			t.Fatalf("%s nonce does not satisfy test MGM policy: %x", label, nonce)
		}
		if err := algorithm.ValidateNonce(nonce); err != nil {
			t.Fatalf("generated %s nonce rejected: %v", label, err)
		}
	}
	if _, err := engine.Decrypt(testPassword, serialized); err != nil {
		t.Fatalf("decrypt with algorithm-specific nonce: %v", err)
	}
	if err := algorithm.ValidateNonce(append([]byte{0x80}, make([]byte, 15)...)); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("nonce with MGM high bit set error = %v", err)
	}
	if err := algorithm.ValidateNonce(make([]byte, 15)); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("wrong-length MGM nonce error = %v", err)
	}
}

func TestRFC9058MGMNoncePolicyGenerationAndValidation(t *testing.T) {
	policy := RFC9058MGMNoncePolicy{BlockSize: 16}
	nonce, err := policy.GenerateNonce(bytes.NewReader(bytes.Repeat([]byte{0xff}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 16 || nonce[0] != 0x7f {
		t.Fatalf("generated MGM nonce has invalid shape: %x", nonce)
	}
	if err := policy.ValidateNonce(nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.GenerateNonce(bytes.NewReader([]byte{1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short random source error = %v", err)
	}

	for _, test := range []struct {
		name  string
		first byte
		valid bool
	}{
		{name: "lowest allowed", first: 0x00, valid: true},
		{name: "highest allowed", first: 0x7f, valid: true},
		{name: "lowest forbidden", first: 0x80, valid: false},
		{name: "highest forbidden", first: 0xff, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundaryNonce := make([]byte, 16)
			boundaryNonce[0] = test.first
			err := policy.ValidateNonce(boundaryNonce)
			if test.valid && err != nil {
				t.Fatalf("expected nonce to be valid, got %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidParameters) {
				t.Fatalf("expected high-bit nonce rejection, got %v", err)
			}
		})
	}
}

func TestTamperedVersionAlgorithmSaltAndKDFParameters(t *testing.T) {
	engine := testEngine(t)
	serialized, err := engine.Encrypt(testPassword, []byte("metadata-bound payload"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*Container)
		want error
	}{
		{"version", func(c *Container) { c.Version++ }, ErrUnsupportedFormat},
		{"algorithm", func(c *Container) { c.AEAD = "future-aead" }, ErrUnsupportedAlgorithm},
		{"kdf-id", func(c *Container) { c.KDF.ID = "future-kdf" }, ErrUnsupportedFormat},
		{"salt", func(c *Container) {
			salt, _ := base64.StdEncoding.DecodeString(c.KDF.Salt)
			salt[0] ^= 1
			c.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
		}, ErrAuthentication},
		{"kdf-time", func(c *Container) { c.KDF.Time++ }, ErrAuthentication},
		{"wrap-nonce", func(c *Container) {
			nonce, _ := base64.StdEncoding.DecodeString(c.WrapNonce)
			nonce[0] ^= 1
			c.WrapNonce = base64.StdEncoding.EncodeToString(nonce)
		}, ErrAuthentication},
		{"payload-nonce", func(c *Container) {
			nonce, _ := base64.StdEncoding.DecodeString(c.Nonce)
			nonce[0] ^= 1
			c.Nonce = base64.StdEncoding.EncodeToString(nonce)
		}, ErrAuthentication},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			container := decodeTestContainer(t, serialized)
			test.edit(&container)
			if _, err := engine.Decrypt(testPassword, marshalTestContainer(t, container)); !errors.Is(err, test.want) {
				t.Fatalf("Decrypt error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestMalformedNonceAndWrappedDEKLengthsRejectedBeforeKDF(t *testing.T) {
	engine := testEngine(t)
	serialized, err := engine.Encrypt(testPassword, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*Container)
	}{
		{"wrap nonce", func(c *Container) { c.WrapNonce = base64.StdEncoding.EncodeToString([]byte("short")) }},
		{"payload nonce", func(c *Container) { c.Nonce = base64.StdEncoding.EncodeToString([]byte("short")) }},
		{"wrapped DEK", func(c *Container) { c.WrappedDEK = base64.StdEncoding.EncodeToString(make([]byte, DEKSize-1)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			container := decodeTestContainer(t, serialized)
			test.edit(&container)
			if _, err := engine.Decrypt(testPassword, marshalTestContainer(t, container)); !errors.Is(err, ErrInvalidContainer) {
				t.Fatalf("Decrypt error = %v, want invalid container", err)
			}
		})
	}
	if _, err := sealAEAD(AES256GCM{}, make([]byte, DEKSize-1), make([]byte, 12), nil, nil); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("wrong DEK size error = %v, want invalid parameters", err)
	}
	if _, err := sealAEAD(AES256GCM{}, make([]byte, DEKSize), make([]byte, 11), nil, nil); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("wrong nonce size error = %v, want invalid parameters", err)
	}
}

func TestKDFBoundsAndContainerSizeLimits(t *testing.T) {
	if _, err := NewEngine(Options{KDF: KDFConfig{Time: MaxArgonTime + 1, MemoryKiB: MinArgonMemoryKiB, Threads: 1}}); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("unbounded time config error = %v", err)
	}
	if _, err := NewEngine(Options{KDF: KDFConfig{Time: MinArgonTime, MemoryKiB: MaxArgonMemoryKiB + 1, Threads: 1}}); !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("unbounded memory config error = %v", err)
	}
	engine := testEngine(t)
	if _, err := engine.Decrypt(testPassword, make([]byte, MaxContainerSize+1)); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("oversized serialized input error = %v", err)
	}
	if _, err := engine.Encrypt(testPassword, make([]byte, MaxPlaintextSize+1)); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("oversized plaintext error = %v", err)
	}
}

func TestRandomSourceFailureIsReturned(t *testing.T) {
	engine, err := NewEngine(Options{
		Random: failingReader{},
		KDF:    KDFConfig{Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Encrypt(testPassword, []byte("secret")); err == nil || !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "secure random generation failed") {
		t.Fatalf("random source error = %v", err)
	}
}

func TestUnsupportedFormatsAndNonCanonicalJSONAreRejected(t *testing.T) {
	engine := testEngine(t)
	serialized, err := engine.Encrypt(testPassword, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	unsupported := Container{
		Format: "passwordsaver-v3", Version: 3, AEAD: AEADAES256GCM,
		KDF:        KDFMetadata{ID: KDFArgon2id, Version: Argon2idVersion, Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1, Salt: base64.StdEncoding.EncodeToString(make([]byte, SaltSize))},
		WrapNonce:  base64.StdEncoding.EncodeToString(make([]byte, 12)),
		WrappedDEK: base64.StdEncoding.EncodeToString(make([]byte, DEKSize+16)),
		Nonce:      base64.StdEncoding.EncodeToString(make([]byte, 12)),
		Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, 16)),
	}
	if _, err := engine.Decrypt(testPassword, marshalTestContainer(t, unsupported)); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("unsupported format error = %v", err)
	}
	if _, err := engine.Decrypt(testPassword, append([]byte(" "), serialized...)); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("noncanonical JSON error = %v", err)
	}
	if _, err := engine.Decrypt(testPassword, []byte(`{"format":"passwordsaver-v2","version":2,"unknown":true}`)); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("unknown JSON member error = %v", err)
	}
}

func FuzzParseContainer(f *testing.F) {
	f.Add([]byte(`{"format":"passwordsaver-v2","version":2,"aead":"aes-256-gcm","kdf":{"id":"argon2id","version":19,"time":2,"memoryKiB":19456,"threads":1,"salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"wrapNonce":"AAAAAAAAAAAAAAAA","wrappedDEK":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseContainer(data)
	})
}

func decodeTestContainer(t *testing.T, serialized []byte) Container {
	t.Helper()
	var container Container
	if err := json.Unmarshal(serialized, &container); err != nil {
		t.Fatal(err)
	}
	return container
}

func marshalTestContainer(t *testing.T, container Container) []byte {
	t.Helper()
	serialized, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type testMGMNonceAlgorithm struct{ policy RFC9058MGMNoncePolicy }

func (a testMGMNonceAlgorithm) ID() string     { return "test-mgm-nonce-policy" }
func (a testMGMNonceAlgorithm) KeySize() int   { return DEKSize }
func (a testMGMNonceAlgorithm) NonceSize() int { return a.policy.BlockSize }
func (a testMGMNonceAlgorithm) TagSize() int   { return 16 }
func (a testMGMNonceAlgorithm) GenerateNonce(random io.Reader) ([]byte, error) {
	return a.policy.GenerateNonce(random)
}
func (a testMGMNonceAlgorithm) ValidateNonce(nonce []byte) error {
	return a.policy.ValidateNonce(nonce)
}
func (a testMGMNonceAlgorithm) New(key []byte) (cipher.AEAD, error) {
	if len(key) != DEKSize {
		return nil, ErrInvalidParameters
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, a.policy.BlockSize)
}
