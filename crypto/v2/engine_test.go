package cryptov2

import (
	"bytes"
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
