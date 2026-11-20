package cryptov2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"
)

func TestRecoveryKeyReadsOriginalV2Fixture(t *testing.T) {
	original, err := os.ReadFile("testdata/v2-original.enc")
	if err != nil {
		t.Fatal(err)
	}
	engine := testEngine(t)
	session, plaintext, err := engine.Unlock(testPassword, original)
	if err != nil || !bytes.Equal(plaintext, []byte(`{"accounts":[]}`)) || session.HasRecoveryKey() {
		t.Fatal("original v2 container did not open unchanged")
	}
	defer session.Close()
	_, key, err := engine.EncryptWithRecoveryKey(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.DecryptWithRecoveryKey(key, original); !errors.Is(err, ErrRecoveryKeyUnavailable) {
		t.Fatalf("original v2 recovery error = %v", err)
	}
	updated, err := session.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if c := decodeTestContainer(t, updated); c.Version != FormatVersion || c.Recovery != nil {
		t.Fatal("ordinary save silently upgraded the original envelope")
	}
}

func TestRecoveryKeyAuthenticatesBothPathsAndPersistsInSession(t *testing.T) {
	engine := testEngine(t)
	data := []byte("synthetic plaintext")
	encoded, key, err := engine.EncryptWithRecoveryKey(testPassword, data)
	if err != nil || bytes.Contains(encoded, []byte(key)) || bytes.Contains(encoded, data) {
		t.Fatal("recovery encryption failed or leaked secrets")
	}
	container := decodeTestContainer(t, encoded)
	if container.Version != RecoveryFormatVersion || container.Recovery == nil {
		t.Fatal("missing recovery slot")
	}
	session, plaintext, err := engine.Unlock(testPassword, encoded)
	if err != nil || !session.HasRecoveryKey() || !bytes.Equal(plaintext, data) {
		t.Fatal("password did not open recovery-enabled data")
	}
	defer session.Close()
	updated, err := session.Encrypt([]byte("updated synthetic payload"))
	if err != nil {
		t.Fatal(err)
	}
	const anotherPassword = "synthetic rotated password"
	rotated, err := engine.ChangeMasterPassword(updated, testPassword, anotherPassword)
	if err != nil {
		t.Fatal(err)
	}
	after := decodeTestContainer(t, rotated)
	before := decodeTestContainer(t, updated)
	if *after.Recovery != *container.Recovery || after.Ciphertext != before.Ciphertext || after.Nonce != before.Nonce {
		t.Fatal("normal save or password rewrap changed recovery or the rewrapped payload")
	}
	for _, open := range []func() ([]byte, error){
		func() ([]byte, error) { return engine.DecryptWithRecoveryKey(key, rotated) },
		func() ([]byte, error) { return engine.Decrypt(anotherPassword, rotated) },
	} {
		result, err := open()
		if err != nil || string(result) != "updated synthetic payload" {
			t.Fatal("an authenticated path did not open updated data")
		}
	}
	if _, err := engine.Decrypt(testPassword, rotated); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("previous password accepted: %v", err)
	}
}

func TestRecoveryKeyRejectsTamperingAndRandomFailure(t *testing.T) {
	engine := testEngine(t)
	data := []byte("synthetic plaintext")
	encoded, key, err := engine.EncryptWithRecoveryKey(testPassword, data)
	if err != nil {
		t.Fatal(err)
	}
	bitflip := func(text string) string {
		data, _ := base64.StdEncoding.DecodeString(text)
		data[len(data)-1] ^= 1
		return base64.StdEncoding.EncodeToString(data)
	}
	for _, test := range []struct {
		name                     string
		modify                   func(*Container)
		passwordErr, recoveryErr error
	}{
		{"slot removed", func(c *Container) { c.Recovery = nil }, ErrUnsupportedFormat, ErrUnsupportedFormat},
		{"version downgrade", func(c *Container) { c.Version, c.Recovery = FormatVersion, nil }, ErrAuthentication, ErrRecoveryKeyUnavailable},
		{"slot version", func(c *Container) { c.Recovery.Version++ }, ErrUnsupportedFormat, ErrUnsupportedFormat},
		{"slot salt", func(c *Container) { c.Recovery.Salt = bitflip(c.Recovery.Salt) }, ErrAuthentication, ErrRecoveryKeyInvalid},
		{"slot nonce", func(c *Container) { c.Recovery.Nonce = bitflip(c.Recovery.Nonce) }, ErrAuthentication, ErrRecoveryKeyInvalid},
		{"wrapped key", func(c *Container) { c.Recovery.WrappedDEK = bitflip(c.Recovery.WrappedDEK) }, ErrAuthentication, ErrRecoveryKeyInvalid},
		{"payload tag", func(c *Container) { c.Ciphertext = bitflip(c.Ciphertext) }, ErrAuthentication, ErrRecoveryPayload},
	} {
		t.Run(test.name, func(t *testing.T) {
			container := decodeTestContainer(t, encoded)
			test.modify(&container)
			changed := marshalTestContainer(t, container)
			if _, err := engine.Decrypt(testPassword, changed); !errors.Is(err, test.passwordErr) {
				t.Fatalf("password error = %v", err)
			}
			if _, err := engine.DecryptWithRecoveryKey(key, changed); !errors.Is(err, test.recoveryErr) {
				t.Fatalf("recovery error = %v", err)
			}
		})
	}
	if _, err := engine.DecryptWithRecoveryKey("PSRK1-"+base64.RawURLEncoding.EncodeToString(make([]byte, DEKSize)), encoded); !errors.Is(err, ErrRecoveryKeyInvalid) {
		t.Fatalf("incorrect recovery key error = %v", err)
	}
	// Fail at key generation and at the subsequent recovery-slot salt.
	for _, n := range []int{0, DEKSize + SaltSize + DEKSize + 24} {
		e, err := NewEngine(Options{KDF: engine.kdf, Random: bytes.NewReader(make([]byte, n))})
		if err != nil {
			t.Fatal(err)
		}
		if result, key, err := e.EncryptWithRecoveryKey(testPassword, data); !errors.Is(err, io.EOF) || result != nil || key != "" {
			t.Fatal("randomness failure returned a key or container")
		}
	}
}

func TestRecoveryKeySecurityTransitionsReplaceThePayloadKey(t *testing.T) {
	engine := testEngine(t)
	plaintext := []byte("synthetic payload")
	old, _, err := engine.EncryptWithRecoveryKey(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := engine.openContainer(testPassword, old)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(opened.dek)
	defer wipe(opened.plaintext)
	replaced, _, err := engine.EncryptWithRecoveryKey(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := engine.Encrypt(testPassword, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][]byte{replaced, disabled} {
		validated, err := engine.validateContainer(replacement)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validated.openPayload(opened.dek); !errors.Is(err, ErrAuthentication) {
			t.Fatal("the old DEK can read a later security revision")
		}
	}
}
