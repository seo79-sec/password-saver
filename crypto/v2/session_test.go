package cryptov2

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
)

func TestSessionUnlockAndEncryptPreservesDEKWrapper(t *testing.T) {
	engine, err := NewEngine(Options{KDF: KDFConfig{Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	original, err := engine.Encrypt(testPassword, []byte("before session save"))
	if err != nil {
		t.Fatal(err)
	}
	originalContainer := decodeTestContainer(t, original)
	session, plaintext, err := engine.Unlock(testPassword, original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte("before session save")) {
		t.Fatalf("unlock plaintext = %q", plaintext)
	}
	wipe(plaintext)
	updated, err := session.Encrypt([]byte("after session save"))
	if err != nil {
		t.Fatal(err)
	}
	updatedContainer := decodeTestContainer(t, updated)
	if updatedContainer.KDF != originalContainer.KDF || updatedContainer.WrapNonce != originalContainer.WrapNonce || updatedContainer.WrappedDEK != originalContainer.WrappedDEK {
		t.Fatal("session save changed the DEK wrapper")
	}
	if updatedContainer.Nonce == originalContainer.Nonce || updatedContainer.Ciphertext == originalContainer.Ciphertext {
		t.Fatal("session save reused the payload nonce or ciphertext")
	}
	opened, err := engine.Decrypt(testPassword, updated)
	if err != nil || !bytes.Equal(opened, []byte("after session save")) {
		t.Fatalf("updated container open = (%q, %v)", opened, err)
	}
	wipe(opened)
	session.Close()
	if !session.IsClosed() {
		t.Fatal("session did not close")
	}
	if _, err := session.Encrypt([]byte("after logout")); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("closed session encrypt error = %v", err)
	}
}

func TestSessionBurnsNonceOnRepeatedRandomOutput(t *testing.T) {
	// Supply predictable distinct nonce blocks: salt, DEK, wrap nonce, initial
	// payload nonce, then a repeated initial payload nonce, followed by fresh.
	seed := bytes.NewBuffer(make([]byte, SaltSize+DEKSize+12))
	seed.Write(bytes.Repeat([]byte{0x33}, 12))
	engine, err := NewEngine(Options{Random: seed, KDF: KDFConfig{Time: MinArgonTime, MemoryKiB: MinArgonMemoryKiB, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := engine.Encrypt(testPassword, []byte("seed"))
	if err != nil {
		t.Fatal(err)
	}
	session, plaintext, err := engine.Unlock(testPassword, serialized)
	if err != nil {
		t.Fatal(err)
	}
	wipe(plaintext)
	seed.Write(bytes.Repeat([]byte{0x33}, 12)) // collision with the original payload nonce
	seed.Write(bytes.Repeat([]byte{0x44}, 12)) // accepted replacement nonce
	updated, err := session.Encrypt([]byte("unique nonce"))
	if err != nil {
		t.Fatal(err)
	}
	before := decodeTestContainer(t, serialized)
	after := decodeTestContainer(t, updated)
	if before.Nonce == after.Nonce {
		t.Fatal("session reused an already used nonce")
	}
	oldNonce, _ := base64.StdEncoding.DecodeString(before.Nonce)
	newNonce, _ := base64.StdEncoding.DecodeString(after.Nonce)
	if bytes.Equal(oldNonce, newNonce) {
		t.Fatal("decoded nonce was reused")
	}
	session.Close()
}

func TestSessionConcurrentSavesAndClose(t *testing.T) {
	engine := testEngine(t)
	serialized, err := engine.Encrypt(testPassword, []byte("concurrent initial"))
	if err != nil {
		t.Fatal(err)
	}
	session, plaintext, err := engine.Unlock(testPassword, serialized)
	if err != nil {
		t.Fatal(err)
	}
	wipe(plaintext)
	const writers = 12
	outputs := make(chan []byte, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			output, err := session.Encrypt([]byte{byte(n)})
			if err == nil {
				outputs <- output
			}
		}(i)
	}
	wg.Wait()
	close(outputs)
	seen := map[string]struct{}{}
	for output := range outputs {
		container := decodeTestContainer(t, output)
		if _, exists := seen[container.Nonce]; exists {
			t.Fatal("concurrent session saves reused a nonce")
		}
		seen[container.Nonce] = struct{}{}
	}
	if len(seen) != writers {
		t.Fatalf("successful session saves = %d, want %d", len(seen), writers)
	}
	session.Close()
	if _, err := session.Encrypt([]byte("closed")); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("post-close encrypt error = %v", err)
	}
}
