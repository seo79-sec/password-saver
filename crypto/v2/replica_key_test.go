package cryptov2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestReplicaKeyWrapAuthenticatesVersionAndIdentity(t *testing.T) {
	engine := testEngine(t)
	container, err := engine.Encrypt(testPassword, []byte("synthetic vault"))
	if err != nil {
		t.Fatal(err)
	}
	session, plaintext, err := engine.Unlock(testPassword, container)
	wipe(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	id := [16]byte{1}
	var key [ReplicaKeySize]byte
	rand.Read(key[:])
	defer clear(key[:])
	wrapped, err := session.WrapReplicaKey(id, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.WrapReplicaKey(id, key)
	if err != nil || bytes.Equal(wrapped[1:replicaKeyHeaderSize], second[1:replicaKeyHeaderSize]) {
		t.Fatalf("wrapping did not use a fresh salt: %v", err)
	}
	got, err := session.OpenReplicaKey(id, wrapped)
	defer clear(got[:])
	if err != nil || got != key {
		t.Fatalf("key round trip failed: %v", err)
	}

	version := bytes.Clone(wrapped)
	version[0]++
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name    string
		id      [16]byte
		wrapped []byte
		want    error
	}{
		{"version", id, version, ErrInvalidReplicaKeyWrap},
		{"short", id, wrapped[:len(wrapped)-1], ErrInvalidReplicaKeyWrap},
		{"long", id, append(bytes.Clone(wrapped), 0), ErrInvalidReplicaKeyWrap},
		{"tampered", id, tampered, ErrAuthentication},
		{"other replica", [16]byte{2}, wrapped, ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := session.OpenReplicaKey(tc.id, tc.wrapped); !errors.Is(err, tc.want) || got != ([ReplicaKeySize]byte{}) {
				t.Fatalf("opening wrapper: got %v, want %v and a zero key", err, tc.want)
			}
		})
	}
	session.Close()
	if _, err := session.OpenReplicaKey(id, wrapped); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("opening after close: %v", err)
	}
	if _, err := session.WrapReplicaKey(id, key); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("wrapping after close: %v", err)
	}
}
