package main

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	cryptov2 "password-saver/crypto/v2"
)

func TestV3ReplicaKeyRequiresFullV2Unlock(t *testing.T) {
	app, _, vault := passwordChangeFixture(t, true)
	id := [16]byte{1}
	var key [cryptov2.ReplicaKeySize]byte
	rand.Read(key[:])
	defer clear(key[:])
	wrapped, err := app.wrapReplicaKey(id, key)
	if err != nil {
		t.Fatal(err)
	}
	assertLocked := func() {
		t.Helper()
		if got, err := app.openReplicaKey(id, wrapped); !errors.Is(err, ErrVaultSessionClosed) || got != ([cryptov2.ReplicaKeySize]byte{}) {
			t.Fatalf("opening without full unlock: %v", err)
		}
		if got, err := app.wrapReplicaKey(id, key); !errors.Is(err, ErrVaultSessionClosed) || got != nil {
			t.Fatalf("wrapping without full unlock: %v", err)
		}
	}
	app.Logout()
	assertLocked()
	if _, err := app.LoginV2("wrong synthetic password"); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("wrong password: %v", err)
	}
	assertLocked()
	if needsTOTP, err := app.LoginV2(migrationTestPassword); err != nil || !needsTOTP {
		t.Fatalf("password step: (%v, %v)", needsTOTP, err)
	}
	assertLocked()
	if err := app.Verify2FA("invalid-code"); err == nil {
		t.Fatal("invalid TOTP accepted")
	}
	assertLocked()
	if err := app.Verify2FA(currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	got, err := app.openReplicaKey(id, wrapped)
	defer clear(got[:])
	if err != nil || got != key {
		t.Fatalf("opening after login: %v", err)
	}
	app.mu.Lock()
	app.lastActivity = time.Now().Add(-2 * app.idleTimeout)
	app.mu.Unlock()
	assertLocked()
}

func TestV3ReplicaKeyPasswordChangeAndDEKRotation(t *testing.T) {
	app, _, vault := passwordChangeFixture(t, false)
	id := [16]byte{1}
	var key [cryptov2.ReplicaKeySize]byte
	rand.Read(key[:])
	defer clear(key[:])
	wrapped, err := app.wrapReplicaKey(id, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := app.LoginV2(migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("old password after change: %v", err)
	}
	loginForPasswordChange(t, app, rotatedTestPassword, vault)
	got, err := app.openReplicaKey(id, wrapped)
	defer clear(got[:])
	if err != nil || got != key {
		t.Fatalf("opening after known password change: %v", err)
	}
	if _, err := app.CreateRecoveryKey(rotatedTestPassword, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := app.openReplicaKey(id, wrapped); !errors.Is(err, cryptov2.ErrAuthentication) || got != ([cryptov2.ReplicaKeySize]byte{}) {
		t.Fatalf("old wrapper after DEK rotation: %v", err)
	}
}
