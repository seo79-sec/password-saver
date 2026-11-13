package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestSetIdleTimeoutAcceptsSupportedValues(t *testing.T) {
	a := NewApp()
	for _, minutes := range []int{1, 5, 10, 15} {
		if err := a.SetIdleTimeout(minutes); err != nil {
			t.Fatalf("SetIdleTimeout(%d): %v", minutes, err)
		}
		if got := a.idleTimeout; got != time.Duration(minutes)*time.Minute {
			t.Fatalf("timeout=%v, want %d minutes", got, minutes)
		}
	}
	for _, minutes := range []int{0, 2, 30} {
		if err := a.SetIdleTimeout(minutes); err == nil {
			t.Fatalf("SetIdleTimeout(%d) unexpectedly succeeded", minutes)
		}
	}
}

func TestTOTPAttemptLimitBlocksAndExpires(t *testing.T) {
	a := NewApp()
	for i := 0; i < maxTOTPFailures; i++ {
		a.recordTOTPFailureLocked()
	}
	if a.totpBlockedUntil.IsZero() {
		t.Fatal("threshold did not start lockout")
	}
	if err := a.checkTOTPAttemptsLocked(); err == nil {
		t.Fatal("attempt was accepted during lockout")
	}
	a.totpBlockedUntil = time.Now().Add(-time.Second)
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		t.Fatalf("expired lockout remains active: %v", err)
	}
}

func TestBackendIdleDeadlineLocksSession(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	if _, err := a.Login("test-only master password"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.lastActivity = time.Now().Add(-2 * a.idleTimeout)
	a.mu.Unlock()
	if !a.CheckInactivity() || !a.IsLocked() {
		t.Fatal("backend inactivity deadline did not lock the session")
	}
	if a.cm != nil || a.vault != nil {
		t.Fatal("idle lock retained session state")
	}
}

func TestTOTPCanBeRetriedAfterAnIncorrectCode(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	password := "test-only master password"
	if _, err := a.Login(password); err != nil {
		t.Fatal(err)
	}
	setup, err := a.Generate2FA()
	if err != nil {
		t.Fatal(err)
	}
	validCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wrongCode := ""
	for candidate := 0; candidate < 1_000_000; candidate++ {
		code := fmt.Sprintf("%06d", candidate)
		if !totp.Validate(code, setup.Secret) {
			wrongCode = code
			break
		}
	}
	if wrongCode == "" {
		t.Fatal("could not find a non-matching test TOTP code")
	}
	if err := a.ConfirmAndEnable2FA(setup.Secret, validCode); err != nil {
		t.Fatal(err)
	}
	a.Logout()
	requires2FA, err := a.Login(password)
	if err != nil || !requires2FA {
		t.Fatalf("Login() = (%v, %v), want 2FA required", requires2FA, err)
	}
	if err := a.Verify2FA(wrongCode); err == nil {
		t.Fatal("incorrect TOTP code was accepted")
	}
	validCode, err = totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify2FA(validCode); err != nil {
		t.Fatalf("valid TOTP retry after error failed: %v", err)
	}
	if a.IsLocked() {
		t.Fatal("valid TOTP retry did not unlock the session")
	}
	a.Logout()
}
