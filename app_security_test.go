package main

import (
	"testing"
	"time"
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
