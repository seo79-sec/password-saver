package main

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"password-saver/crypto"
)

const recoveryTestPassword = "recovery fixture password"

func makeRecoverableVault(t *testing.T) (*App, string, []byte) {
	t.Helper()
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager(recoveryTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	want := &Vault{Accounts: []Account{{ID: "recovery-fixture", Password: "kept"}}}
	if err := SaveVault(cm, want); err != nil {
		t.Fatal(err)
	}
	cm.Wipe()
	backup, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile+".bak", backup, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("damaged primary"), 0600); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	token, err := app.PrepareVaultRecovery(recoveryTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	return app, token, backup
}

func pendingRecoveryManager(app *App) *crypto.CryptoManager {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.pendingRecover.cm
}

func TestRecoveryValidatesAndWritesTheSameBackupBytes(t *testing.T) {
	app, token, checkedBytes := makeRecoverableVault(t)
	originalReader := recoveryBackupReader
	defer func() { recoveryBackupReader = originalReader }()
	changed := false
	recoveryBackupReader = func(path string) ([]byte, error) {
		data, err := readVaultFile(path)
		if err == nil && !changed {
			changed = true
			if writeErr := os.WriteFile(path, []byte("replaced after read"), 0600); writeErr != nil {
				return nil, writeErr
			}
		}
		return data, err
	}
	if _, err := app.ConfirmVaultRecovery(token); err != nil {
		t.Fatal(err)
	}
	primary, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(primary, checkedBytes) {
		t.Fatal("restored primary differs from bytes verified before replacement")
	}
	loaded, err := LoadVault(app.cm)
	if err != nil || len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "recovery-fixture" {
		t.Fatalf("restored primary failed to load: %v", err)
	}
}

func TestRecoveryChallengeClearsManagerOnCancelAndError(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		app, token, _ := makeRecoverableVault(t)
		cm := pendingRecoveryManager(app)
		app.CancelVaultRecovery(token)
		if pendingRecoveryManager(app) != nil {
			t.Fatal("cancel left recovery challenge pending")
		}
		if _, err := cm.Encrypt("must be wiped"); err == nil {
			t.Fatal("cancel did not wipe the pending crypto manager")
		}
	})

	t.Run("error", func(t *testing.T) {
		app, token, _ := makeRecoverableVault(t)
		cm := pendingRecoveryManager(app)
		oldReader := recoveryBackupReader
		recoveryBackupReader = func(string) ([]byte, error) { return nil, errors.New("injected backup read failure") }
		defer func() { recoveryBackupReader = oldReader }()
		if _, err := app.ConfirmVaultRecovery(token); err == nil {
			t.Fatal("expected recovery read error")
		}
		if pendingRecoveryManager(app) != nil {
			t.Fatal("error left recovery challenge pending")
		}
		if _, err := cm.Encrypt("must be wiped"); err == nil {
			t.Fatal("error did not wipe the pending crypto manager")
		}
	})
}

func TestRecoveryChallengeExpiresAndWipesManager(t *testing.T) {
	oldLifetime := recoveryChallengeLifetime
	recoveryChallengeLifetime = 20 * time.Millisecond
	defer func() { recoveryChallengeLifetime = oldLifetime }()
	app, _, _ := makeRecoverableVault(t)
	cm := pendingRecoveryManager(app)
	deadline := time.Now().Add(time.Second)
	for pendingRecoveryManager(app) != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pendingRecoveryManager(app) != nil {
		t.Fatal("expired challenge remained pending")
	}
	if _, err := cm.Encrypt("must be wiped"); err == nil {
		t.Fatal("expiry did not wipe the pending crypto manager")
	}
}

func TestRecoveryDoesNotWipeKeyUntilRestoreCompletes(t *testing.T) {
	app, token, _ := makeRecoverableVault(t)
	cm := pendingRecoveryManager(app)
	oldReplace := replaceVaultFile
	entered, release := make(chan struct{}), make(chan struct{})
	replaceVaultFile = func(source, destination string) error {
		if destination == dataFile {
			close(entered)
			<-release
		}
		return oldReplace(source, destination)
	}
	defer func() { replaceVaultFile = oldReplace }()
	done := make(chan error, 1)
	go func() { _, err := app.ConfirmVaultRecovery(token); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not reach atomic replacement")
	}
	if _, err := cm.Encrypt("key is still in use"); err != nil {
		t.Fatalf("manager wiped before operation completed: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not complete")
	}
	if pendingRecoveryManager(app) != nil {
		t.Fatal("completed recovery left a pending manager")
	}
	if app.cm != cm {
		t.Fatal("recovery manager was not transferred to the active session")
	}
	if _, err := app.cm.Encrypt("active session"); err != nil {
		t.Fatalf("transferred manager was wiped: %v", err)
	}
}
