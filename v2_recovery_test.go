package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func corruptV2Primary(t *testing.T) []byte {
	t.Helper()
	primary, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), primary...)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(dataFileV2, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	return corrupt
}

func pendingV2RecoverySession(app *App) *v2VaultSession {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.pendingV2Recover.session
}

func TestV2BackupRecoveryIsExplicitAndPreservesTheDamagedPrimary(t *testing.T) {
	want := syntheticMigrationVault()
	app, _ := activatedV2App(t, want)
	app.Logout()
	corrupt := corruptV2Primary(t)
	backupBefore, err := os.ReadFile(dataFileV2 + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !app.GetVaultStatus().V2BackupPresent {
		t.Fatal("active v2 status did not expose backup availability")
	}
	if _, err := app.PrepareV2VaultRecovery("incorrect synthetic password"); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("incorrect password error = %v", err)
	}
	token, err := app.PrepareV2VaultRecovery(migrationTestPassword)
	if err != nil || token == "" {
		t.Fatalf("prepare = (%q, %v)", token, err)
	}
	primaryAfterPrepare, _ := os.ReadFile(dataFileV2)
	backupAfterPrepare, _ := os.ReadFile(dataFileV2 + ".bak")
	if !bytes.Equal(primaryAfterPrepare, corrupt) || !bytes.Equal(backupAfterPrepare, backupBefore) {
		t.Fatal("preparation modified the primary or backup")
	}
	requiresTOTP, err := app.ConfirmV2VaultRecovery(token)
	if err != nil || !requiresTOTP {
		t.Fatalf("confirm = (%v, %v), want TOTP", requiresTOTP, err)
	}
	if status := app.GetVaultStatus(); status.State != VaultStateV2Active || !status.V2ContainerPresent {
		t.Fatalf("recovery changed the active format: %+v", status)
	}
	primaryAfter, err := os.ReadFile(dataFileV2)
	if err != nil || !bytes.Equal(primaryAfter, backupBefore) {
		t.Fatalf("restored primary differs from verified backup: %v", err)
	}
	backupAfter, err := os.ReadFile(dataFileV2 + ".bak")
	if err != nil || !bytes.Equal(backupAfter, backupBefore) {
		t.Fatalf("backup changed during recovery: %v", err)
	}
	archives, err := filepath.Glob(dataFileV2 + ".corrupt-*")
	if err != nil || len(archives) != 1 {
		t.Fatalf("diagnostic archive paths = %v, %v", archives, err)
	}
	archived, err := os.ReadFile(archives[0])
	if err != nil || !bytes.Equal(archived, corrupt) {
		t.Fatalf("damaged primary was not preserved: %v", err)
	}
	if err := app.Verify2FA(currentCode(t, want.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	accounts, err := app.GetAccounts()
	if err != nil || !reflectVaultEqual(&Vault{Accounts: accounts, TwoFAEnabled: want.TwoFAEnabled, TwoFASecret: want.TwoFASecret}, want) {
		t.Fatalf("restored vault mismatch: %v", err)
	}
	app.Logout()
}

func TestV2BackupRecoverySupportsMissingPrimaryAndRejectsStaleBackup(t *testing.T) {
	t.Run("valid primary is never rolled back", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		primaryBefore, _ := os.ReadFile(dataFileV2)
		if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
			t.Fatal("recovery was prepared while the primary still authenticated")
		}
		primaryAfter, _ := os.ReadFile(dataFileV2)
		if !bytes.Equal(primaryAfter, primaryBefore) {
			t.Fatal("refused recovery changed a valid primary")
		}
	})

	t.Run("authenticated but invalid vault payload", func(t *testing.T) {
		app, engine := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		invalidVault, err := engine.Encrypt(migrationTestPassword, []byte("authenticated but not vault JSON"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataFileV2, invalidVault, 0600); err != nil {
			t.Fatal(err)
		}
		token, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatalf("prepare rejected invalid decrypted Vault data: %v", err)
		}
		if _, err := app.ConfirmV2VaultRecovery(token); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword); err != nil {
			t.Fatalf("backup recovery did not repair the primary: %v", err)
		}
		app.Logout()
	})

	t.Run("missing primary after restart", func(t *testing.T) {
		app, engine := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		if err := os.Remove(dataFileV2); err != nil {
			t.Fatal(err)
		}
		restarted := NewApp()
		restarted.v2Engine = engine
		if status := restarted.GetVaultStatus(); status.State != VaultStateV2Active || status.V2ContainerPresent || !status.V2BackupPresent {
			t.Fatalf("status after primary loss = %+v", status)
		}
		token, err := restarted.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.ConfirmV2VaultRecovery(token); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword); err != nil {
			t.Fatalf("restored primary did not open after restart: %v", err)
		}
		restarted.Logout()
	})

	t.Run("backup changed after preparation", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corruptV2Primary(t)
		token, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataFileV2+".bak", []byte("changed after verification"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := app.ConfirmV2VaultRecovery(token); err == nil {
			t.Fatal("recovery accepted a backup changed after verification")
		}
		if _, err := os.Stat(dataFileV2); err != nil {
			t.Fatalf("failed recovery removed damaged primary: %v", err)
		}
		if !app.IsLocked() {
			t.Fatal("failed recovery unlocked the app")
		}
	})

	t.Run("replacement failure preserves primary", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corrupt := corruptV2Primary(t)
		token, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		oldReplace := replaceVaultFile
		replaceVaultFile = func(source, destination string) error {
			if destination == dataFileV2 {
				return errors.New("injected v2 recovery replacement failure")
			}
			return oldReplace(source, destination)
		}
		defer func() { replaceVaultFile = oldReplace }()
		if _, err := app.ConfirmV2VaultRecovery(token); err == nil {
			t.Fatal("injected replacement failure was ignored")
		}
		primaryAfter, err := os.ReadFile(dataFileV2)
		if err != nil || !bytes.Equal(primaryAfter, corrupt) {
			t.Fatalf("replacement failure changed the primary: %v", err)
		}
		if !app.IsLocked() {
			t.Fatal("replacement failure unlocked the app")
		}
	})
}

func TestV2RecoveryCancelAndExpiryClosePendingKey(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corruptV2Primary(t)
		token, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		pending := pendingV2RecoverySession(app)
		app.CancelV2VaultRecovery(token)
		if pendingV2RecoverySession(app) != nil || pending == nil || !pending.isClosed() {
			t.Fatal("cancel did not clear and close the pending v2 session")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		oldLifetime := recoveryChallengeLifetime
		recoveryChallengeLifetime = 20 * time.Millisecond
		defer func() { recoveryChallengeLifetime = oldLifetime }()
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corruptV2Primary(t)
		if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err != nil {
			t.Fatal(err)
		}
		pending := pendingV2RecoverySession(app)
		deadline := time.Now().Add(time.Second)
		for pendingV2RecoverySession(app) != nil && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if pendingV2RecoverySession(app) != nil || pending == nil || !pending.isClosed() {
			t.Fatal("expiry did not clear and close the pending v2 session")
		}
	})
}
