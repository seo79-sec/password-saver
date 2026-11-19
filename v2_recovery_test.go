package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
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
	prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
	if err != nil || prepared.Token == "" || !prepared.RequiresTOTP {
		t.Fatalf("prepare = (%+v, %v)", prepared, err)
	}
	primaryAfterPrepare, _ := os.ReadFile(dataFileV2)
	backupAfterPrepare, _ := os.ReadFile(dataFileV2 + ".bak")
	if !bytes.Equal(primaryAfterPrepare, corrupt) || !bytes.Equal(backupAfterPrepare, backupBefore) {
		t.Fatal("preparation modified the primary or backup")
	}
	if _, err := app.GetAccounts(); err == nil {
		t.Fatal("checking the backup password unlocked records before TOTP")
	}
	if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, want.TwoFASecret)); err != nil {
		t.Fatalf("confirm with TOTP: %v", err)
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
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatalf("prepare rejected invalid decrypted Vault data: %v", err)
		}
		if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err != nil {
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
		prepared, err := restarted.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err != nil {
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
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataFileV2+".bak", []byte("changed after verification"), 0600); err != nil {
			t.Fatal(err)
		}
		preserved := snapshotV2RecoveryImmutableFiles(t)
		primaryBefore, _ := os.ReadFile(dataFileV2)
		backupBefore, _ := os.ReadFile(dataFileV2 + ".bak")
		if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err == nil {
			t.Fatal("recovery accepted a backup changed after verification")
		}
		assertV2RecoveryImmutableFiles(t, preserved)
		assertFileBytes(t, dataFileV2, primaryBefore)
		assertFileBytes(t, dataFileV2+".bak", backupBefore)
		if !app.IsLocked() {
			t.Fatal("failed recovery unlocked the app")
		}
	})

	t.Run("primary changed after preparation", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corrupt := corruptV2Primary(t)
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		changed := []byte("external change after preparation")
		if err := os.WriteFile(dataFileV2, changed, 0600); err != nil {
			t.Fatal(err)
		}
		preserved := snapshotV2RecoveryImmutableFiles(t)
		primaryBefore, _ := os.ReadFile(dataFileV2)
		if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err == nil {
			t.Fatal("recovery accepted a primary changed after verification")
		}
		assertV2RecoveryImmutableFiles(t, preserved)
		assertFileBytes(t, dataFileV2, primaryBefore)
		if bytes.Equal(primaryBefore, corrupt) {
			t.Fatal("test did not change the primary after preparation")
		}
		archives, _ := filepath.Glob(dataFileV2 + ".corrupt-*")
		if len(archives) != 0 {
			t.Fatalf("stale challenge created diagnostic archive: %v", archives)
		}
	})

	t.Run("replacement failure preserves primary", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corrupt := corruptV2Primary(t)
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		oldReplace := replaceVaultFile
		replaceVaultFile = func(source, destination string) error {
			if filepath.Base(destination) == dataFileV2 {
				return errors.New("injected v2 recovery replacement failure")
			}
			return oldReplace(source, destination)
		}
		defer func() { replaceVaultFile = oldReplace }()
		if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err == nil {
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

func TestV2RecoveryRequiresTOTPBeforeWritingAndSharesLockout(t *testing.T) {
	vault := syntheticMigrationVault()
	app, _ := activatedV2App(t, vault)
	defer app.Logout()
	app.Logout()
	primary := corruptV2Primary(t)
	backup := readPasswordChangeTestFile(t, dataFileV2+".bak")
	immutable := snapshotV2RecoveryImmutableFiles(t)
	for attempt := 0; attempt < maxTOTPFailures; attempt++ {
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil || !prepared.RequiresTOTP {
			t.Fatalf("prepare attempt %d: %v", attempt, err)
		}
		pending := pendingV2RecoverySession(app)
		code := "invalid"
		if attempt == 0 {
			code = ""
		}
		if err := app.ConfirmV2VaultRecovery(prepared.Token, code); !errors.Is(err, errV2RecoveryInvalidTOTP) {
			t.Fatalf("bad TOTP attempt %d: %v", attempt, err)
		}
		if pending == nil || !pending.isClosed() || pendingV2RecoverySession(app) != nil || !app.IsLocked() {
			t.Fatal("failed factor left recovery key material or unlocked the vault")
		}
		assertV2RecoveryImmutableFiles(t, immutable)
		assertFileBytes(t, dataFileV2, primary)
		assertFileBytes(t, dataFileV2+".bak", backup)
		archives, err := filepath.Glob(dataFileV2 + ".corrupt-*")
		if err != nil || len(archives) != 0 {
			t.Fatalf("invalid TOTP created diagnostic file: %v, %v", archives, err)
		}
		app.Logout()
	}
	if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
		t.Fatal("new challenge bypassed the TOTP lockout")
	}
	if _, err := app.LoginV2(migrationTestPassword); err == nil || err.Error() != "слишком много неверных кодов 2FA; попробуйте позже" {
		t.Fatalf("recovery's lockout was not shared with login: %v", err)
	}
	app.mu.Lock()
	app.totpBlockedUntil = time.Now().Add(-time.Second)
	app.mu.Unlock()
	prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetAccounts(); err != nil {
		t.Fatalf("valid TOTP did not authorize the restored vault: %v", err)
	}
	assertFileBytes(t, dataFileV2, backup)
}

func TestV2BackupRecoveryRepairsRecognizedDamagedPrimaryBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "empty primary", edit: func([]byte) []byte { return []byte{} }},
		{name: "arbitrary damaged bytes", edit: func([]byte) []byte { return []byte("\x00not a container\xff") }},
		{name: "truncated json", edit: func([]byte) []byte { return []byte(`{"format":"passwordsaver-v2","version":2`) }},
		{name: "damaged aead tag", edit: damageV2Tag},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, _ := activatedV2App(t, syntheticMigrationVault())
			app.Logout()
			originalPrimary, err := os.ReadFile(dataFileV2)
			if err != nil {
				t.Fatal(err)
			}
			backupBefore, err := os.ReadFile(dataFileV2 + ".bak")
			if err != nil {
				t.Fatal(err)
			}
			damaged := test.edit(originalPrimary)
			if err := os.WriteFile(dataFileV2, damaged, 0600); err != nil {
				t.Fatal(err)
			}
			immutable := snapshotV2RecoveryImmutableFiles(t)
			prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
			if err != nil {
				t.Fatalf("prepare from damaged primary: %v", err)
			}
			assertV2RecoveryImmutableFiles(t, immutable)
			assertFileBytes(t, dataFileV2, damaged)
			if !prepared.RequiresTOTP {
				t.Fatal("TOTP requirement missing from authenticated backup")
			}
			if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, syntheticMigrationVault().TwoFASecret)); err != nil {
				t.Fatalf("explicit recovery with TOTP: %v", err)
			}
			assertV2RecoveryImmutableFiles(t, immutable)
			assertFileBytes(t, dataFileV2+".bak", backupBefore)
			assertFileBytes(t, dataFileV2, backupBefore)
			archives, err := filepath.Glob(dataFileV2 + ".corrupt-*")
			if err != nil || len(archives) != 1 {
				t.Fatalf("diagnostic archive paths = %v, %v", archives, err)
			}
			assertFileBytes(t, archives[0], damaged)
			app.Logout()
		})
	}
}

func TestV2RecoveryRefusesUnsupportedPrimaryWithoutChangingFiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*cryptov2.Container)
	}{
		{name: "unsupported version", mutate: func(c *cryptov2.Container) { c.Version = 3 }},
		{name: "unknown algorithm", mutate: func(c *cryptov2.Container) { c.AEAD = "future-aead" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, _ := activatedV2App(t, syntheticMigrationVault())
			app.Logout()
			original, err := os.ReadFile(dataFileV2)
			if err != nil {
				t.Fatal(err)
			}
			var container cryptov2.Container
			if err := json.Unmarshal(original, &container); err != nil {
				t.Fatal(err)
			}
			test.mutate(&container)
			unsupported, err := json.Marshal(container)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dataFileV2, unsupported, 0600); err != nil {
				t.Fatal(err)
			}
			immutable := snapshotV2RecoveryImmutableFiles(t)
			primaryBefore, _ := os.ReadFile(dataFileV2)
			if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); !errors.Is(err, ErrVaultUnsupportedFormat) {
				t.Fatalf("unsupported container error = %v", err)
			}
			assertV2RecoveryImmutableFiles(t, immutable)
			assertFileBytes(t, dataFileV2, primaryBefore)
			assertNoCorruptArchive(t)
		})
	}

	t.Run("truncated header declares future version", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		future := []byte(`{"format":"passwordsaver-v2","version":9,`)
		if err := os.WriteFile(dataFileV2, future, 0600); err != nil {
			t.Fatal(err)
		}
		immutable := snapshotV2RecoveryImmutableFiles(t)
		if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); !errors.Is(err, ErrVaultUnsupportedFormat) {
			t.Fatalf("truncated unsupported header error = %v", err)
		}
		assertV2RecoveryImmutableFiles(t, immutable)
		assertFileBytes(t, dataFileV2, future)
		assertNoCorruptArchive(t)
	})
}

func TestV2RecoveryRejectsValidPrimaryWithoutChangingFiles(t *testing.T) {
	app, _ := activatedV2App(t, syntheticMigrationVault())
	app.Logout()
	immutable := snapshotV2RecoveryImmutableFiles(t)
	primary, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
		t.Fatal("recovery was prepared while the primary still authenticated")
	}
	assertV2RecoveryImmutableFiles(t, immutable)
	assertFileBytes(t, dataFileV2, primary)
	assertNoCorruptArchive(t)
}

func TestV2RecoveryCannotOverlaySessionWaitingForTOTP(t *testing.T) {
	app, _ := activatedV2App(t, syntheticMigrationVault())
	app.Logout()
	needsTOTP, err := app.LoginV2(migrationTestPassword)
	if err != nil || !needsTOTP {
		t.Fatalf("LoginV2 = (%v, %v), want TOTP pending", needsTOTP, err)
	}
	app.mu.RLock()
	pendingSession := app.v2Session
	app.mu.RUnlock()
	immutable := snapshotV2RecoveryImmutableFiles(t)
	if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
		t.Fatal("recovery started over a session waiting for TOTP")
	}
	assertV2RecoveryImmutableFiles(t, immutable)
	app.mu.RLock()
	stillPending := app.v2Session == pendingSession && app.vault != nil && !app.twoFAVerified
	app.mu.RUnlock()
	if !stillPending {
		t.Fatal("recovery attempt changed or discarded the pending authentication session")
	}
	app.Logout()
}

func TestV2RecoveryRequiresNoActiveV1Session(t *testing.T) {
	for _, pendingTOTP := range []bool{false, true} {
		name := "fully authenticated v1 session"
		vault := &Vault{Accounts: []Account{{ID: "v1-session"}}}
		if pendingTOTP {
			name = "v1 session waiting for TOTP"
			vault.TwoFAEnabled = true
			vault.TwoFASecret = "JBSWY3DPEHPK3PXP"
		}
		t.Run(name, func(t *testing.T) {
			withVaultDir(t)
			cm, err := crypto.NewCryptoManager(migrationTestPassword)
			if err != nil {
				t.Fatal(err)
			}
			defer cm.Wipe()
			if err := SaveVault(cm, vault); err != nil {
				t.Fatal(err)
			}
			app := NewApp()
			requiresTOTP, err := app.Login(migrationTestPassword)
			if err != nil || requiresTOTP != pendingTOTP {
				t.Fatalf("v1 login = (%v, %v)", requiresTOTP, err)
			}
			app.mu.RLock()
			activeManager, activeVault := app.cm, app.vault
			app.mu.RUnlock()
			if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
				t.Fatal("v2 recovery started while a v1 session was active")
			}
			app.mu.RLock()
			unchanged := app.cm == activeManager && app.vault == activeVault && app.cm != nil
			app.mu.RUnlock()
			if !unchanged {
				t.Fatal("recovery attempt overlapped or discarded the active v1 session")
			}
			app.Logout()
		})
	}
}

func TestV2RecoveryRestoresTOTPSettingFromOlderBackup(t *testing.T) {
	older := &Vault{Accounts: []Account{{ID: "older", Password: "synthetic"}}}
	app, engine := activatedV2App(t, older)
	app.Logout()
	newer := &Vault{Accounts: []Account{{ID: "newer", Password: "synthetic"}}, TwoFAEnabled: true, TwoFASecret: "JBSWY3DPEHPK3PXP"}
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, newer); err != nil {
		t.Fatal(err)
	}
	backupBefore, err := os.ReadFile(dataFileV2 + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	corruptV2Primary(t)
	immutable := snapshotV2RecoveryImmutableFiles(t)
	prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RequiresTOTP {
		t.Fatal("pre-TOTP backup reported a second-factor requirement")
	}
	if err := app.ConfirmV2VaultRecovery(prepared.Token, ""); err != nil {
		t.Fatalf("restore pre-TOTP backup: %v", err)
	}
	assertV2RecoveryImmutableFiles(t, immutable)
	assertFileBytes(t, dataFileV2+".bak", backupBefore)
	app.mu.RLock()
	restoredWithoutTOTP := app.vault != nil && !app.vault.TwoFAEnabled && app.twoFAVerified
	app.mu.RUnlock()
	if !restoredWithoutTOTP {
		t.Fatal("recovery did not restore the authorization settings contained in the old backup")
	}
	app.Logout()
}

type v2RecoveryImmutableSnapshot map[string][]byte

func snapshotV2RecoveryImmutableFiles(t *testing.T) v2RecoveryImmutableSnapshot {
	t.Helper()
	snapshot := make(v2RecoveryImmutableSnapshot)
	for _, path := range []string{dataFileV2 + ".bak", dataFile, dataFile + ".bak", vaultSelectorFile} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read recovery preservation snapshot %s: %v", path, err)
		}
		snapshot[path] = append([]byte(nil), data...)
	}
	return snapshot
}

func assertV2RecoveryImmutableFiles(t *testing.T, snapshot v2RecoveryImmutableSnapshot) {
	t.Helper()
	for path, expected := range snapshot {
		assertFileBytes(t, path, expected)
	}
}

func assertFileBytes(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("file %s changed: %v", path, err)
	}
}

func assertNoCorruptArchive(t *testing.T) {
	t.Helper()
	archives, err := filepath.Glob(dataFileV2 + ".corrupt-*")
	if err != nil || len(archives) != 0 {
		t.Fatalf("unexpected diagnostic archives = %v, %v", archives, err)
	}
}

func damageV2Tag(original []byte) []byte {
	var container cryptov2.Container
	if err := json.Unmarshal(original, &container); err != nil {
		panic(err)
	}
	ciphertext, err := decodeB64(container.Ciphertext)
	if err != nil {
		panic(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	container.Ciphertext = encodeB64(ciphertext)
	damaged, err := json.Marshal(container)
	if err != nil {
		panic(err)
	}
	return damaged
}

func TestV2RecoveryCancelAndExpiryClosePendingKey(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		app, _ := activatedV2App(t, syntheticMigrationVault())
		app.Logout()
		corruptV2Primary(t)
		prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		pending := pendingV2RecoverySession(app)
		app.CancelV2VaultRecovery(prepared.Token)
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
