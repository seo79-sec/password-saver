package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

type storageMigrationFixture struct {
	app      *App
	source   string
	target   string
	engine   *cryptov2.Engine
	vault    *Vault
	files    map[string][]byte
	format   string
	password string
}

func newStorageMigrationFixture(t *testing.T, format string, vault *Vault) storageMigrationFixture {
	t.Helper()
	base := t.TempDir()
	source := filepath.Join(base, "old-install")
	target := filepath.Join(base, "local", "PasswordSaver", "vaults", "default")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	cleanupOverride := setStorageDirectoryOverrideForTest(target)
	t.Cleanup(cleanupOverride)
	previousProvider := legacyDirectoryProvider
	legacyDirectoryProvider = func(string) ([]string, error) { return []string{source}, nil }
	t.Cleanup(func() { legacyDirectoryProvider = previousProvider })

	engine := migrationEngine(t)
	switch format {
	case "v1":
		cm, err := crypto.NewCryptoManager(migrationTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveVaultToPath(filepath.Join(source, dataFile), cm, vault); err != nil {
			cm.Wipe()
			t.Fatal(err)
		}
		if err := saveVaultToPath(filepath.Join(source, dataFile), cm, vault); err != nil {
			cm.Wipe()
			t.Fatal(err)
		}
		cm.Wipe()
		if err := writeVaultSelector(filepath.Join(source, vaultSelectorFile), vaultSelectorRecord{
			Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV1,
		}); err != nil {
			t.Fatal(err)
		}
	case "v2":
		plaintext, err := json.Marshal(vault)
		if err != nil {
			t.Fatal(err)
		}
		container, err := engine.Encrypt(migrationTestPassword, plaintext)
		wipeBytes(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, dataFileV2), container, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, dataFileV2+".bak"), container, 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeVaultSelector(filepath.Join(source, vaultSelectorFile), vaultSelectorRecord{
			Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV2,
			NativeV2: true, ActivatedV2SHA256: digestHex(container),
		}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown fixture format %q", format)
	}
	files, err := snapshotKnownVaultFiles(source)
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	app.v2Engine = engine
	return storageMigrationFixture{
		app: app, source: source, target: target, engine: engine, vault: cloneVault(vault),
		files: files, format: format, password: migrationTestPassword,
	}
}

func snapshotKnownVaultFiles(directory string) (map[string][]byte, error) {
	inventory, err := inspectLegacyVaultFiles(directory)
	if err != nil {
		return nil, err
	}
	copy := make(map[string][]byte, len(inventory.Files))
	for name, data := range inventory.Files {
		copy[name] = append([]byte(nil), data...)
	}
	return copy, nil
}

func assertSnapshotEqual(t *testing.T, directory string, expected map[string][]byte) {
	t.Helper()
	actual, err := snapshotKnownVaultFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !sameInventory(vaultFileInventory{HasVaultFiles: len(expected) > 0, Files: expected}, vaultFileInventory{HasVaultFiles: len(actual) > 0, Files: actual}) {
		t.Fatalf("vault files changed in %s", directory)
	}
}

func TestStorageWindowsDefaultUsesLocalAppDataAndIndependentLayout(t *testing.T) {
	localAppData := t.TempDir()
	got, err := vaultDirectoryForOS("windows", localAppData, filepath.Join(t.TempDir(), "cache"), filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(localAppData, "PasswordSaver", "vaults", "default")
	if got != want {
		t.Fatalf("Windows AppData path = %q, want %q", got, want)
	}
	if filepath.Base(filepath.Dir(got)) != "vaults" || filepath.Base(got) != "default" || filepath.Base(filepath.Dir(filepath.Dir(got))) != "PasswordSaver" {
		t.Fatalf("Windows AppData layout = %q", got)
	}
	cacheDir := t.TempDir()
	if fallback, err := vaultDirectoryForOS("windows", "", cacheDir, ""); err != nil || fallback != filepath.Join(cacheDir, "PasswordSaver", "vaults", "default") {
		t.Fatalf("Windows cache fallback = (%q, %v)", fallback, err)
	}
}

func TestStorageMigrationCopiesAuthenticatedV2OnlyAfterExplicitConfirmation(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	status := storageLocationStatus()
	if status.State != "migration-required" || status.Path != fixture.target || len(status.LegacyPaths) != 1 {
		t.Fatalf("legacy route status = %+v", status)
	}
	if _, err := fixture.app.PrepareStorageLocationMigration("wrong synthetic password", currentCode(t, fixture.vault.TwoFASecret)); err == nil {
		t.Fatal("wrong master password was accepted for storage migration")
	}
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare created destination: %v", err)
	}
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first step copied files before explicit confirmation")
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	if err := fixture.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	assertSnapshotEqual(t, fixture.target, fixture.files)
	if status := storageLocationStatus(); status.State != "ready" || status.Format != "v2" || status.Algorithm != "AES-256-GCM" || !status.BackupPresent {
		t.Fatalf("post-migration storage status = %+v", status)
	}
	needsTOTP, err := fixture.app.LoginV2(fixture.password)
	if err != nil || !needsTOTP {
		t.Fatalf("v2 login after copy = (%v, %v)", needsTOTP, err)
	}
	if err := fixture.app.Verify2FA(currentCode(t, fixture.vault.TwoFASecret)); err != nil {
		t.Fatalf("v2 TOTP after copy failed: %v", err)
	}
	accounts, err := fixture.app.GetAccounts()
	if err != nil || !reflect.DeepEqual(accounts, fixture.vault.Accounts) {
		t.Fatalf("copied v2 records = (%+v, %v)", accounts, err)
	}
	fixture.app.Logout()
}

func TestStorageMigrationCancellationAndExpiryLeaveLegacyAvailable(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v1", syntheticMigrationVault())
	code := currentCode(t, fixture.vault.TwoFASecret)
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, code)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.CancelStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancel created target: %v", err)
	}
	if status := storageLocationStatus(); status.State != "migration-required" {
		t.Fatalf("legacy route lost after cancel: %+v", status)
	}

	oldLifetime := storageMigrationChallengeLifetime
	storageMigrationChallengeLifetime = 10 * time.Millisecond
	t.Cleanup(func() { storageMigrationChallengeLifetime = oldLifetime })
	token, err = fixture.app.PrepareStorageLocationMigration(fixture.password, code)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if err := fixture.app.ConfirmStorageLocationMigration(token); !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("expired copy challenge error = %v", err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired challenge created target: %v", err)
	}
	storageMigrationChallengeLifetime = oldLifetime
	// The challenge can be prepared again, and the original v1/TOTP state
	// remains usable after a subsequent successful copy.
	token, err = fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	if needsTOTP, err := fixture.app.Login(fixture.password); err != nil || !needsTOTP {
		t.Fatalf("v1 login after copy = (%v, %v)", needsTOTP, err)
	}
	if err := fixture.app.Verify2FA(currentCode(t, fixture.vault.TwoFASecret)); err != nil {
		t.Fatalf("TOTP after v1 copy failed: %v", err)
	}
	accounts, err := fixture.app.GetAccounts()
	if err != nil || !reflect.DeepEqual(accounts, fixture.vault.Accounts) {
		t.Fatalf("v1 records after copy = (%+v, %v)", accounts, err)
	}
	fixture.app.Logout()
}

func TestStorageMigrationRestartDropsOnlyTheChallengeAndCanRetry(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	// A process restart loses the in-memory challenge; it has not copied or
	// modified any file, so the user can authenticate and prepare again.
	fixture.app.Logout()
	if len(fixture.app.pendingStorageMigration.files) != 0 {
		t.Fatal("logout did not clear the encrypted migration snapshot")
	}
	restarted := NewApp()
	restarted.v2Engine = fixture.engine
	if err := restarted.ConfirmStorageLocationMigration(token); !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("pre-restart token was accepted: %v", err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart published an unconfirmed copy: %v", err)
	}
	token, err = restarted.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	assertSnapshotEqual(t, fixture.target, fixture.files)
}

func TestStorageMigrationRequiresFullyLockedSessionIncludingPendingTOTP(t *testing.T) {
	t.Run("v1 pending TOTP", func(t *testing.T) {
		fixture := newStorageMigrationFixture(t, "v1", syntheticMigrationVault())
		cm, err := crypto.NewCryptoManager(fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		fixture.app.cm = cm
		fixture.app.vault = cloneVault(fixture.vault)
		if _, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret)); err == nil {
			t.Fatal("storage migration began during pending v1 TOTP verification")
		}
		fixture.app.Logout()
	})
	t.Run("v2 pending TOTP", func(t *testing.T) {
		fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
		fixture.app.v2Session = &v2VaultSession{engine: fixture.engine}
		fixture.app.vault = cloneVault(fixture.vault)
		if _, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret)); err == nil {
			t.Fatal("storage migration began during pending v2 TOTP verification")
		}
		fixture.app.Logout()
	})
}

func TestStorageMigrationConflictingLocationsAreNotOverwritten(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	if err := os.MkdirAll(fixture.target, 0700); err != nil {
		t.Fatal(err)
	}
	other := &Vault{Accounts: []Account{{ID: "target-only", Password: "synthetic-only"}}}
	plain, _ := json.Marshal(other)
	container, err := fixture.engine.Encrypt(fixture.password, plain)
	wipeBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.target, dataFileV2), container, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.target, dataFileV2+".bak"), container, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeVaultSelector(filepath.Join(fixture.target, vaultSelectorFile), vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV2,
		NativeV2: true, ActivatedV2SHA256: digestHex(container),
	}); err != nil {
		t.Fatal(err)
	}
	targetBefore, err := snapshotKnownVaultFiles(fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	if status := storageLocationStatus(); status.State != "conflict" {
		t.Fatalf("dual location status = %+v", status)
	}
	if _, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret)); !errors.Is(err, ErrVaultStorageConflict) {
		t.Fatalf("conflict preparation error = %v", err)
	}
	oldOpener := storageFolderOpener
	var opened []string
	storageFolderOpener = func(path string) error { opened = append(opened, path); return nil }
	t.Cleanup(func() { storageFolderOpener = oldOpener })
	if err := fixture.app.OpenStorageFolder(); err != nil {
		t.Fatalf("open AppData folder during conflict: %v", err)
	}
	if err := fixture.app.OpenLegacyStorageFolder(); err != nil {
		t.Fatalf("open legacy folder during conflict: %v", err)
	}
	if !reflect.DeepEqual(opened, []string{fixture.target, fixture.source}) {
		t.Fatalf("conflict folder targets = %q", opened)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	assertSnapshotEqual(t, fixture.target, targetBefore)
}

func TestStorageMigrationStageFailurePreservesSourceAndCanBeRetried(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v1", syntheticMigrationVault())
	oldWrite := storageMigrationWriteFile
	storageMigrationWriteFile = func(path string, data []byte) error {
		if filepath.Base(path) == dataFile+".bak" {
			return os.ErrPermission
		}
		return oldWrite(path, data)
	}
	t.Cleanup(func() { storageMigrationWriteFile = oldWrite })
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.app.ConfirmStorageLocationMigration(token); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("injected stage failure = %v", err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed stage published destination: %v", err)
	}
	storageMigrationWriteFile = oldWrite
	token, err = fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatalf("retry after stage error failed: %v", err)
	}
	if err := fixture.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatalf("retry confirmation failed: %v", err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	assertSnapshotEqual(t, fixture.target, fixture.files)
}

func TestStorageMigrationCopiesDamagedPrimaryAndAllowsExplicitBackupRecovery(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	corrupt := []byte("random damaged synthetic primary")
	if err := os.WriteFile(filepath.Join(fixture.source, dataFileV2), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.files, _ = snapshotKnownVaultFiles(fixture.source)
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret))
	if err != nil {
		t.Fatalf("valid encrypted backup did not authorize a safe copy: %v", err)
	}
	if err := fixture.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	assertSnapshotEqual(t, fixture.source, fixture.files)
	app := NewApp()
	app.v2Engine = fixture.engine
	prepared, err := app.PrepareV2VaultRecovery(fixture.password)
	if err != nil {
		t.Fatalf("backup recovery after storage copy could not be prepared: %v", err)
	}
	if !prepared.RequiresTOTP {
		t.Fatal("storage copy lost TOTP")
	}
	if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, fixture.vault.TwoFASecret)); err != nil {
		t.Fatalf("backup recovery confirmation with TOTP failed: %v", err)
	}
	accounts, err := app.GetAccounts()
	if err != nil || !reflect.DeepEqual(accounts, fixture.vault.Accounts) {
		t.Fatalf("recovered v2 accounts = (%+v, %v)", accounts, err)
	}
	app.Logout()
}

func TestStorageMigrationUsesPreTOTPBackupOnlyThroughExplicitRecovery(t *testing.T) {
	newer := syntheticMigrationVault()
	fixture := newStorageMigrationFixture(t, "v2", newer)
	preTOTP := cloneVault(newer)
	preTOTP.TwoFAEnabled = false
	preTOTP.TwoFASecret = ""
	plain, err := json.Marshal(preTOTP)
	if err != nil {
		t.Fatal(err)
	}
	oldBackup, err := fixture.engine.Encrypt(fixture.password, plain)
	wipeBytes(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.source, dataFileV2), []byte("damaged active primary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.source, dataFileV2+".bak"), oldBackup, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.files, err = snapshotKnownVaultFiles(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	token, err := fixture.app.PrepareStorageLocationMigration(fixture.password, "")
	if err != nil {
		t.Fatalf("verified pre-TOTP backup could not be copied: %v", err)
	}
	if err := fixture.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	recovered := NewApp()
	recovered.v2Engine = fixture.engine
	if prepared, err := recovered.PrepareV2VaultRecovery(fixture.password); err != nil {
		t.Fatalf("recovery from pre-TOTP backup could not be prepared: %v", err)
	} else {
		if prepared.RequiresTOTP {
			t.Fatal("pre-TOTP backup reported a second factor")
		}
		if err := recovered.ConfirmV2VaultRecovery(prepared.Token, ""); err != nil {
			t.Fatalf("recovered pre-TOTP state: %v", err)
		}
	}
	accounts, err := recovered.GetAccounts()
	if err != nil || !reflect.DeepEqual(accounts, preTOTP.Accounts) {
		t.Fatalf("pre-TOTP backup records = (%+v, %v)", accounts, err)
	}
	recovered.Logout()
}

func TestStorageMigrationNeverUsesBackupForUnsupportedFutureV2(t *testing.T) {
	fixture := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	primary, err := os.ReadFile(filepath.Join(fixture.source, dataFileV2))
	if err != nil {
		t.Fatal(err)
	}
	future := strings.Replace(string(primary), `"version":1`, `"version":99`, 1)
	if future == string(primary) {
		t.Fatal("fixture container did not contain a version field")
	}
	if err := os.WriteFile(filepath.Join(fixture.source, dataFileV2), []byte(future), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := snapshotKnownVaultFiles(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.app.PrepareStorageLocationMigration(fixture.password, currentCode(t, fixture.vault.TwoFASecret)); !errors.Is(err, ErrVaultUnsupportedFormat) {
		t.Fatalf("future format was treated as repairable: %v", err)
	}
	assertSnapshotEqual(t, fixture.source, before)
	if _, err := os.Stat(fixture.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("future format created an AppData copy: %v", err)
	}
}

func TestStorageMigrationDoesNotReadWorkingDirectoryForLegacyFiles(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "local", "PasswordSaver", "vaults", "default")
	working := filepath.Join(base, "unrelated-launch-directory")
	if err := os.MkdirAll(working, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(working, dataFileV2), []byte("unrelated marker"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanupOverride := setStorageDirectoryOverrideForTest(target)
	t.Cleanup(cleanupOverride)
	previousProvider := legacyDirectoryProvider
	legacyDirectoryProvider = func(string) ([]string, error) { return nil, nil }
	t.Cleanup(func() { legacyDirectoryProvider = previousProvider })
	oldWorking, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(working); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWorking) })
	got, err := activeVaultStorageDirectory()
	if err != nil || got != target {
		t.Fatalf("active directory changed with working directory = (%q, %v)", got, err)
	}
	if _, err := os.Stat(filepath.Join(target, dataFileV2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("working-directory marker was consumed: %v", err)
	}
	if filepath.Base(got) != "default" {
		t.Fatalf("unexpected Windows root %q", got)
	}
}
