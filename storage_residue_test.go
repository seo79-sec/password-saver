package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"password-saver/crypto"
)

func assertStorageBytes(t *testing.T, path string, expected []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("bytes changed at %s: %v", filepath.Base(path), err)
	}
}

func TestWriteResiduePreservesV2LoginTOTPAndSave(t *testing.T) {
	for _, name := range []string{".vault-write-123456", ".vault-v2-stage-4294967295"} {
		t.Run(name, func(t *testing.T) {
			want := syntheticMigrationVault()
			app, engine := activatedV2App(t, want)
			app.Logout()
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			original, err := snapshotKnownVaultFiles(dir)
			if err != nil {
				t.Fatal(err)
			}
			residue := []byte("untrusted partial synthetic ciphertext; never select it")
			writeStorageTestFile(t, name, residue)
			reads := countStoragePayloadReads(t)
			restarted := NewApp()
			restarted.v2Engine = engine
			t.Cleanup(restarted.Logout)
			for i := 0; i < 2; i++ {
				status := restarted.GetStorageLocationStatus()
				if status.State != "ready" || status.Diagnostic != "write-residue" || status.TemporaryFiles != 1 {
					t.Fatalf("residue status = %+v", status)
				}
				if public := restarted.GetVaultStatus(); public.State != VaultStateV2Active {
					t.Fatalf("residue changed selection: %+v", public)
				}
			}
			if *reads != 0 {
				t.Fatal("status read ciphertext/residue")
			}
			needsTOTP, err := restarted.LoginV2(migrationTestPassword)
			if err != nil || !needsTOTP {
				t.Fatalf("login = %v, %v", needsTOTP, err)
			}
			if _, err := restarted.GetAccounts(); err == nil {
				t.Fatal("residue bypassed TOTP")
			}
			if err := restarted.Verify2FA(currentCode(t, want.TwoFASecret)); err != nil {
				t.Fatal(err)
			}
			assertSnapshotEqual(t, dir, original)
			if err := restarted.AddAccount("synthetic extra", "synthetic login", "synthetic secret"); err != nil {
				t.Fatal(err)
			}
			assertStorageBytes(t, dataFileV2+".bak", original[dataFileV2])
			assertStorageBytes(t, vaultSelectorFile, original[vaultSelectorFile])
			assertStorageBytes(t, dataFile, original[dataFile])
			assertStorageBytes(t, dataFile+".bak", original[dataFile+".bak"])
			assertStorageBytes(t, name, residue)
			restarted.Logout()
			if _, err := restarted.LoginV2(migrationTestPassword); err != nil {
				t.Fatal(err)
			}
			if err := restarted.Verify2FA(currentCode(t, want.TwoFASecret)); err != nil {
				t.Fatal(err)
			}
			accounts, err := restarted.GetAccounts()
			if err != nil || len(accounts) != len(want.Accounts)+1 {
				t.Fatalf("save after residue failed: %v", err)
			}
			assertStorageBytes(t, name, residue)
		})
	}
}

func TestWriteResiduePreservesLegacyV1AndBackup(t *testing.T) {
	dir := withVaultDir(t)
	want := syntheticMigrationVault()
	cm, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cm.Wipe)
	if err := SaveVault(cm, want); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, want); err != nil {
		t.Fatal(err)
	}
	const name = ".vault-v2-stage-0"
	residue := []byte("untrusted partial selector or container")
	writeStorageTestFile(t, name, residue)
	app := NewApp()
	t.Cleanup(app.Logout)
	needsTOTP, err := app.Login(migrationTestPassword)
	if err != nil || !needsTOTP {
		t.Fatalf("legacy login = %v, %v", needsTOTP, err)
	}
	if err := app.Verify2FA(currentCode(t, want.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	before, err := snapshotKnownVaultFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.AddAccount("synthetic", "user", "synthetic secret"); err != nil {
		t.Fatal(err)
	}
	assertStorageBytes(t, dataFile+".bak", before[dataFile])
	assertStorageBytes(t, vaultSelectorFile, before[vaultSelectorFile])
	assertStorageBytes(t, name, residue)
}

func TestWriteResidueBlocksRecreatingMissingVaultDuringExistingSession(t *testing.T) {
	for _, format := range []string{"v1", "v2"} {
		t.Run(format, func(t *testing.T) {
			var app *App
			if format == "v2" {
				app, _ = activatedV2App(t, &Vault{})
			} else {
				withVaultDir(t)
				cm, err := crypto.NewCryptoManager(migrationTestPassword)
				if err != nil {
					t.Fatal(err)
				}
				if err := SaveVault(cm, &Vault{}); err != nil {
					t.Fatal(err)
				}
				cm.Wipe()
				app = NewApp()
				if _, err := app.Login(migrationTestPassword); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(app.Logout)
			// Model external loss of all normal containers after login.
			for name := range knownVaultFileLimits() {
				if name != vaultSelectorFile {
					if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				}
			}
			writeStorageTestFile(t, ".vault-write-2", []byte("interrupted data"))
			if err := app.AddAccount("synthetic", "user", "secret"); err == nil {
				t.Fatal("recreated missing vault over residue")
			}
			if !app.IsLocked() {
				t.Fatal("incomplete storage retained old session")
			}
			for _, name := range []string{dataFile, dataFileV2} {
				if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("lost primary was recreated")
				}
			}
			assertStorageBytes(t, ".vault-write-2", []byte("interrupted data"))
		})
	}
}

func TestWriteResidueDoesNotReplaceExplicitBackupRecovery(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run("primary state", func(t *testing.T) {
			want := syntheticMigrationVault()
			app, _ := activatedV2App(t, want)
			app.Logout()
			t.Cleanup(app.Logout)
			backup, err := os.ReadFile(dataFileV2 + ".bak")
			if err != nil {
				t.Fatal(err)
			}
			selector, err := os.ReadFile(vaultSelectorFile)
			if err != nil {
				t.Fatal(err)
			}
			v1, _ := os.ReadFile(dataFile)
			v1Backup, _ := os.ReadFile(dataFile + ".bak")
			corrupt := []byte("damaged synthetic primary")
			if missing {
				if err := os.Remove(dataFileV2); err != nil {
					t.Fatal(err)
				}
			} else {
				writeStorageTestFile(t, dataFileV2, corrupt)
			}
			// Even a fully valid encrypted container under a temporary name
			// is untrusted residue, never an alternative primary or backup.
			const name = ".vault-write-123"
			writeStorageTestFile(t, name, backup)
			if status := app.GetVaultStatus(); status.State != VaultStateV2Active || !status.V2BackupPresent {
				t.Fatalf("recovery hidden: %+v", status)
			}
			prepared, err := app.PrepareV2VaultRecovery(migrationTestPassword)
			if err != nil {
				t.Fatal(err)
			}
			assertStorageBytes(t, name, backup)
			assertStorageBytes(t, dataFileV2+".bak", backup)
			if !missing {
				assertStorageBytes(t, dataFileV2, corrupt)
			}
			if !prepared.RequiresTOTP {
				t.Fatal("temporary residue hid the second-factor requirement of the backup")
			}
			if _, err := app.GetAccounts(); err == nil {
				t.Fatal("backup password alone unlocked records")
			}
			if err := app.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, want.TwoFASecret)); err != nil {
				t.Fatalf("recovery with TOTP: %v", err)
			}
			assertStorageBytes(t, dataFileV2, backup)
			assertStorageBytes(t, dataFileV2+".bak", backup)
			assertStorageBytes(t, vaultSelectorFile, selector)
			assertStorageBytes(t, dataFile, v1)
			assertStorageBytes(t, dataFile+".bak", v1Backup)
			assertStorageBytes(t, name, backup)
			archives, err := filepath.Glob(dataFileV2 + ".corrupt-*")
			if err != nil {
				t.Fatal(err)
			}
			if !missing {
				if len(archives) != 1 {
					t.Fatal("damaged primary not archived")
				}
				assertStorageBytes(t, archives[0], corrupt)
			} else if len(archives) != 0 {
				t.Fatal("archive invented for missing primary")
			}
		})
	}
}

func TestWriteResidueAloneBlocksInitializationAndAllowsManualInspection(t *testing.T) {
	for _, withSelector := range []bool{false, true} {
		t.Run("unfinished first initialization", func(t *testing.T) {
			dir := withVaultDir(t)
			const name = ".vault-v2-stage-456"
			residue := []byte("incomplete first write")
			writeStorageTestFile(t, name, residue)
			if withSelector {
				writeStorageTestFile(t, vaultSelectorFile, []byte("partial selector"))
			}
			app := NewApp()
			status := app.GetStorageLocationStatus()
			if status.State != "incomplete-write" || status.Diagnostic != "incomplete-write" || status.TemporaryFiles != 1 {
				t.Fatalf("residue-only = %+v", status)
			}
			if status := app.GetVaultStatus(); status.State != VaultStateAmbiguous {
				t.Fatalf("residue offered as vault: %+v", status)
			}
			if err := app.CreateV2Vault(migrationTestPassword); !errors.Is(err, ErrVaultStorageIncomplete) {
				t.Fatalf("new vault created after crash: %v", err)
			}
			if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultStorageIncomplete) {
				t.Fatalf("v1 login with residue = %v", err)
			}
			if _, err := app.LoginV2(migrationTestPassword); !errors.Is(err, ErrVaultStorageIncomplete) {
				t.Fatalf("v2 login with residue = %v", err)
			}
			oldOpen := storageFolderOpener
			storageFolderOpener = func(path string) error {
				if path != dir {
					t.Fatal("opened arbitrary path")
				}
				return nil
			}
			t.Cleanup(func() { storageFolderOpener = oldOpen })
			if err := app.OpenStorageFolder(); err != nil {
				t.Fatal(err)
			}
			assertStorageBytes(t, name, residue)
			if _, err := os.Lstat(dataFileV2); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("residue promoted to primary")
			}
		})
	}
}

func TestWriteResidueStrictNamesAndFileTypes(t *testing.T) {
	for _, name := range []string{".vault-write-", ".vault-write-01", ".vault-write-+1", ".vault-write-4294967296", ".vault-write-123.txt", ".vault-write-１２３", ".vault-WRITE-123", ".vault-v2-stage-unknown", ".default-migration-123", "unknown.txt"} {
		t.Run(name, func(t *testing.T) {
			dir := withVaultDir(t)
			writeStorageTestFile(t, name, []byte("unknown synthetic object"))
			if _, err := scanVaultDirectory(dir, managedVaultDirectory); !errors.Is(err, ErrVaultStorageUnsafe) {
				t.Fatalf("unexpected name accepted: %v", err)
			}
			if status := storageLocationStatus(); status.State != "error" || status.Diagnostic != "unsafe-entry" {
				t.Fatalf("missing unsafe diagnostics: %+v", status)
			}
			assertStorageBytes(t, name, []byte("unknown synthetic object"))
		})
	}
	for _, kind := range []string{"oversize", "directory", "symlink", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := withVaultDir(t)
			path := filepath.Join(dir, ".vault-write-123")
			target := filepath.Join(t.TempDir(), "synthetic-target")
			writeStorageTestFile(t, target, []byte("must stay untouched"))
			switch kind {
			case "oversize":
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				err = f.Truncate(vaultWriteTemporaryLimit() + 1)
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("oversize fixture: %v, %v", err, closeErr)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if kind == "dangling symlink" {
					target += "-missing"
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink privilege unavailable: %v", err)
				}
			}
			if _, err := scanVaultDirectory(dir, managedVaultDirectory); !errors.Is(err, ErrVaultStorageUnsafe) {
				t.Fatalf("unsafe residue accepted: %v", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("unsafe object removed")
			}
			if kind != "dangling symlink" {
				assertStorageBytes(t, filepath.Join(filepath.Dir(target), "synthetic-target"), []byte("must stay untouched"))
			}
		})
	}
}

func TestWriteResidueIsNeverReadOrIncludedInInventory(t *testing.T) {
	dir := withVaultDir(t)
	for _, name := range []string{".vault-write-0", ".vault-write-4294967295", ".vault-v2-stage-123"} {
		writeStorageTestFile(t, name, nil)
	}
	original := readStorageInventoryFile
	readStorageInventoryFile = func(path string, limit int64) ([]byte, error) {
		t.Fatalf("residue was read: %s", filepath.Base(path))
		return nil, nil
	}
	t.Cleanup(func() { readStorageInventoryFile = original })
	inventory, err := inspectVaultFiles(dir)
	if err != nil || inventory.HasVaultFiles || len(inventory.Files) != 0 {
		t.Fatalf("residue in payload inventory: %+v, %v", inventory, err)
	}
	if err := requireEmptyDirectoryIfPresent(dir); !errors.Is(err, ErrVaultStorageConflict) {
		t.Fatalf("residue allowed migration overwrite: %v", err)
	}
}

func TestWriteResidueCannotBeUsedAsBackupOrOverrideSelector(t *testing.T) {
	app, _ := activatedV2App(t, syntheticMigrationVault())
	app.Logout()
	t.Cleanup(app.Logout)
	valid, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := os.ReadFile(vaultSelectorFile)
	if err != nil {
		t.Fatal(err)
	}
	writeStorageTestFile(t, ".vault-v2-stage-12", valid)
	writeStorageTestFile(t, dataFileV2, []byte("corrupt synthetic primary"))
	if err := os.Remove(dataFileV2 + ".bak"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareV2VaultRecovery(migrationTestPassword); err == nil {
		t.Fatal("temporary used as backup")
	}
	assertStorageBytes(t, vaultSelectorFile, selector)
	assertStorageBytes(t, ".vault-v2-stage-12", valid)
	assertStorageBytes(t, dataFileV2, []byte("corrupt synthetic primary"))
	writeStorageTestFile(t, vaultSelectorFile, []byte("unknown selector"))
	if _, err := app.LoginV2(migrationTestPassword); err == nil {
		t.Fatal("temporary bypassed invalid selector")
	}
	if _, err := app.Login(migrationTestPassword); err == nil {
		t.Fatal("temporary downgraded v2 to v1")
	}
	assertStorageBytes(t, vaultSelectorFile, []byte("unknown selector"))
}

func TestWriteResidueUnsafeDiagnosticsAllowOnlyFixedFolderInspection(t *testing.T) {
	dir := withVaultDir(t)
	writeStorageTestFile(t, ".vault-write-unexpected", []byte("must not be touched"))
	oldOpen := storageFolderOpener
	called := false
	storageFolderOpener = func(path string) error {
		if path != dir {
			t.Fatal("arbitrary folder")
		}
		called = true
		return nil
	}
	t.Cleanup(func() { storageFolderOpener = oldOpen })
	app := NewApp()
	if err := app.OpenStorageFolder(); err != nil || !called {
		t.Fatalf("manual folder inspection = %v, %v", called, err)
	}
	assertStorageBytes(t, ".vault-write-unexpected", []byte("must not be touched"))
	if _, err := activeVaultStorageDirectory(); !errors.Is(err, ErrVaultStorageUnsafe) {
		t.Fatalf("unsafe entry did not block writes: %v", err)
	}

	// A symlink in the managed directory path cannot use the diagnostic
	// folder-opening path to bypass the existing component checks.
	otherRoot := filepath.Join(t.TempDir(), "PasswordSaver", "vaults", "default")
	if err := os.MkdirAll(filepath.Dir(otherRoot), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, otherRoot); err != nil {
		t.Skipf("symlink privilege unavailable: %v", err)
	}
	restore := setStorageDirectoryOverrideForTest(otherRoot)
	t.Cleanup(restore)
	called = false
	if err := app.OpenStorageFolder(); !errors.Is(err, ErrVaultStorageUnsafe) || called {
		t.Fatalf("followed folder symlink: %v, %v", called, err)
	}
}

// Exit before the rename/link and without running defers, reproducing a real
// terminated writer rather than a normal error path which removes its temp.
func TestStorageInterruptedWriterProcess(t *testing.T) {
	dir := os.Getenv("PASSWORDSAVER_TEST_CRASH_DIR")
	if dir == "" {
		return
	}
	syncVaultTempFile = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			os.Exit(92)
		}
		os.Exit(91)
		return nil
	}
	path := filepath.Join(dir, "never-published")
	if os.Getenv("PASSWORDSAVER_TEST_CRASH_MODE") == "replace" {
		_ = writeFileAtomic(path, []byte("interrupted synthetic encrypted write"))
	} else {
		_ = writeFileAtomicNoReplace(path, []byte("interrupted synthetic encrypted write"))
	}
	os.Exit(93)
}

func TestWriteResidueAfterTerminatedWriterSupportsRestart(t *testing.T) {
	for _, mode := range []string{"replace", "no-replace"} {
		t.Run(mode, func(t *testing.T) {
			app, engine := activatedV2App(t, syntheticMigrationVault())
			app.Logout()
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			before, err := snapshotKnownVaultFiles(dir)
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestStorageInterruptedWriterProcess$")
			cmd.Env = append(os.Environ(), "PASSWORDSAVER_TEST_CRASH_DIR="+dir, "PASSWORDSAVER_TEST_CRASH_MODE="+mode)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("crash helper: %v, %s", err, output)
			}
			restarted := NewApp()
			restarted.v2Engine = engine
			t.Cleanup(restarted.Logout)
			if status := restarted.GetStorageLocationStatus(); status.State != "ready" || status.TemporaryFiles != 1 {
				t.Fatalf("post-crash status = %+v", status)
			}
			if _, err := restarted.LoginV2(migrationTestPassword); err != nil {
				t.Fatal(err)
			}
			assertSnapshotEqual(t, dir, before)
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if isVaultWriteTemporary(entry.Name()) {
					assertStorageBytes(t, entry.Name(), []byte("interrupted synthetic encrypted write"))
				}
			}
			if _, err := os.Lstat("never-published"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("interrupted target was published")
			}
		})
	}
}

func TestLocationChecksDuringAtomicSaveKeepResidueUnchanged(t *testing.T) {
	app, _ := activatedV2App(t, syntheticMigrationVault())
	t.Cleanup(app.Logout)
	writeStorageTestFile(t, ".vault-write-1", []byte("older residue"))
	original := syncVaultTempFile
	syncVaultTempFile = func(f *os.File) error {
		directory := filepath.Dir(f.Name())
		if _, err := activeVaultStorageDirectory(); err != nil {
			return err
		}
		inventory, err := inspectVaultFiles(directory)
		if err != nil {
			return err
		}
		for name := range inventory.Files {
			if strings.HasPrefix(name, ".vault-") {
				t.Fatal("live temp entered inventory")
			}
		}
		return original(f)
	}
	t.Cleanup(func() { syncVaultTempFile = original })
	// Concurrent read-only route checks share no trust cache with the save.
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < 5; i++ {
			if status := storageLocationStatus(); status.State != "ready" {
				t.Errorf("status during save = %+v", status)
			}
		}
	})
	if err := app.AddAccount("synthetic", "user", "synthetic secret"); err != nil {
		t.Error(err)
	}
	wg.Wait()
	assertStorageBytes(t, ".vault-write-1", []byte("older residue"))
}
