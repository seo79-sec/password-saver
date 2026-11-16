package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeStorageTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func addInstallationFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"password-saver.exe":        []byte("synthetic executable, never execute"),
		"password-saver.exe.sha256": []byte("synthetic checksum"),
		"notes.txt":                 []byte("unrelated user file"),
	}
	for name, data := range files {
		writeStorageTestFile(t, filepath.Join(dir, name), data)
	}
	return files
}

func countStoragePayloadReads(t *testing.T) *int {
	t.Helper()
	reads := new(int)
	original := readStorageInventoryFile
	readStorageInventoryFile = func(path string, limit int64) ([]byte, error) {
		if filepath.Base(path) != vaultSelectorFile {
			*reads++
		}
		return original(path, limit)
	}
	t.Cleanup(func() { readStorageInventoryFile = original })
	return reads
}

func TestLegacyDirectoryIgnoresApplicationFiles(t *testing.T) {
	for _, names := range [][]string{nil, {"password-saver.exe"}, {"password-saver.exe", "password-saver.exe.sha256"}, {"notes.txt"}} {
		t.Run("installation", func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range names {
				writeStorageTestFile(t, filepath.Join(dir, name), []byte("unrelated"))
			}
			reads := countStoragePayloadReads(t)
			inventory, err := inspectLegacyVaultFiles(dir)
			if err != nil || inventory.HasVaultFiles || *reads != 0 {
				t.Fatalf("legacy inventory = %+v, %v; reads=%d", inventory, err, *reads)
			}
			// Exercise the production executable discovery with an EXE directory
			// containing no vault, not just the standalone inventory helper.
			restore := setStorageDirectoryOverrideForTest(filepath.Join(t.TempDir(), "PasswordSaver", "vaults", "default"))
			t.Cleanup(restore)
			oldExec, oldProvider := storageExecutablePath, legacyDirectoryProvider
			storageExecutablePath = func() (string, error) { return filepath.Join(dir, "password-saver.exe"), nil }
			legacyDirectoryProvider = discoverLegacyVaultDirectories
			t.Cleanup(func() { storageExecutablePath, legacyDirectoryProvider = oldExec, oldProvider })
			if route, err := discoverStorageRoute(); err != nil || route.State != storageRouteReady {
				t.Fatalf("installation route = %+v, %v", route, err)
			}
		})
	}
}

func TestLegacyMigrationWithExecutableCopiesOnlyVaultFiles(t *testing.T) {
	for _, format := range []string{"v1", "v2"} {
		t.Run(format, func(t *testing.T) {
			f := newStorageMigrationFixture(t, format, syntheticMigrationVault())
			extras := addInstallationFiles(t, f.source)
			token, err := f.app.PrepareStorageLocationMigration(f.password, currentCode(t, f.vault.TwoFASecret))
			if err != nil {
				t.Fatal(err)
			}
			if err := f.app.ConfirmStorageLocationMigration(token); err != nil {
				t.Fatal(err)
			}
			assertSnapshotEqual(t, f.source, f.files)
			assertSnapshotEqual(t, f.target, f.files)
			for name, data := range extras {
				got, err := os.ReadFile(filepath.Join(f.source, name))
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("unrelated file %s modified", name)
				}
				if _, err := os.Lstat(filepath.Join(f.target, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unrelated file copied: %s", name)
				}
			}
		})
	}
}

func TestLegacyCorruptionDoesNotDisguiseAsEmptyInstallation(t *testing.T) {
	f := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	addInstallationFiles(t, f.source)
	writeStorageTestFile(t, filepath.Join(f.source, dataFileV2), []byte("corrupt synthetic primary"))
	writeStorageTestFile(t, filepath.Join(f.source, dataFileV2+".bak"), []byte("corrupt synthetic backup"))
	before, err := snapshotKnownVaultFiles(f.source)
	if err != nil {
		t.Fatal(err)
	}
	if status := storageLocationStatus(); status.State != "migration-required" {
		t.Fatalf("lost legacy data: %+v", status)
	}
	if _, err := f.app.PrepareStorageLocationMigration(f.password, ""); err == nil {
		t.Fatal("corrupt files authenticated")
	}
	if err := f.app.CreateV2Vault(f.password); err == nil {
		t.Fatal("created empty vault over undiscovered legacy")
	}
	assertSnapshotEqual(t, f.source, before)
}

func TestStorageDirectoryModesPreserveStrictFileChecks(t *testing.T) {
	for _, kind := range []storageDirectoryKind{legacyVaultDirectory, managedVaultDirectory} {
		t.Run("known symlink", func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "synthetic")
			writeStorageTestFile(t, target, []byte("encrypted marker"))
			if err := os.Symlink(target, filepath.Join(dir, dataFileV2)); err != nil {
				t.Skipf("OS does not permit symlink creation: %v", err)
			}
			if _, err := scanVaultDirectory(dir, kind); !errors.Is(err, ErrVaultStorageUnsafe) {
				t.Fatalf("symlink accepted: %v", err)
			}
		})
		t.Run("known directory", func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, dataFile), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := scanVaultDirectory(dir, kind); !errors.Is(err, ErrVaultStorageUnsafe) {
				t.Fatalf("directory accepted: %v", err)
			}
		})
		t.Run("oversized known file", func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, vaultSelectorFile)
			writeStorageTestFile(t, path, make([]byte, 4097))
			if _, err := scanVaultDirectory(dir, kind); !errors.Is(err, ErrVaultDataLocation) {
				t.Fatalf("oversized selector accepted: %v", err)
			}
		})
	}
	t.Run("unexpected managed entry", func(t *testing.T) {
		dir := t.TempDir()
		addInstallationFiles(t, dir)
		if _, err := inspectVaultFiles(dir); !errors.Is(err, ErrVaultStorageUnsafe) {
			t.Fatalf("managed allowlist weakened: %v", err)
		}
	})
}

// Model the Windows shortcut's Start in directory being different from the
// EXE directory. A native selection can choose either, even on another volume;
// the production code does not derive a source from the process CWD.
func manualStorageFixture(t *testing.T, format string) storageMigrationFixture {
	t.Helper()
	f := newStorageMigrationFixture(t, format, syntheticMigrationVault())
	exeDir := t.TempDir()
	addInstallationFiles(t, exeDir)
	oldExec := storageExecutablePath
	storageExecutablePath = func() (string, error) { return filepath.Join(exeDir, "password-saver.exe"), nil }
	legacyDirectoryProvider = discoverLegacyVaultDirectories
	t.Cleanup(func() { storageExecutablePath = oldExec })
	oldChoose := chooseLegacyStorageDirectory
	chooseLegacyStorageDirectory = func(context.Context) (string, error) { return f.source, nil }
	t.Cleanup(func() { chooseLegacyStorageDirectory = oldChoose; f.app.Logout() })
	return f
}

func TestManualLegacySelectionFromDifferentWorkingDirectory(t *testing.T) {
	for _, format := range []string{"v1", "v2"} {
		t.Run(format, func(t *testing.T) {
			f := manualStorageFixture(t, format)
			addInstallationFiles(t, f.source)
			t.Chdir(f.source)
			reads := countStoragePayloadReads(t)
			if route, err := discoverStorageRoute(); err != nil || route.State != storageRouteReady {
				t.Fatalf("CWD auto-selected: %+v %v", route, err)
			}
			// Startup/status creates only an empty managed scaffold. It must
			// still be possible to import before creating a new vault.
			if status := storageLocationStatus(); status.State != "ready" {
				t.Fatalf("initial status = %+v", status)
			}
			selected, err := f.app.SelectLegacyStorageDirectory()
			if err != nil || selected.Path != f.source || selected.Token == "" || selected.TargetPath != f.target {
				t.Fatalf("native choice = %+v, %v", selected, err)
			}
			if *reads != 0 {
				t.Fatalf("choosing a directory read payloads %d times", *reads)
			}
			if err := f.app.CreateV2Vault(f.password); !errors.Is(err, ErrVaultStorageMigrationBusy) {
				t.Fatalf("created second vault during selection: %v", err)
			}
			if _, err := f.app.PrepareSelectedStorageLocationMigration(f.source, f.password, ""); !errors.Is(err, ErrVaultStorageMigrationExpired) {
				t.Fatalf("path accepted instead of capability: %v", err)
			}
			if _, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, "wrong synthetic password", ""); err == nil {
				t.Fatal("wrong password accepted")
			}
			if _, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, "invalid"); !errors.Is(err, errStorageMigrationTOTP) {
				t.Fatalf("wrong TOTP accepted: %v", err)
			}
			token, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, currentCode(t, f.vault.TwoFASecret))
			if err != nil {
				t.Fatal(err)
			}
			if err := requireEmptyDirectoryIfPresent(f.target); err != nil {
				t.Fatalf("copied without confirmation: %v", err)
			}
			if err := f.app.CreateV2Vault(f.password); !errors.Is(err, ErrVaultStorageMigrationBusy) {
				t.Fatalf("created second vault during confirmation: %v", err)
			}
			if err := f.app.ConfirmStorageLocationMigration(token); err != nil {
				t.Fatal(err)
			}
			assertSnapshotEqual(t, f.source, f.files)
			assertSnapshotEqual(t, f.target, f.files)
			if _, err := os.Stat(filepath.Join(f.target, "password-saver.exe")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("copied executable")
			}
		})
	}
}

func TestManualStorageSelectionRejectsUnsafePathsSelectorsAndConflicts(t *testing.T) {
	for _, scenario := range []string{"relative", "empty", "file", "selector", "target conflict", "two legacy vaults", "same target"} {
		t.Run(scenario, func(t *testing.T) {
			f := manualStorageFixture(t, "v2")
			selectedPath := f.source
			switch scenario {
			case "relative":
				selectedPath = "."
			case "empty":
				selectedPath = t.TempDir()
			case "file":
				selectedPath = filepath.Join(f.source, dataFileV2)
			case "selector":
				writeStorageTestFile(t, filepath.Join(f.source, vaultSelectorFile), []byte(`{"format":"unknown","version":1,"mode":"v2-active"}`))
			case "target conflict", "same target":
				if err := os.MkdirAll(f.target, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range f.files {
					writeStorageTestFile(t, filepath.Join(f.target, name), data)
				}
				if scenario == "same target" {
					selectedPath = f.target
				}
			case "two legacy vaults":
				second := t.TempDir()
				writeStorageTestFile(t, filepath.Join(second, dataFile), []byte("different encrypted marker"))
				legacyDirectoryProvider = func(string) ([]string, error) { return []string{second}, nil }
			}
			before, err := snapshotKnownVaultFiles(f.source)
			if err != nil {
				t.Fatal(err)
			}
			chooseLegacyStorageDirectory = func(context.Context) (string, error) { return selectedPath, nil }
			if selected, err := f.app.SelectLegacyStorageDirectory(); err == nil || selected.Token != "" {
				t.Fatalf("unsafe choice accepted: %+v %v", selected, err)
			}
			assertSnapshotEqual(t, f.source, before)
			if scenario == "target conflict" || scenario == "same target" {
				assertSnapshotEqual(t, f.target, f.files)
			}
		})
	}
}

func TestManualStorageSelectionCancellationExpiryAndRestart(t *testing.T) {
	f := manualStorageFixture(t, "v2")
	selected, err := f.app.SelectLegacyStorageDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.app.CancelLegacyStorageSelection(selected.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, ""); !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("cancelled choice used: %v", err)
	}
	selected, err = f.app.SelectLegacyStorageDirectory()
	if err != nil {
		t.Fatal(err)
	}
	f.app.mu.Lock()
	f.app.selectedLegacyStorage.expires = time.Now().Add(-time.Second)
	f.app.mu.Unlock()
	if _, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, ""); !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("expired choice used: %v", err)
	}
	if f.app.selectedLegacyStorage.token != "" {
		t.Fatal("expired selection was retained")
	}
	f.app.Logout()
	selected, err = f.app.SelectLegacyStorageDirectory()
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, currentCode(t, f.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.app.CancelStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	selected, err = f.app.SelectLegacyStorageDirectory()
	if err != nil {
		t.Fatal(err)
	}
	token, err = f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, currentCode(t, f.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	f.app.Logout()
	restarted := NewApp()
	if err := restarted.ConfirmStorageLocationMigration(token); !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("restarted copy accepted: %v", err)
	}
	assertSnapshotEqual(t, f.source, f.files)
	if _, err := os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancel/restart wrote target: %v", err)
	}
}

func TestNativeStorageDialogResultAfterLogoutIsDiscarded(t *testing.T) {
	f := manualStorageFixture(t, "v2")
	started, finish := make(chan struct{}), make(chan struct{})
	chooseLegacyStorageDirectory = func(context.Context) (string, error) { close(started); <-finish; return f.source, nil }
	result := make(chan error, 1)
	go func() { _, err := f.app.SelectLegacyStorageDirectory(); result <- err }()
	<-started
	f.app.Logout()
	close(finish)
	if err := <-result; !errors.Is(err, ErrVaultStorageMigrationExpired) {
		t.Fatalf("late native result accepted: %v", err)
	}
	if f.app.selectedLegacyStorage.token != "" {
		t.Fatal("late dialog restored selection")
	}
	assertSnapshotEqual(t, f.source, f.files)
}

func TestLocationOnlyChecksDoNotReadActivePayload(t *testing.T) {
	f := manualStorageFixture(t, "v2")
	if err := os.MkdirAll(f.target, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range f.files {
		writeStorageTestFile(t, filepath.Join(f.target, name), data)
	}
	reads := countStoragePayloadReads(t)
	for i := 0; i < 3; i++ {
		if dir, err := activeVaultStorageDirectory(); err != nil || dir != f.target {
			t.Fatalf("route = %q, %v", dir, err)
		}
		if status := storageLocationStatus(); status.State != "ready" || status.Format != "v2" {
			t.Fatalf("status = %+v", status)
		}
	}
	if *reads != 0 {
		t.Fatalf("routing reread payload %d times", *reads)
	}
	if _, err := f.app.LoginV2(f.password); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Verify2FA(currentCode(t, f.vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	if err := f.app.AddAccount("synthetic", "test", "not-a-real-secret"); err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Fatalf("save reread payload through location discovery %d times", *reads)
	}
	// Existing session revision checks must still detect replacement even if
	// the size and mtime match. A cheap route check does not authenticate it.
	path := filepath.Join(f.target, dataFileV2)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	writeStorageTestFile(t, path, data)
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := f.app.AddAccount("another", "test", "not-a-real-secret"); err == nil {
		t.Fatal("session overwrote substituted active vault")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(data, got) {
		t.Fatal("substituted active file was overwritten")
	}
}

func TestReceiptConflictFallbackChecksBytesWithoutMetadataCache(t *testing.T) {
	f := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
	token, err := f.app.PrepareStorageLocationMigration(f.password, currentCode(t, f.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.source, dataFileV2)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), f.files[dataFileV2]...)
	changed[len(changed)/2] ^= 1
	writeStorageTestFile(t, path, changed)
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := activeVaultStorageDirectory(); !errors.Is(err, ErrVaultStorageConflict) {
		t.Fatalf("source substitution hidden by route cache: %v", err)
	}
	assertSnapshotEqual(t, f.target, f.files)
}

func TestStorageMigrationDirectorySyncFailuresPreserveData(t *testing.T) {
	for _, afterPublish := range []bool{false, true} {
		t.Run("directory sync", func(t *testing.T) {
			f := newStorageMigrationFixture(t, "v2", syntheticMigrationVault())
			token, err := f.app.PrepareStorageLocationMigration(f.password, currentCode(t, f.vault.TwoFASecret))
			if err != nil {
				t.Fatal(err)
			}
			original := storageMigrationSyncDirectory
			storageMigrationSyncDirectory = func(path string) error {
				isParent := sameStoragePath(path, filepath.Dir(f.target))
				if afterPublish == isParent {
					return os.ErrPermission
				}
				return original(path)
			}
			t.Cleanup(func() { storageMigrationSyncDirectory = original })
			err = f.app.ConfirmStorageLocationMigration(token)
			if err == nil {
				t.Fatal("directory sync error was ignored")
			}
			if afterPublish {
				if !errors.Is(err, ErrVaultStorageCommitUncertain) {
					t.Fatalf("lost uncertain commit: %v", err)
				}
				assertSnapshotEqual(t, f.target, f.files)
			} else if _, err := os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published before sync: %v", err)
			}
			assertSnapshotEqual(t, f.source, f.files)
			if f.app.pendingStorageMigration.token != "" {
				t.Fatal("failed migration kept challenge")
			}
		})
	}
}

func TestManualStorageMigrationRejectsSourceOrDestinationChanges(t *testing.T) {
	for _, changeSource := range []bool{false, true} {
		t.Run("changes after authentication", func(t *testing.T) {
			f := manualStorageFixture(t, "v2")
			selected, err := f.app.SelectLegacyStorageDirectory()
			if err != nil {
				t.Fatal(err)
			}
			token, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, currentCode(t, f.vault.TwoFASecret))
			if err != nil {
				t.Fatal(err)
			}
			if changeSource {
				original := storageMigrationWriteFile
				storageMigrationWriteFile = func(path string, data []byte) error {
					if filepath.Base(path) == storageMigrationReceiptFile {
						// Simulate another process writing after staging begins.
						writeStorageTestFile(t, filepath.Join(f.source, dataFileV2+".bak"), []byte("changed encrypted backup"))
					}
					return original(path, data)
				}
				t.Cleanup(func() { storageMigrationWriteFile = original })
			} else {
				if err := os.MkdirAll(f.target, 0700); err != nil {
					t.Fatal(err)
				}
				writeStorageTestFile(t, filepath.Join(f.target, dataFile), []byte("existing destination"))
			}
			if err := f.app.ConfirmStorageLocationMigration(token); err == nil {
				t.Fatal("changed inputs were accepted")
			}
			if changeSource {
				f.files[dataFileV2+".bak"] = []byte("changed encrypted backup")
				if _, err := os.Stat(f.target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stale copy published: %v", err)
				}
			} else {
				got, err := os.ReadFile(filepath.Join(f.target, dataFile))
				if err != nil || string(got) != "existing destination" {
					t.Fatal("destination overwritten")
				}
			}
			assertSnapshotEqual(t, f.source, f.files)
		})
	}
}

func TestManualStorageChoiceRequiresFullyLockedSession(t *testing.T) {
	f := manualStorageFixture(t, "v2")
	f.app.v2Session = &v2VaultSession{engine: f.engine}
	f.app.vault = cloneVault(f.vault)
	f.app.twoFAVerified = false
	if _, err := f.app.SelectLegacyStorageDirectory(); !errors.Is(err, ErrVaultStorageMigrationBusy) {
		t.Fatalf("selection allowed during pending TOTP: %v", err)
	}
	assertSnapshotEqual(t, f.source, f.files)
}
