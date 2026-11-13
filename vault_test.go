package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"password-saver/crypto"
)

//go:embed testdata/vault_data_v1_legacy.enc
var legacyVaultFixture embed.FS

func withVaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func TestSaveLoadBackupAndWrongPassword(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	first := &Vault{Accounts: []Account{{ID: "one", Password: "secret"}}}
	if err := SaveVault(cm, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "two", Password: "new"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dataFile + ".bak"); err != nil {
		t.Fatalf("encrypted backup missing: %v", err)
	}
	loaded, err := LoadVault(cm)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "two" {
		t.Fatalf("unexpected loaded vault: %#v", loaded)
	}
	wrong, _ := crypto.NewCryptoManager("incorrect horse battery staple")
	defer wrong.Wipe()
	if _, err := LoadVault(wrong); err == nil {
		t.Fatal("wrong master password accepted")
	}
}

func TestLoadVaultRejectsDamagedAndOversizedFiles(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	for _, data := range [][]byte{[]byte("not a valid signed vault"), bytes.Repeat([]byte("x"), maxVaultFileSize+1)} {
		if err := os.WriteFile(dataFile, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVault(cm); err == nil {
			t.Fatal("LoadVault accepted damaged or oversized file")
		}
	}
}

func TestLoadVaultRequiresConfirmationAndArchivesCorruptPrimary(t *testing.T) {
	for _, primary := range []string{"missing", "corrupt"} {
		t.Run(primary, func(t *testing.T) {
			withVaultDir(t)
			cm, _ := crypto.NewCryptoManager("correct horse battery staple")
			defer cm.Wipe()
			want := &Vault{Accounts: []Account{{ID: "from-backup", Password: "secret"}}}
			if err := SaveVault(cm, want); err != nil {
				t.Fatal(err)
			}
			backup, err := os.ReadFile(dataFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dataFile+".bak", backup, 0600); err != nil {
				t.Fatal(err)
			}
			if primary == "missing" {
				if err := os.Remove(dataFile); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(dataFile, []byte("truncated"), 0600); err != nil {
				t.Fatal(err)
			}
			originalPrimary, _ := os.ReadFile(dataFile)
			_, err = LoadVault(cm)
			if !errors.Is(err, errVaultRecoveryAvailable) {
				t.Fatalf("LoadVault error = %v, want explicit recovery decision", err)
			}
			unchanged, readErr := os.ReadFile(dataFile)
			if primary == "missing" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("missing primary changed: %v", readErr)
				}
			} else if readErr != nil || !bytes.Equal(unchanged, originalPrimary) {
				t.Fatal("corrupt primary was modified before confirmation")
			}
			app := NewApp()
			token, err := app.PrepareVaultRecovery("correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			requires2FA, err := app.ConfirmVaultRecovery(token)
			if err != nil || requires2FA {
				t.Fatalf("ConfirmVaultRecovery = (%v, %v)", requires2FA, err)
			}
			if len(app.vault.Accounts) != 1 || app.vault.Accounts[0].ID != "from-backup" {
				t.Fatalf("unexpected recovered vault: %#v", app.vault)
			}
			restored, err := os.ReadFile(dataFile)
			if err != nil || !bytes.Equal(restored, backup) {
				t.Fatalf("backup not restored: %v", err)
			}
			if primary == "corrupt" {
				archives, err := filepath.Glob(dataFile + ".corrupt-*")
				if err != nil || len(archives) != 1 {
					t.Fatalf("diagnostic archive missing: %v (%v)", archives, err)
				}
				archived, err := os.ReadFile(archives[0])
				if err != nil || !bytes.Equal(archived, originalPrimary) {
					t.Fatal("corrupt original was not retained for diagnostics")
				}
			}
		})
	}
}

func TestLegacyVaultFixtureRemainsReadable(t *testing.T) {
	withVaultDir(t)
	fixture, err := legacyVaultFixture.ReadFile("testdata/vault_data_v1_legacy.enc")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	cm, err := crypto.NewCryptoManager("legacy-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Wipe()
	loaded, err := LoadVault(cm)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "legacy-account" || loaded.Accounts[0].Password != "legacy-fixture-password" {
		t.Fatalf("legacy fixture was not decoded: %#v", loaded)
	}
}

func TestWrongPasswordDoesNotRestoreBackupOverPrimary(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "old"}}}); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "current"}}}); err != nil {
		t.Fatal(err)
	}
	primaryBefore, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := crypto.NewCryptoManager("incorrect horse battery staple")
	defer wrong.Wipe()
	if _, err := LoadVault(wrong); err == nil {
		t.Fatal("wrong password accepted")
	}
	primaryAfter, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(primaryBefore, primaryAfter) {
		t.Fatal("wrong password caused backup restoration over a valid primary")
	}
}

func TestRecoveryRequiresBackupPasswordAndPreservesDamagedPrimary(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "backup"}}}); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile+".bak", backup, 0600); err != nil {
		t.Fatal(err)
	}
	damaged := []byte("damaged original for diagnostics")
	if err := os.WriteFile(dataFile, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if _, err := app.PrepareVaultRecovery("incorrect horse battery staple"); err == nil {
		t.Fatal("recovery accepted incorrect master password")
	}
	contents, err := os.ReadFile(dataFile)
	if err != nil || !bytes.Equal(contents, damaged) {
		t.Fatal("failed verification modified the damaged primary")
	}
}

func TestSaveVaultWriteFailurePreservesPreviousFile(t *testing.T) {
	dir := withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	oldVault := &Vault{Accounts: []Account{{ID: "original"}}}
	path := filepath.Join(dir, dataFile)
	if err := saveVaultToPath(path, cm, oldVault); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldRename := replaceVaultFile
	defer func() { replaceVaultFile = oldRename }()
	failed := false
	replaceVaultFile = func(src, dst string) error {
		if strings.HasPrefix(filepath.Base(src), ".vault-write-") && dst == path {
			failed = true
			return os.ErrPermission
		}
		return os.Rename(src, dst)
	}
	if err := saveVaultToPath(path, cm, &Vault{Accounts: []Account{{ID: "replacement"}}}); err == nil {
		t.Fatal("expected injected replacement failure")
	}
	if !failed {
		t.Fatal("write failure injection was not reached")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed save changed the previous container")
	}
}

func TestAtomicWriteChecksFileAndDirectorySyncErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dataFile)
	old := []byte("old encrypted payload")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	oldFileSync, oldDirSync := syncVaultTempFile, syncVaultDirectory
	t.Cleanup(func() { syncVaultTempFile, syncVaultDirectory = oldFileSync, oldDirSync })
	syncVaultTempFile = func(*os.File) error { return errors.New("injected file sync failure") }
	if err := writeFileAtomic(path, []byte("new encrypted payload")); err == nil {
		t.Fatal("file sync failure was ignored")
	}
	contents, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(contents, old) {
		t.Fatal("file changed after pre-commit sync failure")
	}

	syncVaultTempFile = func(f *os.File) error { return f.Sync() }
	syncVaultDirectory = func(string) error { return errors.New("injected directory sync failure") }
	err = writeFileAtomic(path, []byte("new encrypted payload"))
	if !errors.Is(err, errVaultCommitUncertain) {
		t.Fatalf("directory sync error = %v, want uncertain commit", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(contents, []byte("new encrypted payload")) {
		t.Fatal("post-replacement sync error did not leave visible new file")
	}
}

func TestConcurrentVaultLoadAndSave(t *testing.T) {
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Wipe()
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "initial"}}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for worker := 0; worker < 12; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			if worker%2 == 0 {
				errs <- SaveVault(cm, &Vault{Accounts: []Account{{ID: fmt.Sprintf("worker-%d", worker)}}})
				return
			}
			_, err := LoadVault(cm)
			errs <- err
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
