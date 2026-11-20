package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	cryptov2 "password-saver/crypto/v2"
)

func createTestRecoveryKey(t *testing.T, app *App, code string) string {
	t.Helper()
	key, err := app.CreateRecoveryKey(migrationTestPassword, code)
	if err != nil || key == "" {
		t.Fatalf("creating recovery key: %v", err)
	}
	return key
}

func TestRecoveryKeyLifecycleRevokesLiveDEKAndPreservesCopies(t *testing.T) {
	app, engine, _ := passwordChangeFixture(t, false)
	before := importFileSnapshot(t, ".")
	if key, err := app.CreateRecoveryKey("incorrect synthetic password", ""); key != "" || !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("wrong password enrollment: %v", err)
	}
	expectImportSnapshot(t, ".", before)
	old := createTestRecoveryKey(t, app, "")
	original := readPasswordChangeTestFile(t, dataFileV2)
	assertRecoveryKeyArchive(t, dataFileV2, before[dataFileV2])
	assertRecoveryKeyArchive(t, dataFileV2+".bak", before[dataFileV2+".bak"])
	assertFileBytes(t, dataFileV2+".bak", original)
	assertFileBytes(t, vaultSelectorFile, before[vaultSelectorFile])
	verified := importFileSnapshot(t, ".")
	if err := app.VerifyRecoveryKey(migrationTestPassword, "", old); err != nil {
		t.Fatal(err)
	}
	expectImportSnapshot(t, ".", verified)
	if app.IsLocked() || app.AddAccount("post-enrollment synthetic entry", "", "synthetic-entry-only") != nil {
		t.Fatal("new session cannot save")
	}
	mostRecent := readPasswordChangeTestFile(t, dataFileV2)
	pub, err := engine.DecryptWithRecoveryKey(old, mostRecent)
	if err != nil || !bytes.Contains(pub, []byte("post-enrollment synthetic entry")) {
		t.Fatal("CRUD did not maintain the recovery slot")
	}
	wipeBytes(pub)
	rotated := createTestRecoveryKey(t, app, "")
	if old == rotated || bytes.Equal(mostRecent, readPasswordChangeTestFile(t, dataFileV2)) {
		t.Fatal("rotation did not produce new keys")
	}
	for _, path := range []string{dataFileV2, dataFileV2 + ".bak"} {
		if _, err := engine.DecryptWithRecoveryKey(old, readPasswordChangeTestFile(t, path)); !errors.Is(err, cryptov2.ErrRecoveryKeyInvalid) {
			t.Fatalf("revoked key opened %s: %v", path, err)
		}
	}
	if previous, err := engine.DecryptWithRecoveryKey(old, original); err != nil {
		t.Fatalf("older copy did not remain readable: %v", err)
	} else {
		wipeBytes(previous)
	}
	if err := app.DisableRecoveryKey(migrationTestPassword, ""); err != nil {
		t.Fatal(err)
	}
	app.Logout()
	for _, path := range []string{dataFileV2, dataFileV2 + ".bak"} {
		newData := readPasswordChangeTestFile(t, path)
		if _, err := engine.DecryptWithRecoveryKey(rotated, newData); !errors.Is(err, cryptov2.ErrRecoveryKeyUnavailable) {
			t.Fatalf("disabled key opened %s: %v", path, err)
		}
	}
	// An explicitly supplied old .bak cannot roll back revocation while the
	// primary is still present and structurally valid.
	if err := os.WriteFile(dataFileV2+".bak", original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareRecoveryKeyReset(old, "", rotatedTestPassword, rotatedTestPassword, true); !errors.Is(err, errRecoveryKeyUnavailable) {
		t.Fatalf("disabled key used stale backup: %v", err)
	}
	reopened := passwordChangeApp(t, engine)
	if needs, err := reopened.LoginV2(migrationTestPassword); needs || err != nil {
		t.Fatalf("password login after disable: %v, %v", needs, err)
	}
}

func TestRecoveryKeyResetRequiresTOTPAndSurvivesRestart(t *testing.T) {
	app, engine, original := passwordChangeFixture(t, true)
	code := func() string { return currentCode(t, original.TwoFASecret) }
	if _, err := app.CreateRecoveryKey(migrationTestPassword, ""); err == nil {
		t.Fatal("enrollment skipped TOTP")
	}
	key := createTestRecoveryKey(t, app, code())
	if _, err := app.PrepareRecoveryKeyReset(key, code(), rotatedTestPassword, rotatedTestPassword, false); !errors.Is(err, errRecoveryKeySession) {
		t.Fatalf("active session reset: %v", err)
	}
	app.Logout()
	if needed, err := app.LoginV2(migrationTestPassword); err != nil || !needed {
		t.Fatal("login did not wait for TOTP")
	}
	if _, err := app.PrepareRecoveryKeyReset(key, code(), rotatedTestPassword, rotatedTestPassword, false); !errors.Is(err, errRecoveryKeySession) {
		t.Fatalf("overlapping TOTP session: %v", err)
	}
	app.Logout()
	before := importFileSnapshot(t, ".")
	if _, err := app.BeginVaultReset(); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("v1 reset accepted active v2: %v", err)
	}
	if _, err := app.PrepareRecoveryKeyReset("invalid-key", code(), rotatedTestPassword, rotatedTestPassword, false); !errors.Is(err, errRecoveryKeyInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	for i := 0; i < maxTOTPFailures; i++ {
		if _, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, false); err == nil {
			t.Fatal("reset skipped second factor")
		}
	}
	if _, err := app.PrepareRecoveryKeyReset(key, code(), rotatedTestPassword, rotatedTestPassword, false); err == nil {
		t.Fatal("reset skipped TOTP rate limit")
	}
	expectImportSnapshot(t, ".", before)
	app.mu.Lock()
	app.totpBlockedUntil = time.Now().Add(-time.Second)
	app.mu.Unlock()
	prepare := func() string {
		t.Helper()
		token, err := app.PrepareRecoveryKeyReset(key, code(), rotatedTestPassword, rotatedTestPassword, false)
		if token == "" || err != nil {
			t.Fatalf("reset preparation: %v", err)
		}
		expectImportSnapshot(t, ".", before)
		return token
	}
	token := prepare()
	app.CancelRecoveryKeyReset(token)
	if err := app.ConfirmRecoveryKeyReset(token); !errors.Is(err, errRecoveryKeyExpired) {
		t.Fatalf("cancelled confirmation: %v", err)
	}
	token = prepare()
	app.mu.Lock()
	app.pendingRecoveryKey.expires = time.Now().Add(-time.Second)
	app.mu.Unlock()
	if err := app.ConfirmRecoveryKeyReset(token); !errors.Is(err, errRecoveryKeyExpired) {
		t.Fatalf("expired confirmation: %v", err)
	}
	expectImportSnapshot(t, ".", before)
	token = prepare()
	if err := app.ConfirmRecoveryKeyReset(token); err != nil || !app.IsLocked() {
		t.Fatalf("reset result: %v", err)
	}
	assertRecoveryKeyArchive(t, dataFileV2, before[dataFileV2])
	assertRecoveryKeyArchive(t, dataFileV2+".bak", before[dataFileV2+".bak"])
	assertFileBytes(t, vaultSelectorFile, before[vaultSelectorFile])
	assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, original)
	assertPasswordChangeVault(t, engine, dataFileV2+".bak", rotatedTestPassword, original)
	reopened := passwordChangeApp(t, engine)
	if _, err := reopened.LoginV2(migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("old password after reset: %v", err)
	}
	if _, err := reopened.PrepareRecoveryKeyReset(key, code(), "another synthetic password", "another synthetic password", false); !errors.Is(err, errRecoveryKeyUnavailable) {
		t.Fatalf("reused recovery key: %v", err)
	}
	loginForPasswordChange(t, reopened, rotatedTestPassword, original)
}

func TestRecoveryKeyBackupRepairsOnlyExplicitlyAndPreservesDamage(t *testing.T) {
	for _, name := range []string{"intact", "missing", "empty", "damaged tag", "unknown version", "unknown recovery slot"} {
		t.Run(name, func(t *testing.T) {
			app, engine, original := passwordChangeFixture(t, false)
			key := createTestRecoveryKey(t, app, "")
			app.Logout()
			good := readPasswordChangeTestFile(t, dataFileV2)
			var changed []byte
			want := error(nil)
			switch name {
			case "intact":
				changed, want = good, errRecoveryKeyUsePrimary
			case "missing":
				if err := os.Remove(dataFileV2); err != nil {
					t.Fatal(err)
				}
			case "empty":
				changed = []byte{}
			case "damaged tag":
				changed = damageV2Tag(good)
			case "unknown version":
				changed, want = append([]byte(`{"format":"passwordsaver-v2","version":99,`), ' '), ErrVaultUnsupportedFormat
			case "unknown recovery slot":
				changed, want = bytes.Replace(good, []byte(`"recovery":{"version":1`), []byte(`"recovery":{"version":99`), 1), ErrVaultUnsupportedFormat
			}
			if changed != nil {
				if err := os.WriteFile(dataFileV2, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := importFileSnapshot(t, ".")
			token, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, true)
			expectImportSnapshot(t, ".", before)
			if want != nil {
				if token != "" || !errors.Is(err, want) {
					t.Fatalf("backup preparation: %v", err)
				}
				return
			}
			if err != nil || token == "" {
				t.Fatalf("backup preparation: %v", err)
			}
			if err := app.ConfirmRecoveryKeyReset(token); err != nil {
				t.Fatal(err)
			}
			if changed != nil {
				assertRecoveryKeyArchive(t, dataFileV2, changed)
			}
			assertRecoveryKeyArchive(t, dataFileV2+".bak", before[dataFileV2+".bak"])
			assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, original)
		})
	}
}

func TestRecoveryKeyBackupUsesTheExplicitlySelectedSnapshotsTOTP(t *testing.T) {
	app, engine, original := passwordChangeFixture(t, false)
	key := createTestRecoveryKey(t, app, "")
	secret := "KRUGS4ZANFZSAYJA"
	if err := app.ConfirmAndEnable2FA(secret, currentCode(t, secret)); err != nil {
		t.Fatal(err)
	}
	app.Logout()
	primary := readPasswordChangeTestFile(t, dataFileV2)
	if _, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, true); !errors.Is(err, errRecoveryKeyUsePrimary) {
		t.Fatalf("intact TOTP-enabled primary could be rolled back: %v", err)
	}
	if _, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, false); err == nil {
		t.Fatal("primary opened without TOTP")
	}
	if err := os.WriteFile(dataFileV2, damageV2Tag(primary), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, true)
	if err != nil {
		t.Fatalf("explicit recovery of the earlier TOTP-off snapshot: %v", err)
	}
	if err := app.ConfirmRecoveryKeyReset(token); err != nil {
		t.Fatal(err)
	}
	assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, original)
}

func TestRecoveryKeyResetRejectsChangedFilesAndHandlesWriteFailures(t *testing.T) {
	for _, name := range []string{"primary replaced", "changed backup", "backup rename", "primary rename", "primary sync"} {
		t.Run(name, func(t *testing.T) {
			app, engine, original := passwordChangeFixture(t, false)
			key := createTestRecoveryKey(t, app, "")
			app.Logout()
			token, err := app.PrepareRecoveryKeyReset(key, "", rotatedTestPassword, rotatedTestPassword, false)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "primary replaced":
				// Equal bytes are insufficient if the selected file is replaced.
				current := readPasswordChangeTestFile(t, dataFileV2)
				other := filepath.Join(".", "substitute.enc")
				if err := os.WriteFile(other, current, 0600); err != nil {
					t.Fatal(err)
				}
				if err := replaceVaultFile(other, dataFileV2); err != nil {
					t.Fatal(err)
				}
			case "changed backup":
				if err := os.WriteFile(dataFileV2+".bak", []byte("synthetic substitution"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := importFileSnapshot(t, ".")
			failed := errors.New("synthetic failure")
			rename, syncDirectory := replaceVaultFile, syncVaultDirectory
			restore := func() { replaceVaultFile, syncVaultDirectory = rename, syncDirectory }
			t.Cleanup(restore)
			replaceVaultFile = func(from, to string) error {
				if (name == "backup rename" && filepath.Base(to) == dataFileV2+".bak") ||
					(name == "primary rename" && filepath.Base(to) == dataFileV2) {
					return failed
				}
				return rename(from, to)
			}
			call := 0
			syncVaultDirectory = func(dir string) error {
				call++
				if name == "primary sync" && call == 4 {
					return failed
				} // two archives and two operational files
				return syncDirectory(dir)
			}
			err = app.ConfirmRecoveryKeyReset(token)
			restore()
			if name == "primary replaced" || name == "changed backup" {
				if !errors.Is(err, ErrVaultSessionChanged) {
					t.Fatalf("substituted revision: %v", err)
				}
				expectImportSnapshot(t, ".", before)
				return
			}
			if !errors.Is(err, errRecoveryKeyCommit) || !app.IsLocked() ||
				app.pendingRecoveryKey.token != "" {
				t.Fatalf("write failure: %v", err)
			}
			assertRecoveryKeyArchive(t, dataFileV2, before[dataFileV2])
			assertRecoveryKeyArchive(t, dataFileV2+".bak", before[dataFileV2+".bak"])
			assertFileBytes(t, vaultSelectorFile, before[vaultSelectorFile])
			switch name {
			case "backup rename":
				assertFileBytes(t, dataFileV2, before[dataFileV2])
				assertFileBytes(t, dataFileV2+".bak", before[dataFileV2+".bak"])
			case "primary rename":
				assertFileBytes(t, dataFileV2, before[dataFileV2])
				assertPasswordChangeVault(t, engine, dataFileV2+".bak", rotatedTestPassword, original)
				// The existing password-based repair opens the newly durable backup.
				repair, err := app.PrepareV2VaultRecovery(rotatedTestPassword)
				if err != nil || repair == "" {
					t.Fatalf("password recovery after interrupted write: %v", err)
				}
				app.CancelV2VaultRecovery(repair)
			case "primary sync":
				assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, original)
				assertPasswordChangeVault(t, engine, dataFileV2+".bak", rotatedTestPassword, original)
			}
		})
	}
}

func assertRecoveryKeyArchive(t *testing.T, path string, expected []byte) {
	t.Helper()
	for name, data := range importFileSnapshot(t, filepath.Dir(path)) {
		matched, err := filepath.Match(filepath.Base(path)+".pre-restore-*", name)
		if err == nil && matched && bytes.Equal(data, expected) {
			return
		}
	}
	t.Fatalf("archive for %s does not match its old encrypted bytes", path)
}
