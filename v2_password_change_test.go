package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

const rotatedTestPassword = "synthetic-replacement-master-password"

func passwordChangeFixture(t *testing.T, useTOTP bool) (*App, *cryptov2.Engine, *Vault) {
	t.Helper()
	withVaultDir(t)
	engine := migrationEngine(t)
	vault := syntheticMigrationVault()
	if !useTOTP {
		vault.TwoFAEnabled, vault.TwoFASecret = false, ""
	}
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, &Vault{}); err != nil {
		t.Fatal(err)
	}
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, vault); err != nil {
		t.Fatal(err)
	}
	if err := writeVaultSelector(vaultSelectorFile, vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV2,
		NativeV2: true, ActivatedV2SHA256: digestHex(readPasswordChangeTestFile(t, dataFileV2)),
	}); err != nil {
		t.Fatal(err)
	}
	app := passwordChangeApp(t, engine)
	loginForPasswordChange(t, app, migrationTestPassword, vault)
	return app, engine, vault
}

func passwordChangeApp(t *testing.T, engine *cryptov2.Engine) *App {
	t.Helper()
	app := NewApp()
	app.v2Engine = engine
	t.Cleanup(app.Logout)
	return app
}

func loginForPasswordChange(t *testing.T, app *App, password string, vault *Vault) {
	t.Helper()
	needsTOTP, err := app.LoginV2(password)
	if err != nil || needsTOTP != vault.TwoFAEnabled {
		t.Fatalf("login = (%v, %v)", needsTOTP, err)
	}
	if needsTOTP {
		if _, err := app.GetAccounts(); err == nil {
			t.Fatal("accounts exposed before the second factor")
		}
		if err := app.Verify2FA(currentCode(t, vault.TwoFASecret)); err != nil {
			t.Fatal(err)
		}
	}
}

func readPasswordChangeTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertPasswordChangeFile(t *testing.T, path string, expected []byte) {
	t.Helper()
	if !bytes.Equal(readPasswordChangeTestFile(t, path), expected) {
		t.Fatalf("%s differs from expected bytes", path)
	}
}

func assertPasswordChangeLocked(t *testing.T, app *App, session *v2VaultSession) {
	t.Helper()
	if !app.IsLocked() || !session.isClosed() || app.v2Session != nil || app.vault != nil || app.twoFAVerified {
		t.Fatal("session data or authorization survived rotation")
	}
}

func assertPasswordChangeVault(t *testing.T, engine *cryptov2.Engine, path, password string, want *Vault) {
	t.Helper()
	got, err := ReadV2Vault(path, engine, password)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s did not open with all original data: %v", path, err)
	}
}

func TestMasterPasswordChangePreservesPayloadTOTPAndLegacyFiles(t *testing.T) {
	want := syntheticMigrationVault()
	app, engine := activatedV2App(t, want)
	defer app.Logout()
	session := app.v2Session
	primary := readPasswordChangeTestFile(t, dataFileV2)
	untouched := map[string][]byte{}
	for _, name := range []string{dataFile, dataFile + ".bak", vaultSelectorFile} {
		untouched[name] = readPasswordChangeTestFile(t, name)
	}
	err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, currentCode(t, want.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	assertPasswordChangeLocked(t, app, session)
	rotated := readPasswordChangeTestFile(t, dataFileV2)
	assertPasswordChangeFile(t, dataFileV2+".bak", rotated)
	var before, after cryptov2.Container
	if json.Unmarshal(primary, &before) != nil || json.Unmarshal(rotated, &after) != nil {
		t.Fatal("cannot decode container headers")
	}
	if before.Ciphertext != after.Ciphertext || before.Nonce != after.Nonce ||
		before.Format != after.Format || before.Version != after.Version || before.AEAD != after.AEAD {
		t.Fatal("payload or content algorithm changed")
	}
	if before.WrappedDEK == after.WrappedDEK || before.WrapNonce == after.WrapNonce || before.KDF.Salt == after.KDF.Salt {
		t.Fatal("DEK wrapper, wrapper nonce or salt was not refreshed")
	}
	for name, data := range untouched {
		assertPasswordChangeFile(t, name, data)
	}
	for _, name := range []string{dataFileV2, dataFileV2 + ".bak"} {
		if _, err := ReadV2Vault(name, engine, migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
			t.Fatalf("old password accepted or unexpected error for %s: %v", name, err)
		}
		assertPasswordChangeVault(t, engine, name, rotatedTestPassword, want)
	}

	reopened := passwordChangeApp(t, engine)
	if _, err := reopened.LoginV2(migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("old password login = %v", err)
	}
	loginForPasswordChange(t, reopened, rotatedTestPassword, want)
	if err := reopened.AddAccount("Synthetic new", "test", "synthetic added after change"); err != nil {
		t.Fatal(err)
	}
	// A subsequent ordinary save must keep the new wrapper in both revisions.
	assertPasswordChangeFile(t, dataFileV2+".bak", rotated)
	afterCRUD := cloneVault(reopened.vault)
	assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, afterCRUD)
	if _, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("CRUD brought back old wrapping: %v", err)
	}
	reopened.Logout()
	corruptV2Primary(t)
	prepared, err := reopened.PrepareV2VaultRecovery(rotatedTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.RequiresTOTP {
		t.Fatal("backup lost TOTP after rotation")
	}
	if _, err := reopened.GetAccounts(); err == nil {
		t.Fatal("backup preparation bypassed TOTP")
	}
	if err := reopened.ConfirmV2VaultRecovery(prepared.Token, currentCode(t, want.TwoFASecret)); err != nil {
		t.Fatalf("recover with TOTP: %v", err)
	}
	assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, want)
}

func TestMasterPasswordChangeRejectsInvalidAndRateLimitedRequests(t *testing.T) {
	app, _, vault := passwordChangeFixture(t, true)
	primary := readPasswordChangeTestFile(t, dataFileV2)
	backup := readPasswordChangeTestFile(t, dataFileV2+".bak")
	check := func(current, next, confirmation, code string, want error) {
		t.Helper()
		if err := app.ChangeMasterPassword(current, next, confirmation, code); !errors.Is(err, want) {
			t.Fatalf("change password = %v; expected %v", err, want)
		}
	}
	code := currentCode(t, vault.TwoFASecret)
	check(migrationTestPassword, "🔑🔑🔑", "🔑🔑🔑", code, errPasswordChangeShort)
	check(migrationTestPassword, rotatedTestPassword, "different synthetic password", code, errPasswordChangeMismatch)
	check(migrationTestPassword, migrationTestPassword, migrationTestPassword, code, errPasswordChangeSame)
	check("wrong synthetic password", rotatedTestPassword, rotatedTestPassword, code, ErrVaultV2Authentication)
	for attempt := 1; attempt <= maxTOTPFailures; attempt++ {
		if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, "invalid"); err == nil || err.Error() != "неверный код 2FA" {
			t.Fatalf("TOTP attempt %d: %v", attempt, err)
		}
	}
	blockedUntil := app.totpBlockedUntil
	if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, code); err == nil || !strings.Contains(err.Error(), "слишком много") {
		t.Fatalf("valid TOTP during lockout: %v", err)
	}
	if !app.totpBlockedUntil.Equal(blockedUntil) || app.IsLocked() {
		t.Fatal("an invalid request reset lockout or closed a valid session")
	}
	app.Logout()
	check(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, code, errPasswordChangeLocked)
	// Expire the test deadline without sleeping. A password-only session cannot rotate.
	app.totpBlockedUntil = time.Now().Add(-time.Second)
	if needsTOTP, err := app.LoginV2(migrationTestPassword); err != nil || !needsTOTP {
		t.Fatalf("pending session = (%v, %v)", needsTOTP, err)
	}
	check(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, code, errPasswordChangeLocked)
	assertPasswordChangeFile(t, dataFileV2, primary)
	assertPasswordChangeFile(t, dataFileV2+".bak", backup)
}

func TestMasterPasswordChangeRequiresV2(t *testing.T) {
	withVaultDir(t)
	manager, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	if err := SaveVault(manager, &Vault{}); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	defer app.Logout()
	if _, err := app.Login(migrationTestPassword); err != nil {
		t.Fatal(err)
	}
	before := readPasswordChangeTestFile(t, dataFile)
	if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, ""); !errors.Is(err, errPasswordChangeRequiresV2) {
		t.Fatalf("v1 password rotation = %v", err)
	}
	assertPasswordChangeFile(t, dataFile, before)
}

func TestMasterPasswordChangeCreatesMissingBackup(t *testing.T) {
	app, engine, want := passwordChangeFixture(t, false)
	if err := os.Remove(dataFileV2 + ".bak"); err != nil {
		t.Fatal(err)
	}
	if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, ""); err != nil {
		t.Fatal(err)
	}
	assertPasswordChangeVault(t, engine, dataFileV2+".bak", rotatedTestPassword, want)
}

func TestMasterPasswordChangeRejectsRevisionStaleBeforeRequest(t *testing.T) {
	app, engine, _ := passwordChangeFixture(t, false)
	session := app.v2Session
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, &Vault{}); err != nil {
		t.Fatal(err)
	}
	primary := readPasswordChangeTestFile(t, dataFileV2)
	backup := readPasswordChangeTestFile(t, dataFileV2+".bak")
	if err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, ""); !errors.Is(err, ErrVaultSessionChanged) {
		t.Fatalf("stale change: %v", err)
	}
	assertPasswordChangeLocked(t, app, session)
	assertPasswordChangeFile(t, dataFileV2, primary)
	assertPasswordChangeFile(t, dataFileV2+".bak", backup)
}

func TestMasterPasswordChangeWriteFailuresLeaveRecoverableRevisions(t *testing.T) {
	stages := []string{"file-sync", "replace", "directory-sync"}
	for file := 1; file <= 2; file++ {
		for _, stage := range stages {
			t.Run(fmt.Sprintf("file-%d/%s", file, stage), func(t *testing.T) {
				app, engine, want := passwordChangeFixture(t, false)
				session := app.v2Session
				primary := readPasswordChangeTestFile(t, dataFileV2)
				backup := readPasswordChangeTestFile(t, dataFileV2+".bak")
				selector := readPasswordChangeTestFile(t, vaultSelectorFile)
				injected := errors.New("synthetic interrupted write")
				fileSync, replace, dirSync := syncVaultTempFile, replaceVaultFile, syncVaultDirectory
				restore := func() { syncVaultTempFile, replaceVaultFile, syncVaultDirectory = fileSync, replace, dirSync }
				t.Cleanup(restore)
				calls := 0
				fail := func(at string) bool {
					if stage != at {
						return false
					}
					calls++
					return calls == file
				}
				syncVaultTempFile = func(f *os.File) error {
					if fail("file-sync") {
						return injected
					}
					return fileSync(f)
				}
				replaceVaultFile = func(from, to string) error {
					if fail("replace") {
						return injected
					}
					return replace(from, to)
				}
				syncVaultDirectory = func(dir string) error {
					if fail("directory-sync") {
						return injected
					}
					return dirSync(dir)
				}

				err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, "")
				restore()
				if !errors.Is(err, errPasswordChangeUnconfirmed) {
					t.Fatalf("interrupted change did not report uncertainty: %v", err)
				}
				assertPasswordChangeLocked(t, app, session)
				assertPasswordChangeFile(t, vaultSelectorFile, selector)
				backupUpdated := file == 2 || stage == "directory-sync"
				primaryUpdated := file == 2 && stage == "directory-sync"

				reopened := passwordChangeApp(t, engine)
				if primaryUpdated {
					loginForPasswordChange(t, reopened, rotatedTestPassword, want)
					assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, want)
				} else {
					assertPasswordChangeFile(t, dataFileV2, primary)
					loginForPasswordChange(t, reopened, migrationTestPassword, want)
					reopened.Logout()
				}
				if !backupUpdated {
					assertPasswordChangeFile(t, dataFileV2+".bak", backup)
				} else {
					assertPasswordChangeVault(t, engine, dataFileV2+".bak", rotatedTestPassword, want)
					if !primaryUpdated {
						prepared, err := reopened.PrepareV2VaultRecovery(rotatedTestPassword)
						if err != nil {
							t.Fatalf("fresh process could not prepare recovery: %v", err)
						}
						if prepared.RequiresTOTP {
							t.Fatal("unexpected second factor for the synthetic backup")
						}
						if err := reopened.ConfirmV2VaultRecovery(prepared.Token, ""); err != nil {
							t.Fatalf("resume from new backup: %v", err)
						}
						assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, want)
					}
				}
			})
		}
	}
}

func TestMasterPasswordChangeDetectsFileReplacementAtCommit(t *testing.T) {
	for _, path := range []string{dataFileV2, dataFileV2 + ".bak", vaultSelectorFile} {
		t.Run(path, func(t *testing.T) {
			app, _, _ := passwordChangeFixture(t, false)
			session := app.v2Session
			original := map[string][]byte{}
			for _, name := range []string{dataFileV2, dataFileV2 + ".bak", vaultSelectorFile} {
				original[name] = readPasswordChangeTestFile(t, name)
			}
			external := []byte("synthetic external write")
			fileSync := syncVaultTempFile
			t.Cleanup(func() { syncVaultTempFile = fileSync })
			syncVaultTempFile = func(f *os.File) error {
				if err := os.WriteFile(path, external, 0600); err != nil {
					return err
				}
				return fileSync(f)
			}
			err := app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, "")
			if !errors.Is(err, errPasswordChangeUnconfirmed) {
				t.Fatalf("external edit was not detected: %v", err)
			}
			assertPasswordChangeLocked(t, app, session)
			original[path] = external
			for name, data := range original {
				assertPasswordChangeFile(t, name, data)
			}
		})
	}
}

func TestMasterPasswordChangeSerializesCRUDLogoutAndIdleCheck(t *testing.T) {
	app, engine, want := passwordChangeFixture(t, false)
	session := app.v2Session
	replace := replaceVaultFile
	t.Cleanup(func() { replaceVaultFile = replace })
	reached, proceed := make(chan struct{}), make(chan struct{})
	replaceVaultFile = func(from, to string) error {
		if strings.HasSuffix(to, ".bak") {
			close(reached)
			<-proceed
		}
		return replace(from, to)
	}
	change := make(chan error, 1)
	go func() {
		change <- app.ChangeMasterPassword(migrationTestPassword, rotatedTestPassword, rotatedTestPassword, "")
	}()
	select {
	case <-reached:
	case err := <-change:
		t.Fatalf("rotation did not reach the first replacement: %v", err)
	case <-time.After(10 * time.Second):
		close(proceed)
		t.Fatal("rotation timed out")
	}
	crud := make(chan error, 1)
	logout, idle := make(chan struct{}), make(chan bool, 1)
	go func() { crud <- app.AddAccount("Synthetic concurrent", "", "synthetic concurrent password") }()
	go func() { app.Logout(); close(logout) }()
	go func() { idle <- app.CheckInactivity() }()
	close(proceed)
	select {
	case err := <-change:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rotation and session operations deadlocked")
	}
	if err := <-crud; err == nil {
		t.Fatal("CRUD wrote using the session closed by rotation")
	}
	<-logout
	if !<-idle {
		t.Fatal("idle check observed an open session after rotation")
	}
	assertPasswordChangeLocked(t, app, session)
	assertPasswordChangeVault(t, engine, dataFileV2, rotatedTestPassword, want)
}
