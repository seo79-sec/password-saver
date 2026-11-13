package main

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"password-saver/crypto"
)

func makeV1UIFixture(t *testing.T, vault *Vault) (*App, []byte, []byte) {
	t.Helper()
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	cm.Wipe()
	primary, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(dataFile + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVaultSelector(vaultSelectorFile, vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV1,
	}); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	app.v2Engine = migrationEngine(t)
	return app, primary, backup
}

func TestPublicVaultStatusNeverExposesSecretsOrSelectsFallback(t *testing.T) {
	app, _, _ := makeV1UIFixture(t, syntheticMigrationVault())
	status := app.GetVaultStatus()
	if status.State != VaultStateV1Active || status.V2ContainerPresent {
		t.Fatalf("initial status = %+v", status)
	}
	if err := MigrateV1VaultToV2(migrationTestPassword, app.v2Engine); err != nil {
		t.Fatal(err)
	}
	// A candidate alone cannot change a durable v1 selection.
	status = app.GetVaultStatus()
	if status.State != VaultStateV1Active || !status.V2ContainerPresent {
		t.Fatalf("candidate changed the active format: %+v", status)
	}
	service := app.v2ActivationLocked()
	token, err := service.Prepare(".", migrationTestPassword, currentCode(t, syntheticMigrationVault().TwoFASecret), app.v2Engine)
	if err != nil {
		t.Fatal(err)
	}
	status = app.GetVaultStatus()
	if status.State != VaultStateV1Prepared || !status.V2ContainerPresent || !status.PreparationFresh {
		t.Fatalf("prepared status = %+v", status)
	}
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, syntheticMigrationVault().TwoFASecret), app.v2Engine); err != nil {
		t.Fatal(err)
	}
	status = app.GetVaultStatus()
	if status.State != VaultStateV2Active || !status.V2ContainerPresent {
		t.Fatalf("active status = %+v", status)
	}
	if err := os.Remove(dataFileV2); err != nil {
		t.Fatal(err)
	}
	status = app.GetVaultStatus()
	if status.State != VaultStateV2Active || status.V2ContainerPresent {
		t.Fatalf("missing active container enabled fallback: %+v", status)
	}
	if _, err := app.LoginV2(migrationTestPassword); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("missing v2 container error = %v", err)
	}
	if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("missing active v2 container fell back to v1: %v", err)
	}
}

func TestWailsV1MigrationReauthenticatesAndActivatesOnlyAfterConfirmation(t *testing.T) {
	vault := syntheticMigrationVault()
	app, primaryBefore, backupBefore := makeV1UIFixture(t, vault)
	requiresTOTP, err := app.Login(migrationTestPassword)
	if err != nil || !requiresTOTP {
		t.Fatalf("v1 login = (%v, %v)", requiresTOTP, err)
	}
	if err := app.Verify2FA(currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PrepareV2Migration("wrong synthetic password", currentCode(t, vault.TwoFASecret)); err == nil {
		t.Fatal("migration accepted an incorrect master password")
	}
	if _, err := app.PrepareV2Migration(migrationTestPassword, "000000"); err == nil {
		t.Fatal("migration accepted an incorrect TOTP code")
	}
	token, err := app.PrepareV2Migration(migrationTestPassword, currentCode(t, vault.TwoFASecret))
	if err != nil || token == "" {
		t.Fatalf("migration preparation = (%q, %v)", token, err)
	}
	if status := app.GetVaultStatus(); status.State != VaultStateV1Prepared || !status.V2ContainerPresent || !status.PreparationFresh {
		t.Fatalf("migration result was not prepared: %+v", status)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("migration changed v1 primary or backup")
	}
	staged, err := ReadV2Vault(dataFileV2, app.v2Engine, migrationTestPassword)
	if err != nil || !reflectVaultEqual(staged, vault) {
		t.Fatalf("staged v2 data mismatch: (%#v, %v)", staged, err)
	}

	if err := app.ConfirmV2Migration(token, "wrong synthetic password", currentCode(t, vault.TwoFASecret)); err == nil {
		t.Fatal("activation accepted an incorrect master password")
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || !selection.Prepared || selection.ActiveV2 {
		t.Fatalf("failed confirmation switched selector: (%+v, %v)", selection, err)
	}

	// Prepare issues a fresh short-lived token after a failed confirmation.
	token, err = app.PrepareV2Migration(migrationTestPassword, currentCode(t, vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ConfirmV2Migration(token, migrationTestPassword, "000000"); err == nil {
		t.Fatal("activation accepted an incorrect TOTP code")
	}
	if err := app.ConfirmV2Migration(token, migrationTestPassword, currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	if !app.IsLocked() || app.cm != nil || app.vault != nil {
		t.Fatal("previous v1 session remained active after selector commit")
	}
	if status := app.GetVaultStatus(); status.State != VaultStateV2Active {
		t.Fatalf("confirmed activation status = %+v", status)
	}
	primaryAfter, _ = os.ReadFile(dataFile)
	backupAfter, _ = os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("activation changed preserved v1 files")
	}
}

func TestWailsV2LoginTOTPCRUDLogoutAndInactivity(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, _, _ := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	app.v2Engine = engine
	if _, err := app.LoginV2("incorrect synthetic master password"); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("wrong v2 password error = %v", err)
	}
	if !app.IsLocked() {
		t.Fatal("failed v2 password unlocked the app")
	}
	requiresTOTP, err := app.LoginV2(migrationTestPassword)
	if err != nil || !requiresTOTP || app.v2Session == nil || app.cm != nil {
		t.Fatalf("v2 password step = (%v, %v), session=%v", requiresTOTP, err, app.v2Session != nil)
	}
	if _, err := app.GetAccounts(); err == nil {
		t.Fatal("account API opened before TOTP")
	}
	if err := app.Verify2FA("000000"); err == nil {
		t.Fatal("wrong v2 TOTP was accepted")
	}
	if err := app.Verify2FA(currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	if err := app.AddAccount("synthetic-service", "test-user", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	accounts, err := app.GetAccounts()
	if err != nil || len(accounts) != len(vault.Accounts)+1 {
		t.Fatalf("v2 add result = (%d, %v)", len(accounts), err)
	}
	added := accounts[len(accounts)-1]
	if err := app.UpdateAccount(added.ID, "synthetic-updated", "test-user", "synthetic-updated-password"); err != nil {
		t.Fatal(err)
	}
	if err := app.DeleteAccount(added.ID); err != nil {
		t.Fatal(err)
	}
	accounts, err = app.GetAccounts()
	if err != nil || len(accounts) != len(vault.Accounts) {
		t.Fatalf("v2 CRUD result = (%d, %v)", len(accounts), err)
	}
	session := app.v2Session
	app.Logout()
	if !session.isClosed() || !app.IsLocked() {
		t.Fatal("v2 logout did not close session")
	}

	if _, err := app.LoginV2(migrationTestPassword); err != nil {
		t.Fatal(err)
	}
	if err := app.Verify2FA(currentCode(t, vault.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	session = app.v2Session
	app.mu.Lock()
	app.lastActivity = time.Now().Add(-2 * time.Minute)
	app.mu.Unlock()
	if !app.CheckInactivity() || !session.isClosed() {
		t.Fatal("v2 backend inactivity check did not lock and close the session")
	}
}

func TestWailsCancelAfterRestartOrMissingCandidateAndRefuseV2(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, primaryBefore, backupBefore := createV1AndPreparedV2(t, vault)
	_, _ = prepareActivation(t, engine, vault)
	if err := os.Remove(dataFileV2); err != nil {
		t.Fatal(err)
	}
	app := NewApp() // models a restart; only the persistent selector remains
	token, err := app.BeginCancelV2Preparation()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ConfirmCancelV2Preparation(token); err != nil {
		t.Fatal(err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("UI cancellation changed v1 files")
	}
	if status := app.GetVaultStatus(); status.State != VaultStateV1Active {
		t.Fatalf("status after cancel = %+v", status)
	}
	if err := MigrateV1VaultToV2(migrationTestPassword, engine); err != nil {
		t.Fatal(err)
	}
	service, token := prepareActivation(t, engine, vault)
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BeginCancelV2Preparation(); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("UI allowed cancel of active v2: %v", err)
	}
}
