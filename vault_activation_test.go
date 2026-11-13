package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func createV1AndPreparedV2(t *testing.T, vault *Vault) (*cryptov2.Engine, *crypto.CryptoManager, []byte, []byte) {
	t.Helper()
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cm.Wipe)
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	primary, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(dataFile + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	engine := migrationEngine(t)
	if err := MigrateV1VaultToV2(migrationTestPassword, engine); err != nil {
		t.Fatal(err)
	}
	return engine, cm, primary, backup
}

func prepareActivation(t *testing.T, engine *cryptov2.Engine, vault *Vault) (*v2ActivationService, string) {
	t.Helper()
	service := &v2ActivationService{}
	code := ""
	if vault.TwoFAEnabled {
		code = currentCode(t, vault.TwoFASecret)
	}
	token, err := service.Prepare(".", migrationTestPassword, code, engine)
	if err != nil {
		t.Fatal(err)
	}
	return service, token
}

func TestVaultSelectionRefusesAmbiguousOrCorruptState(t *testing.T) {
	withVaultDir(t)
	selection, err := ResolveVaultSelection(".")
	if err != nil || selection.ActiveV2 || selection.Prepared || !selection.NeedsV1Record {
		t.Fatalf("legacy-only selection = (%+v, %v)", selection, err)
	}
	engine := migrationEngine(t)
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, &Vault{Accounts: []Account{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveVaultSelection("."); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("missing selector with v2 present error = %v", err)
	}
	if err := os.WriteFile(vaultSelectorFile, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveVaultSelection("."); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("corrupt selector error = %v", err)
	}
}

func TestSuccessfulLegacyLoginPersistsExplicitV1Selection(t *testing.T) {
	withVaultDir(t)
	app := NewApp()
	if _, err := app.Login(migrationTestPassword); err != nil {
		t.Fatal(err)
	}
	defer app.Logout()
	record, err := readVaultSelector(vaultSelectorFile)
	if err != nil || record.Mode != selectorActiveV1 {
		t.Fatalf("persisted legacy selector = (%+v, %v)", record, err)
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || selection.ActiveV2 || selection.NeedsV1Record {
		t.Fatalf("persisted v1 selection = (%+v, %v)", selection, err)
	}
}

func TestBackendActivationAndV2SessionSavesWithoutPasswordReuse(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, primaryBefore, backupBefore := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	app := NewApp()
	if _, err := app.Login(migrationTestPassword); err != nil {
		t.Fatal(err)
	}
	legacyCM := app.cm
	if selection, err := ResolveVaultSelection("."); err != nil || !selection.Prepared || selection.ActiveV2 {
		t.Fatalf("prepared selection = (%+v, %v)", selection, err)
	}
	if err := app.confirmV2Activation(service, token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); !errors.Is(err, ErrVaultActivationDenied) {
		t.Fatalf("activation challenge reuse error = %v", err)
	}
	if !app.IsLocked() || app.cm != nil || app.vault != nil {
		t.Fatal("v1 session remained open after active format changed")
	}
	if _, err := legacyCM.Encrypt("synthetic check after activation"); err == nil {
		t.Fatal("old v1 crypto session survived activation")
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || !selection.ActiveV2 {
		t.Fatalf("active selector = (%+v, %v)", selection, err)
	}
	if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultV2UIUnavailable) {
		t.Fatalf("v1 Login did not refuse downgrade: %v", err)
	}
	if err := app.unlockActiveV2ForBackend(migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	session := app.v2Session
	initialContainer, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	var initial cryptov2.Container
	if err := json.Unmarshal(initialContainer, &initial); err != nil {
		t.Fatal(err)
	}
	const parallelAdds = 5
	var wg sync.WaitGroup
	errCh := make(chan error, parallelAdds)
	for i := 0; i < parallelAdds; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			errCh <- app.AddAccount("synthetic-added", "test-user", "synthetic-password")
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	finalContainer, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	var final cryptov2.Container
	if err := json.Unmarshal(finalContainer, &final); err != nil {
		t.Fatal(err)
	}
	if initial.KDF != final.KDF || initial.WrapNonce != final.WrapNonce || initial.WrappedDEK != final.WrappedDEK {
		t.Fatal("ordinary v2 saves changed the existing DEK wrapper")
	}
	if initial.Nonce == final.Nonce {
		t.Fatal("ordinary v2 saves reused payload nonce")
	}
	loaded, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword)
	if err != nil || len(loaded.Accounts) != len(vault.Accounts)+parallelAdds || !loaded.TwoFAEnabled || loaded.TwoFASecret != vault.TwoFASecret {
		t.Fatalf("saved v2 state = (%#v, %v)", loaded, err)
	}
	backup, err := os.ReadFile(dataFileV2 + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Decrypt(migrationTestPassword, backup); err != nil {
		t.Fatalf("v2 backup failed AEAD verification: %v", err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("v1 primary or backup changed during v2 activation and saves")
	}
	app.Logout()
	if !session.isClosed() {
		t.Fatal("v2 session key was not wiped on logout")
	}
	if err := app.AddAccount("after-logout", "", ""); err == nil {
		t.Fatal("operation after logout succeeded")
	}
}

func activatedV2App(t *testing.T, vault *Vault) (*App, *cryptov2.Engine) {
	t.Helper()
	engine, _, _, _ := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if err := app.unlockActiveV2ForBackend(migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	return app, engine
}

func TestV2SessionClosesOnExternalFileModification(t *testing.T) {
	app, engine := activatedV2App(t, syntheticMigrationVault())
	defer app.Logout()
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, &Vault{Accounts: []Account{{ID: "external", Password: "synthetic-external"}}}); err != nil {
		t.Fatal(err)
	}
	if err := app.AddAccount("local", "", "synthetic-local"); !errors.Is(err, ErrVaultSessionChanged) {
		t.Fatalf("save after external modification error = %v", err)
	}
	if !app.IsLocked() || app.vault != nil || app.v2Session != nil {
		t.Fatal("stale v2 session retained decrypted memory")
	}
	loaded, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword)
	if err != nil || len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "external" {
		t.Fatalf("external current container changed: (%#v, %v)", loaded, err)
	}
}

func TestV2SaveFailureRollsBackMemoryAndKeepsSession(t *testing.T) {
	app, _ := activatedV2App(t, syntheticMigrationVault())
	defer app.Logout()
	before := cloneVault(app.vault)
	oldReplace := replaceVaultFile
	replaceVaultFile = func(source, destination string) error {
		if filepath.Base(destination) == dataFileV2 {
			return os.ErrPermission
		}
		return oldReplace(source, destination)
	}
	t.Cleanup(func() { replaceVaultFile = oldReplace })
	if err := app.AddAccount("failed", "", "synthetic-failed-save"); err == nil {
		t.Fatal("expected injected v2 primary write failure")
	}
	if app.IsLocked() || !reflectVaultEqual(app.vault, before) {
		t.Fatal("pre-commit failure left inconsistent app memory/session state")
	}
}

func TestV2ActivationRejectsStaleV1AfterPreparation(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, cm, _, _ := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	changed := cloneVault(vault)
	changed.Accounts[0].Password = "newer-synthetic-password"
	if err := SaveVault(cm, changed); err != nil {
		t.Fatal(err)
	}
	err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine)
	if !errors.Is(err, ErrVaultV2StalePreparation) {
		t.Fatalf("stale activation error = %v", err)
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || selection.ActiveV2 || !selection.Prepared || selection.Fresh {
		t.Fatalf("stale prepared selector = (%+v, %v)", selection, err)
	}
}

func TestActivationInterruptionBeforeSelectorCommitKeepsV1Active(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, primaryBefore, backupBefore := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	oldReplace := replaceVaultFile
	replaceVaultFile = func(source, destination string) error {
		if destination == vaultSelectorFile {
			return os.ErrPermission
		}
		return oldReplace(source, destination)
	}
	t.Cleanup(func() { replaceVaultFile = oldReplace })
	err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine)
	if err == nil {
		t.Fatal("expected selector commit failure")
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || selection.ActiveV2 || !selection.Prepared {
		t.Fatalf("selection after pre-commit interruption = (%+v, %v)", selection, err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("activation interruption modified v1 files")
	}
}

func TestActivationDirectorySyncUncertaintyDoesNotDowngradeAndClosesAppSession(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, _, _ := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	app := NewApp()
	if _, err := app.Login(migrationTestPassword); err != nil {
		t.Fatal(err)
	}
	oldSync := syncVaultDirectory
	count := 0
	syncVaultDirectory = func(path string) error {
		count++
		if count == 2 {
			return os.ErrPermission
		}
		return oldSync(path)
	}
	t.Cleanup(func() { syncVaultDirectory = oldSync })
	err := app.confirmV2Activation(service, token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine)
	if !errors.Is(err, errVaultCommitUncertain) {
		t.Fatalf("selector sync error = %v, want uncertain commit", err)
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || !selection.ActiveV2 {
		t.Fatalf("selector after uncertain commit = (%+v, %v)", selection, err)
	}
	if !app.IsLocked() || app.cm != nil || app.vault != nil {
		t.Fatal("old v1 application session stayed active after selector commit")
	}
	if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultV2UIUnavailable) {
		t.Fatalf("Login downgraded after uncertain activation: %v", err)
	}
}

func TestV1ResetAndRecoveryCannotTouchActiveV2(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, primaryBefore, backupBefore := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if _, err := app.PrepareVaultRecovery(migrationTestPassword); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("v1 recovery in active v2 mode error = %v", err)
	}
	if _, err := app.BeginVaultReset(); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("v1 reset challenge in active v2 mode error = %v", err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("v1 reset/recovery modified the preserved v1 primary or backup")
	}
	if _, err := os.Stat(dataFileV2); err != nil {
		t.Fatalf("active v2 file was removed: %v", err)
	}
}

func TestActiveV2MissingFileNeverFallsBackToV1(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, _, _ := createV1AndPreparedV2(t, vault)
	service, token := prepareActivation(t, engine, vault)
	if err := service.Confirm(token, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dataFileV2); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("missing active v2 file caused downgrade: %v", err)
	}
	if err := app.unlockActiveV2ForBackend(migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("backend unlock of missing v2 file error = %v", err)
	}
}

func TestCancelExpiredPreparationAfterRestartAndPrepareAgain(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, primaryBefore, backupBefore := createV1AndPreparedV2(t, vault)
	service, activationToken := prepareActivation(t, engine, vault)
	service.mu.Lock()
	service.pending.expires = time.Now().Add(-time.Second)
	service.mu.Unlock()
	if err := service.Confirm(activationToken, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); !errors.Is(err, ErrVaultActivationDenied) {
		t.Fatalf("expired activation token error = %v", err)
	}
	if err := os.Remove(dataFileV2); err != nil {
		t.Fatal(err)
	}

	// A new service instance models an application restart: no in-memory token
	// survives, but an explicit cancel flow can still recover v1 ownership.
	restarted := &v2ActivationService{}
	cancelToken, err := restarted.BeginCancelV2Preparation(".")
	if err != nil {
		t.Fatalf("begin cancel without v2 candidate: %v", err)
	}
	if err := restarted.ConfirmCancelV2Preparation(cancelToken); err != nil {
		t.Fatalf("confirm cancel after restart: %v", err)
	}
	record, err := readVaultSelector(vaultSelectorFile)
	if err != nil || record.Mode != selectorActiveV1 {
		t.Fatalf("selector after cancellation = (%+v, %v)", record, err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("cancellation changed the v1 primary or backup")
	}
	if _, err := os.Stat(dataFileV2); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancellation unexpectedly recreated/deleted the v2 candidate: %v", err)
	}

	// With cancellation committed, migration can explicitly prepare again.
	if err := MigrateV1VaultToV2(migrationTestPassword, engine); err != nil {
		t.Fatalf("repeat migration after cancellation: %v", err)
	}
	repeated := &v2ActivationService{}
	newActivationToken, err := repeated.Prepare(".", migrationTestPassword, currentCode(t, vault.TwoFASecret), engine)
	if err != nil {
		t.Fatalf("repeat activation preparation: %v", err)
	}
	if err := repeated.Confirm(newActivationToken, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatalf("activation after repeated preparation: %v", err)
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || !selection.ActiveV2 {
		t.Fatalf("selector after repeated preparation = (%+v, %v)", selection, err)
	}
}

func TestCancelPreparationLeavesFilesUntouchedAndRestoresV1Recovery(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, _, backupBefore := createV1AndPreparedV2(t, vault)
	_, _ = prepareActivation(t, engine, vault)
	damagedPrimary := []byte("synthetic damaged v1 primary")
	if err := os.WriteFile(dataFile, damagedPrimary, 0600); err != nil {
		t.Fatal(err)
	}
	candidateBefore, err := os.ReadFile(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	service := &v2ActivationService{}
	cancelToken, err := service.BeginCancelV2Preparation(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfirmCancelV2Preparation(cancelToken); err != nil {
		t.Fatal(err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	candidateAfter, _ := os.ReadFile(dataFileV2)
	if !bytes.Equal(damagedPrimary, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) || !bytes.Equal(candidateBefore, candidateAfter) {
		t.Fatal("cancel modified v1 data, backup, or v2 candidate")
	}

	app := NewApp()
	recoveryToken, err := app.PrepareVaultRecovery(migrationTestPassword)
	if err != nil {
		t.Fatalf("v1 backup recovery unavailable after cancellation: %v", err)
	}
	if _, err := app.ConfirmVaultRecovery(recoveryToken); err != nil {
		t.Fatalf("restore v1 backup after cancellation: %v", err)
	}
	loaded, err := LoadVault(app.cm)
	if err != nil || !reflectVaultEqual(loaded, vault) {
		t.Fatalf("recovered v1 contents = (%#v, %v)", loaded, err)
	}
	app.Logout()
}

func TestCancelPreparationRequiresCurrentExplicitState(t *testing.T) {
	vault := syntheticMigrationVault()
	engine, _, _, _ := createV1AndPreparedV2(t, vault)
	service, activationToken := prepareActivation(t, engine, vault)
	cancelToken, err := service.BeginCancelV2Preparation(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Confirm(activationToken, migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfirmCancelV2Preparation(cancelToken); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("cancellation after v2 activation error = %v", err)
	}
	if _, err := (&v2ActivationService{}).BeginCancelV2Preparation("."); !errors.Is(err, ErrVaultV2Protected) {
		t.Fatalf("begin cancellation while v2 active error = %v", err)
	}
	selection, err := ResolveVaultSelection(".")
	if err != nil || !selection.ActiveV2 {
		t.Fatalf("v2 was not kept active after refused cancellation: (%+v, %v)", selection, err)
	}

	// An unknown selector is never rewritten as v1 by the cancel path.
	if err := os.WriteFile(vaultSelectorFile, []byte(`{"format":"unknown"}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(vaultSelectorFile)
	if _, err := (&v2ActivationService{}).BeginCancelV2Preparation("."); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("cancel with unknown selector error = %v", err)
	}
	after, _ := os.ReadFile(vaultSelectorFile)
	if !bytes.Equal(before, after) {
		t.Fatal("cancel rewrote an unknown selector")
	}
}

func TestPrepareTokenFailurePreservesV1Management(t *testing.T) {
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	vault := syntheticMigrationVault()
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, vault); err != nil {
		t.Fatal(err)
	}
	cm.Wipe()
	primaryBefore, _ := os.ReadFile(dataFile)
	backupBefore, _ := os.ReadFile(dataFile + ".bak")
	engine := migrationEngine(t)
	if err := MigrateV1VaultToV2(migrationTestPassword, engine); err != nil {
		t.Fatal(err)
	}
	oldToken := activationChallengeToken
	activationChallengeToken = func() (string, error) { return "", errors.New("injected token source failure") }
	t.Cleanup(func() { activationChallengeToken = oldToken })
	service := &v2ActivationService{}
	if _, err := service.Prepare(".", migrationTestPassword, currentCode(t, vault.TwoFASecret), engine); err == nil {
		t.Fatal("expected activation token generation failure")
	}
	record, err := readVaultSelector(vaultSelectorFile)
	if err != nil || record.Mode != selectorActiveV1 {
		t.Fatalf("selector after token generation failure = (%+v, %v)", record, err)
	}
	primaryAfter, _ := os.ReadFile(dataFile)
	backupAfter, _ := os.ReadFile(dataFile + ".bak")
	if !bytes.Equal(primaryBefore, primaryAfter) || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatal("failed preparation changed v1 data")
	}
	if err := os.WriteFile(dataFile, []byte("damaged after failed preparation"), 0600); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	recoveryToken, err := app.PrepareVaultRecovery(migrationTestPassword)
	if err != nil {
		t.Fatalf("v1 recovery unavailable after token failure: %v", err)
	}
	app.CancelVaultRecovery(recoveryToken)
}
