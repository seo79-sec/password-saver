package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cryptov2 "password-saver/crypto/v2"
)

const externalImportTestPassword = "synthetic distinct external password"

func externalImportFixture(t *testing.T, sourceTOTP bool) (*App, *cryptov2.Engine, *Vault, string) {
	t.Helper()
	app, engine, original := passwordChangeFixture(t, true)
	path := filepath.Join(t.TempDir(), "backup.v2.enc")
	source := &Vault{
		Accounts: []Account{
			{ID: original.Accounts[0].ID, Title: " SYNTHETIC mail |||New category", Login: "USER@example.invalid ", Password: "different-source-only-password", UpdatedAt: 9},
			{ID: original.Accounts[1].ID, Title: "Imported entry", Login: "source@example.invalid", Password: "selected-source-only-password", UpdatedAt: 13},
			{ID: "copy-unique-2", Title: "Not selected", Login: "source@example.invalid", Password: "unselected-source-only-password"},
		},
		TwoFAEnabled: sourceTOTP,
	}
	if sourceTOTP {
		source.TwoFASecret = "KRUGS4ZANFZSAYJA"
	}
	if err := SaveV2Vault(path, engine, externalImportTestPassword, source); err != nil {
		t.Fatal(err)
	}
	useBackupDialogs(t, "", path)
	return app, engine, original, path
}

func externalImportSelect(t *testing.T, app *App, forImport bool) ExternalImportSelection {
	t.Helper()
	selection, err := app.SelectExternalV2Import(forImport)
	if err != nil || selection.Token == "" || selection.FileName != "backup.v2.enc" {
		t.Fatalf("selection = (%+v, %v)", selection, err)
	}
	return selection
}

func externalImportPreview(t *testing.T, app *App) ExternalImportReview {
	t.Helper()
	selection := externalImportSelect(t, app, true)
	review, err := app.CheckSelectedExternalV2Backup(selection.Token, externalImportTestPassword, "")
	if err != nil || review.Token == "" || len(review.Records) != 3 {
		t.Fatalf("preview = (%+v, %v)", review, err)
	}
	return review
}

func importFileSnapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(files))
	for _, file := range files {
		if !file.IsDir() {
			out[file.Name()] = readPasswordChangeTestFile(t, filepath.Join(dir, file.Name()))
		}
	}
	return out
}

func expectImportSnapshot(t *testing.T, dir string, want map[string][]byte) {
	t.Helper()
	if got := importFileSnapshot(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatal("unexpected change to encrypted files or directory contents")
	}
}

func TestExternalImportIntegrityCheckIsReadOnlyAndNoCapability(t *testing.T) {
	app, _, _, source := externalImportFixture(t, true)
	if err := os.Chmod(dataFileV2, 0640); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(dataFileV2)
	if err != nil {
		t.Fatal(err)
	}
	targetBefore := importFileSnapshot(t, ".")
	sourceBefore := importFileSnapshot(t, filepath.Dir(source))

	selection := externalImportSelect(t, app, false)
	review, err := app.CheckSelectedExternalV2Backup(selection.Token, externalImportTestPassword, currentCode(t, "KRUGS4ZANFZSAYJA"))
	if err != nil || review.AccountCount != 3 || !review.TOTPEnabled || review.Token != "" || len(review.Records) != 0 {
		t.Fatalf("integrity review = (%+v, %v)", review, err)
	}
	if _, err := app.ConfirmExternalV2Import(selection.Token, []ExternalImportChoice{{Index: 0}}); !errors.Is(err, errExternalImportExpired) {
		t.Fatalf("integrity exposed a write capability: %v", err)
	}
	expectImportSnapshot(t, ".", targetBefore)
	expectImportSnapshot(t, filepath.Dir(source), sourceBefore)
	infoAfter, err := os.Stat(dataFileV2)
	if err != nil || infoAfter.Mode() != infoBefore.Mode() || !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Fatalf("integrity check changed file permissions or write timestamp: %v", err)
	}
}

func TestExternalImportChecksCopyCredentialsAndFormatBeforePreview(t *testing.T) {
	app, engine, _, source := externalImportFixture(t, true)
	before := importFileSnapshot(t, ".")
	run := func(password, code string) error {
		selected := externalImportSelect(t, app, true)
		review, err := app.CheckSelectedExternalV2Backup(selected.Token, password, code)
		if review.Token != "" || len(review.Records) != 0 || app.pendingExternalImport.token != "" {
			t.Fatal("rejected copy produced a preview or left a challenge")
		}
		expectImportSnapshot(t, ".", before)
		return err
	}
	if err := run("incorrect external backup password", ""); !errors.Is(err, ErrVaultV2Authentication) || errors.Is(err, ErrVaultV2Corrupt) {
		t.Fatalf("wrong password classification: %v", err)
	}
	if err := run(externalImportTestPassword, ""); err == nil || err.Error() != "неверный код 2FA" || app.totpFailures != 1 {
		t.Fatalf("missing TOTP did not consume a failure: %v", err)
	}
	unmodified := readPasswordChangeTestFile(t, source)
	if err := os.WriteFile(source, damageV2Tag(unmodified), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(externalImportTestPassword, ""); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("invalid tag must share authentication error: %v", err)
	}
	if err := os.WriteFile(source, []byte("invalid copy container"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(externalImportTestPassword, ""); !errors.Is(err, ErrVaultV2Corrupt) {
		t.Fatalf("malformed container: %v", err)
	}
	notAVault, err := engine.Encrypt(externalImportTestPassword, []byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, notAVault, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(externalImportTestPassword, ""); !errors.Is(err, ErrVaultV2Corrupt) {
		t.Fatalf("null authenticated payload: %v", err)
	}
}

func TestExternalImportKeepsDestinationSettingsAndNeverReplaces(t *testing.T) {
	app, engine, original, source := externalImportFixture(t, false)
	before := importFileSnapshot(t, ".")
	sourceBytes := readPasswordChangeTestFile(t, source)
	review := externalImportPreview(t, app)
	if !review.Records[0].Conflict || review.Records[1].Conflict || review.TOTPEnabled {
		t.Fatalf("unexpected conflict or source TOTP markers: %+v", review)
	}
	public, err := json.Marshal(review)
	if err != nil || bytes.Contains(public, []byte("source-only-password")) {
		t.Fatal("preview exposed a password")
	}
	expectImportSnapshot(t, ".", before)
	n, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 0}, {Index: 1}})
	if err != nil || n != 1 {
		t.Fatalf("confirmation = (%d, %v)", n, err)
	}
	accounts, err := app.GetAccounts()
	if err != nil || len(accounts) != len(original.Accounts)+1 || !reflect.DeepEqual(accounts[:len(original.Accounts)], original.Accounts) {
		t.Fatal("current entries were altered")
	}
	added := accounts[len(original.Accounts)]
	if added.Title != "Imported entry" || added.Password != "selected-source-only-password" ||
		added.ID == original.Accounts[1].ID || added.UpdatedAt != 13 {
		t.Fatal("selected entry lost its data or reused a destination ID")
	}
	assertFileBytes(t, source, sourceBytes)
	assertFileBytes(t, vaultSelectorFile, before[vaultSelectorFile])
	assertFileBytes(t, dataFileV2+".bak", before[dataFileV2])
	assertPasswordChangeVault(t, engine, dataFileV2, migrationTestPassword, &Vault{
		Accounts: accounts, TwoFAEnabled: original.TwoFAEnabled, TwoFASecret: original.TwoFASecret,
	})
	if _, err := ReadV2Vault(dataFileV2, engine, externalImportTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("source password opened the destination: %v", err)
	}
	if _, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 1}}); !errors.Is(err, errExternalImportExpired) {
		t.Fatalf("preview token reused: %v", err)
	}

	review = externalImportPreview(t, app)
	if n, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 0, Separate: true}}); err != nil || n != 1 {
		t.Fatalf("separate record = (%d, %v)", n, err)
	}
	app.Logout()
	loginForPasswordChange(t, passwordChangeApp(t, engine), migrationTestPassword, original)
	reloaded, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword)
	if err != nil || len(reloaded.Accounts) != len(original.Accounts)+2 ||
		reloaded.Accounts[len(reloaded.Accounts)-1].ID == original.Accounts[0].ID ||
		reloaded.Accounts[len(reloaded.Accounts)-1].Password != "different-source-only-password" ||
		!reflect.DeepEqual(reloaded.Accounts[:len(original.Accounts)], original.Accounts) {
		t.Fatal("separate record replaced an existing ID or original record")
	}
}

func TestExternalImportRequiresDestinationAndCopySecondFactors(t *testing.T) {
	active, engine, original, _ := externalImportFixture(t, true)
	active.Logout()
	app := passwordChangeApp(t, engine)
	needsTOTP, err := app.LoginV2(migrationTestPassword)
	if err != nil || !needsTOTP {
		t.Fatalf("destination login = (%v, %v)", needsTOTP, err)
	}
	if _, err := app.SelectExternalV2Import(true); !errors.Is(err, errExternalImportLocked) {
		t.Fatalf("session awaiting the destination second factor could select a copy: %v", err)
	}
	if err := app.Verify2FA(currentCode(t, original.TwoFASecret)); err != nil {
		t.Fatal(err)
	}
	before := importFileSnapshot(t, ".")
	for i := 0; i < maxTOTPFailures; i++ {
		selection := externalImportSelect(t, app, true)
		if _, err := app.CheckSelectedExternalV2Backup(selection.Token, externalImportTestPassword, ""); err == nil {
			t.Fatal("copy preview accepted a missing second factor")
		}
	}
	selection := externalImportSelect(t, app, true)
	if _, err := app.CheckSelectedExternalV2Backup(selection.Token, externalImportTestPassword, currentCode(t, "KRUGS4ZANFZSAYJA")); err == nil ||
		!strings.Contains(err.Error(), "слишком много неверных кодов") {
		t.Fatalf("copy authentication during TOTP lockout: %v", err)
	}
	expectImportSnapshot(t, ".", before)
	app.mu.Lock()
	app.totpBlockedUntil = time.Now().Add(-time.Second)
	app.mu.Unlock()
	selection = externalImportSelect(t, app, true)
	review, err := app.CheckSelectedExternalV2Backup(selection.Token, externalImportTestPassword, currentCode(t, "KRUGS4ZANFZSAYJA"))
	if err != nil || review.Token == "" || !review.TOTPEnabled {
		t.Fatalf("authenticated preview after lockout = (%+v, %v)", review, err)
	}
	if count, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 1}}); err != nil || count != 1 {
		t.Fatalf("import from a copy with TOTP = (%d, %v)", count, err)
	}
}

func TestExternalImportCancellationAndStaleSessions(t *testing.T) {
	for _, scenario := range []string{"cancel", "expiry", "logout", "destination edited", "invalid choices", "skip only"} {
		t.Run(scenario, func(t *testing.T) {
			app, _, _, _ := externalImportFixture(t, false)
			review := externalImportPreview(t, app)
			records := app.pendingExternalImport.records
			choices := []ExternalImportChoice{{Index: 1}}
			want := error(errExternalImportExpired)
			switch scenario {
			case "cancel":
				app.CancelExternalV2Import(review.Token)
			case "expiry":
				app.mu.Lock()
				app.pendingExternalImport.expires = time.Now().Add(-time.Second)
				app.mu.Unlock()
			case "logout":
				app.Logout()
				want = errExternalImportLocked
			case "destination edited":
				if err := app.AddAccount("new current record", "test", "synthetic unshared value"); err != nil {
					t.Fatal(err)
				}
				want = nil // the stale-preview error is distinct from session loss
			case "invalid choices":
				choices = append(choices, choices[0])
				want = errExternalImportChoice
			case "skip only":
				choices = []ExternalImportChoice{{Index: 0}}
				want = nil
			}
			before := importFileSnapshot(t, ".")
			n, err := app.ConfirmExternalV2Import(review.Token, choices)
			if scenario == "destination edited" {
				if err == nil || !strings.Contains(err.Error(), "изменилось после предпросмотра") || app.IsLocked() {
					t.Fatalf("legitimate destination edit handling: %v", err)
				}
			} else if n != 0 || !errors.Is(err, want) {
				t.Fatalf("result = (%d, %v), want (0, %v)", n, err, want)
			}
			expectImportSnapshot(t, ".", before)
			if app.pendingExternalImport.token != "" {
				t.Fatal("consumed challenge remained active")
			}
			for _, record := range records {
				if record != (Account{}) {
					t.Fatal("pending record data was not cleared")
				}
			}
		})
	}
}

func TestExternalImportChecksSourceAgainBeforeEveryReplacement(t *testing.T) {
	for _, stage := range []int{0, 1, 2} {
		t.Run([]string{"before confirm", "before backup rename", "before primary rename"}[stage], func(t *testing.T) {
			app, _, _, path := externalImportFixture(t, false)
			review := externalImportPreview(t, app)
			before := importFileSnapshot(t, ".")
			mutate := func() error { return os.WriteFile(path, []byte("external synthetic replacement"), 0600) }
			if stage == 0 {
				if err := mutate(); err != nil {
					t.Fatal(err)
				}
			} else {
				originalSync := syncVaultTempFile
				t.Cleanup(func() { syncVaultTempFile = originalSync })
				n := 0
				syncVaultTempFile = func(f *os.File) error {
					n++
					if n == stage {
						if err := mutate(); err != nil {
							return err
						}
					}
					return originalSync(f)
				}
			}
			if _, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 1}}); !errors.Is(err, errExternalImportChanged) {
				t.Fatalf("changed source returned %v", err)
			}
			if stage == 2 {
				before[dataFileV2+".bak"] = before[dataFileV2]
			}
			expectImportSnapshot(t, ".", before)
		})
	}
}

func TestExternalImportWriteFailuresKeepRecoverableRevision(t *testing.T) {
	for _, stage := range []string{"backup rename", "primary rename", "primary directory sync"} {
		t.Run(stage, func(t *testing.T) {
			app, engine, original, _ := externalImportFixture(t, false)
			review := externalImportPreview(t, app)
			before := importFileSnapshot(t, ".")
			injected := errors.New("synthetic write failure")
			replace, syncDir := replaceVaultFile, syncVaultDirectory
			restore := func() { replaceVaultFile, syncVaultDirectory = replace, syncDir }
			t.Cleanup(restore)
			replaceVaultFile = func(source, destination string) error {
				leaf := filepath.Base(destination)
				if (leaf == dataFileV2+".bak" && stage == "backup rename") || (leaf == dataFileV2 && stage == "primary rename") {
					return injected
				}
				return replace(source, destination)
			}
			call := 0
			syncVaultDirectory = func(directory string) error {
				call++
				if stage == "primary directory sync" && call == 2 {
					return injected
				}
				return syncDir(directory)
			}
			_, err := app.ConfirmExternalV2Import(review.Token, []ExternalImportChoice{{Index: 1}})
			restore()
			if stage == "primary directory sync" {
				if !errors.Is(err, errVaultCommitUncertain) || !app.IsLocked() {
					t.Fatalf("uncertain result left a live session or reported success: %v", err)
				}
				assertFileBytes(t, dataFileV2+".bak", before[dataFileV2])
				reopened := passwordChangeApp(t, engine)
				loginForPasswordChange(t, reopened, migrationTestPassword, original)
				return
			}
			if !errors.Is(err, injected) {
				t.Fatalf("injected error lost: %v", err)
			}
			if stage == "primary rename" {
				before[dataFileV2+".bak"] = before[dataFileV2]
			}
			expectImportSnapshot(t, ".", before)
			accounts, accountsErr := app.GetAccounts()
			if accountsErr != nil || !reflect.DeepEqual(accounts, original.Accounts) {
				t.Fatal("failed import modified current RAM")
			}
		})
	}
}
