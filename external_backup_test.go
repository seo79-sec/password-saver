package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useBackupDialogs(t *testing.T, exportPath, importPath string) {
	t.Helper()
	oldExport, oldImport := chooseBackupExportFile, chooseBackupImportFile
	chooseBackupExportFile = func(context.Context) (string, error) { return exportPath, nil }
	chooseBackupImportFile = func(context.Context) (string, error) { return importPath, nil }
	t.Cleanup(func() { chooseBackupExportFile, chooseBackupImportFile = oldExport, oldImport })
}

func selectExternalBackupForTest(t *testing.T, app *App, path string) {
	t.Helper()
	if selected, err := app.SelectExternalV2Backup(); err != nil || selected != filepath.Base(path) {
		t.Fatalf("select backup = (%q, %v)", selected, err)
	}
}

func TestExternalBackupRoundTripPreservesPriorEncryptedRevisions(t *testing.T) {
	app, engine, original := passwordChangeFixture(t, true)
	path := filepath.Join(t.TempDir(), "backup.v2.enc")
	useBackupDialogs(t, path, path)
	if saved, err := app.ExportEncryptedV2Backup(); err != nil || saved != path {
		t.Fatalf("export = (%q, %v)", saved, err)
	}
	exported := readPasswordChangeTestFile(t, path)
	if !bytes.Equal(exported, readPasswordChangeTestFile(t, dataFileV2)) {
		t.Fatal("export was not the exact encrypted revision")
	}
	if saved, err := app.ExportEncryptedV2Backup(); !errors.Is(err, ErrVaultV2TargetExists) || saved != "" {
		t.Fatalf("existing export target = (%q, %v)", saved, err)
	}
	if !bytes.Equal(exported, readPasswordChangeTestFile(t, path)) {
		t.Fatal("existing export was overwritten")
	}
	if err := app.AddAccount("Synthetic later", "user", "synthetic later password"); err != nil {
		t.Fatal(err)
	}
	priorPrimary := readPasswordChangeTestFile(t, dataFileV2)
	priorBackup := readPasswordChangeTestFile(t, dataFileV2+".bak")
	app.Logout()
	selectExternalBackupForTest(t, app, path)
	if _, err := app.PrepareExternalV2Restore("wrong password", ""); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("wrong password: %v", err)
	}
	selectExternalBackupForTest(t, app, path)
	if _, err := app.PrepareExternalV2Restore(migrationTestPassword, "000000"); err == nil {
		t.Fatal("wrong TOTP accepted")
	}
	if !bytes.Equal(priorPrimary, readPasswordChangeTestFile(t, dataFileV2)) {
		t.Fatal("prepare changed primary")
	}
	selectExternalBackupForTest(t, app, path)
	preview, err := app.PrepareExternalV2Restore(migrationTestPassword, currentCode(t, original.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Token == "" || preview.FileName != filepath.Base(path) || preview.AccountCount != len(original.Accounts) || !preview.TOTPEnabled || !preview.PrimaryPresent || !preview.BackupPresent {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if !bytes.Equal(priorPrimary, readPasswordChangeTestFile(t, dataFileV2)) {
		t.Fatal("preview changed primary")
	}
	if err := app.ConfirmExternalV2Restore(preview.Token); err != nil {
		t.Fatal(err)
	}
	if !app.IsLocked() {
		t.Fatal("restore unexpectedly unlocked the vault")
	}
	assertPasswordChangeFile(t, dataFileV2, exported)
	assertPasswordChangeFile(t, dataFileV2+".bak", exported)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	archivedPrimary, archivedBackup := false, false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), dataFileV2+".pre-restore-") && bytes.Equal(readPasswordChangeTestFile(t, entry.Name()), priorPrimary) {
			archivedPrimary = true
		}
		if strings.HasPrefix(entry.Name(), dataFileV2+".bak.pre-restore-") && bytes.Equal(readPasswordChangeTestFile(t, entry.Name()), priorBackup) {
			archivedBackup = true
		}
	}
	if !archivedPrimary || !archivedBackup {
		t.Fatal("prior encrypted revisions were not preserved")
	}
	loginForPasswordChange(t, app, migrationTestPassword, original)
	assertPasswordChangeVault(t, engine, dataFileV2, migrationTestPassword, original)
}

func TestExternalRestoreRejectsDuplicateAndChangedSource(t *testing.T) {
	app, engine, original := passwordChangeFixture(t, false)
	path := filepath.Join(t.TempDir(), "backup.v2.enc")
	useBackupDialogs(t, path, path)
	if _, err := app.ExportEncryptedV2Backup(); err != nil {
		t.Fatal(err)
	}
	app.Logout()
	selectExternalBackupForTest(t, app, path)
	if _, err := app.PrepareExternalV2Restore(migrationTestPassword, ""); err == nil || !strings.Contains(err.Error(), "совпадает") {
		t.Fatalf("duplicate import = %v", err)
	}
	loginForPasswordChange(t, app, migrationTestPassword, original)
	if err := app.AddAccount("Synthetic later", "user", "synthetic password"); err != nil {
		t.Fatal(err)
	}
	app.Logout()
	selectExternalBackupForTest(t, app, path)
	preview, err := app.PrepareExternalV2Restore(migrationTestPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	before := readPasswordChangeTestFile(t, dataFileV2)
	if err := app.ConfirmExternalV2Restore(preview.Token); err == nil {
		t.Fatal("changed source accepted")
	}
	assertPasswordChangeFile(t, dataFileV2, before)
	remaining, err := ReadV2Vault(dataFileV2, engine, migrationTestPassword)
	if err != nil || len(remaining.Accounts) != len(original.Accounts)+1 {
		t.Fatalf("current vault changed: %v", err)
	}
}

func TestExternalExportRejectsManagedDirectoryAndLockedSession(t *testing.T) {
	app, _, _ := passwordChangeFixture(t, false)
	useBackupDialogs(t, filepath.Join(".", "illegal.v2.enc"), "")
	if _, err := app.ExportEncryptedV2Backup(); err == nil {
		t.Fatal("relative path accepted")
	}
	app.Logout()
	if _, err := app.ExportEncryptedV2Backup(); err == nil {
		t.Fatal("locked export accepted")
	}
}

func TestExternalRestorePrimaryWriteFailureLeavesOldPrimaryAndRecoverableCopy(t *testing.T) {
	app, _, _ := passwordChangeFixture(t, false)
	path := filepath.Join(t.TempDir(), "backup.v2.enc")
	useBackupDialogs(t, path, path)
	if _, err := app.ExportEncryptedV2Backup(); err != nil {
		t.Fatal(err)
	}
	exported := readPasswordChangeTestFile(t, path)
	if err := app.AddAccount("Synthetic later", "user", "synthetic password"); err != nil {
		t.Fatal(err)
	}
	priorPrimary := readPasswordChangeTestFile(t, dataFileV2)
	priorBackup := readPasswordChangeTestFile(t, dataFileV2+".bak")
	app.Logout()
	selectExternalBackupForTest(t, app, path)
	preview, err := app.PrepareExternalV2Restore(migrationTestPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	oldReplace := replaceVaultFile
	replaceVaultFile = func(source, destination string) error {
		if filepath.Base(destination) == dataFileV2 {
			return errors.New("synthetic primary write failure")
		}
		return oldReplace(source, destination)
	}
	t.Cleanup(func() { replaceVaultFile = oldReplace })
	if err := app.ConfirmExternalV2Restore(preview.Token); err == nil {
		t.Fatal("primary write failure was not reported")
	}
	if !app.IsLocked() {
		t.Fatal("failed restore unlocked the vault")
	}
	assertPasswordChangeFile(t, dataFileV2, priorPrimary)
	assertPasswordChangeFile(t, dataFileV2+".bak", exported)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	archivedPrimary, archivedBackup := false, false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), dataFileV2+".pre-restore-") && bytes.Equal(readPasswordChangeTestFile(t, entry.Name()), priorPrimary) {
			archivedPrimary = true
		}
		if strings.HasPrefix(entry.Name(), dataFileV2+".bak.pre-restore-") && bytes.Equal(readPasswordChangeTestFile(t, entry.Name()), priorBackup) {
			archivedBackup = true
		}
	}
	if !archivedPrimary || !archivedBackup {
		t.Fatal("old revisions were lost after failed primary write")
	}
}
