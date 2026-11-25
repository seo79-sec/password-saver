package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
)

func TestV3ActivationRestartAndRollback(t *testing.T) {
	app, engine, vault := passwordChangeFixture(t, true)
	ctx := t.Context()
	want := cloneVault(vault)
	candidate, err := app.prepareV3Migration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(candidate.profile) })
	marker := filepath.Join(candidate.profile, v3MarkerFile)
	source := readPasswordChangeTestFile(t, dataFileV2)
	if err := SaveV2Vault(dataFileV2, engine, migrationTestPassword, vault); err != nil {
		t.Fatal(err)
	}
	if err := app.activateV3Copy(ctx, candidate); !errors.Is(err, ErrVaultV2SourceChanged) || ensurePathAbsent(marker) != nil {
		t.Fatalf("activation with stale v2: %v", err)
	}
	if err := writeFileAtomic(dataFileV2, source); err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("synthetic interruption")
	create, syncDir := createVaultFileNoReplace, syncVaultDirectory
	createVaultFileNoReplace = func(string, string) error { return interrupted }
	err = app.activateV3Copy(ctx, candidate)
	createVaultFileNoReplace = create
	if !errors.Is(err, interrupted) || ensurePathAbsent(marker) != nil {
		t.Fatalf("before marker commit: %v", err)
	}
	syncVaultDirectory = func(dir string) error {
		if _, err := os.Stat(marker); err == nil {
			return interrupted
		}
		return syncDir(dir)
	}
	err = app.activateV3Copy(ctx, candidate)
	syncVaultDirectory = syncDir
	if !errors.Is(err, errVaultCommitUncertain) {
		t.Fatalf("after marker commit: %v", err)
	}
	app.Logout()
	visit := func(use func(*v3OpenedCopy) error) error {
		return withV3Copy(ctx, candidate.profile, engine, migrationTestPassword, currentCode(t, want.TwoFASecret), use)
	}
	if err := os.Rename(candidate.replicaPath(), candidate.replicaPath()+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := visit(func(*v3OpenedCopy) error { return nil }); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing replica on restart: %v", err)
	}
	if err := os.Rename(candidate.replicaPath()+".saved", candidate.replicaPath()); err != nil {
		t.Fatal(err)
	}
	want.Accounts[0].Title = "Edited after activation"
	if err := visit(func(p *v3OpenedCopy) error {
		view, err := p.replica.Read(ctx)
		if err != nil {
			return err
		}
		data, err := json.Marshal(want.Accounts[0])
		if err != nil {
			return err
		}
		result, err := p.replica.Apply(ctx, syncmerge.Operation{
			ID: "edit", AuthorID: "local", RecordID: want.Accounts[0].ID, Action: syncmerge.Put,
			Parents: []string{view.Records[0].Versions[0].ID}, Data: data,
		}, replicastore.Local)
		if result.Status != syncmerge.Applied {
			return errors.Join(ErrVaultMigrationMismatch, err, result.Err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := visit(func(p *v3OpenedCopy) error { return p.rollback(ctx, engine, migrationTestPassword) }); err != nil {
		t.Fatal(err)
	}
	if err := visit(func(p *v3OpenedCopy) error {
		if p.replica != nil || !reflectVaultEqual(p.vault, want) {
			return ErrVaultMigrationMismatch
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	checkV3RollbackReleasedEXE(t, filepath.Join(candidate.profile, v3RollbackFile), want)
	if err := os.WriteFile(marker, []byte("damaged marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := visit(func(*v3OpenedCopy) error { return nil }); !errors.Is(err, ErrVaultSelectionAmbiguous) {
		t.Fatalf("damaged marker on restart: %v", err)
	}
}
