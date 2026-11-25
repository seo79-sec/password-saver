package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
)

func TestV3MigrationRoundTrip(t *testing.T) {
	for _, revision := range []string{"v2", "recovery"} {
		t.Run(revision, func(t *testing.T) {
			app, engine, vault := passwordChangeFixture(t, true)
			var recovery string
			if revision == "recovery" {
				var err error
				recovery, err = app.CreateRecoveryKey(migrationTestPassword, currentCode(t, vault.TwoFASecret))
				if err != nil {
					t.Fatal(err)
				}
			}
			primary := readPasswordChangeTestFile(t, dataFileV2)
			backup := readPasswordChangeTestFile(t, dataFileV2+".bak")
			candidate, err := app.prepareV3Migration(t.Context())
			if err != nil || candidate.id == ([16]byte{}) || candidate.sourceSHA256 != sha256.Sum256(primary) {
				t.Fatalf("preparing verified candidate: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(candidate.profile) })
			syncFile, syncErr := syncVaultTempFile, errors.New("synthetic export sync failure")
			syncVaultTempFile = func(*os.File) error { return syncErr }
			_, err = app.exportV3Migration(t.Context(), candidate, migrationTestPassword)
			syncVaultTempFile = syncFile
			if !errors.Is(err, syncErr) {
				t.Fatalf("export with failed staged write: %v", err)
			}
			assertPasswordChangeFile(t, dataFileV2, primary)
			assertPasswordChangeFile(t, dataFileV2+".bak", backup)
			path, err := app.exportV3Migration(t.Context(), candidate, migrationTestPassword)
			if err != nil {
				t.Fatal(err)
			}
			assertPasswordChangeVault(t, engine, path, migrationTestPassword, vault)
			if recovery != "" {
				plain, err := engine.DecryptWithRecoveryKey(recovery, readPasswordChangeTestFile(t, path))
				var recovered Vault
				if err != nil || json.Unmarshal(plain, &recovered) != nil || !reflectVaultEqual(vault, &recovered) {
					t.Fatalf("export recovery key did not restore the vault: %v", err)
				}
			}
			assertPasswordChangeFile(t, dataFileV2, primary)
			assertPasswordChangeFile(t, dataFileV2+".bak", backup)
		})
	}
}

func TestV3MigrationRejectsDuplicateIDs(t *testing.T) {
	app, _, vault := passwordChangeFixture(t, false)
	if err := app.updateVault(func(v *Vault) { v.Accounts[1].ID = vault.Accounts[0].ID }); err != nil {
		t.Fatal(err)
	}
	if candidate, err := app.prepareV3Migration(t.Context()); !errors.Is(err, errV3MigrationRecordID) || candidate.profile != "" {
		t.Fatalf("duplicate ID accepted: %v", err)
	}
}

func TestV3MigrationRejectsVersionConflict(t *testing.T) {
	app, _, vault := passwordChangeFixture(t, false)
	candidate, err := app.prepareV3Migration(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(candidate.profile) })
	key, err := app.openReplicaKey(candidate.id, candidate.wrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := replicastore.Open(t.Context(), candidate.replicaPath(), key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Apply(t.Context(), syncmerge.Operation{
		ID: "delete", AuthorID: "other", RecordID: vault.Accounts[0].ID, Action: syncmerge.Delete,
	}, replicastore.Incoming)
	if err := errors.Join(err, store.Close()); err != nil || result.Status != syncmerge.Applied {
		t.Fatalf("introducing a version conflict: %v", err)
	}
	if _, err := app.exportV3Migration(t.Context(), candidate, migrationTestPassword); !errors.Is(err, errV3MigrationConflict) {
		t.Fatalf("export with version conflict: %v", err)
	}
}
