package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestV25DefaultVaultDirectoryIsNotWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	directory, err := vaultDirectoryFromBase(base)
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(base, "PasswordSaver", "vaults", "default")
	if directory != expected {
		t.Fatalf("default vault dir = %q, expected %q", directory, expected)
	}
	for _, base := range []string{"", "relative", ".", "../unsafe"} {
		if _, err := vaultDirectoryFromBase(base); !errors.Is(err, ErrVaultDataLocation) {
			t.Fatalf("base %q was accepted: %v", base, err)
		}
	}
}

func TestV25InventoryDetectsVaultWithoutReadingSecretData(t *testing.T) {
	dir := t.TempDir()
	got, err := inspectVaultFiles(dir)
	if err != nil || got.HasVaultFiles {
		t.Fatalf("empty vault inventory = (%+v, %v)", got, err)
	}
	filename := filepath.Join(dir, dataFileV2)
	secret := []byte("synthetic encrypted fixture bytes")
	if err := os.WriteFile(filename, secret, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = inspectVaultFiles(dir)
	if err != nil || !got.HasVaultFiles {
		t.Fatalf("vault inventory = (%+v, %v)", got, err)
	}
	after, err := os.ReadFile(filename)
	if err != nil || string(after) != string(secret) {
		t.Fatal("read-only inventory modified vault bytes")
	}
}

func TestV25VaultLocationPlanRequiresExplicitConflictResolution(t *testing.T) {
	legacy := t.TempDir()
	target := t.TempDir()
	plan, err := inspectVaultLocationPlan(legacy, target)
	if err != nil || plan.HasTargetVault || plan.HasLegacyVault || plan.NeedsMigration || plan.HasConflict {
		t.Fatalf("empty plan = (%+v, %v)", plan, err)
	}
	legacyPath := filepath.Join(legacy, dataFile)
	if err := os.WriteFile(legacyPath, []byte("legacy marker"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err = inspectVaultLocationPlan(legacy, target)
	if err != nil || !plan.NeedsMigration || !plan.HasLegacyVault || plan.HasConflict {
		t.Fatalf("legacy-only plan = (%+v, %v)", plan, err)
	}
	targetPath := filepath.Join(target, dataFileV2)
	if err := os.WriteFile(targetPath, []byte("target marker"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err = inspectVaultLocationPlan(legacy, target)
	if err != nil || !plan.HasConflict || plan.NeedsMigration {
		t.Fatalf("conflicted plan = (%+v, %v)", plan, err)
	}
	if got, _ := os.ReadFile(legacyPath); string(got) != "legacy marker" {
		t.Fatal("source changed while inspecting location conflict")
	}
	if got, _ := os.ReadFile(targetPath); string(got) != "target marker" {
		t.Fatal("target changed while inspecting location conflict")
	}
	plan, err = inspectVaultLocationPlan(target, target)
	if err != nil || plan.HasConflict || plan.NeedsMigration || !plan.HasTargetVault {
		t.Fatalf("same-location plan = (%+v, %v)", plan, err)
	}
}

func TestV25InventoryRejectsNonRegularFileEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, vaultSelectorFile), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectVaultFiles(dir); !errors.Is(err, ErrVaultDataLocation) {
		t.Fatalf("directory in place of selector was accepted: %v", err)
	}
}
