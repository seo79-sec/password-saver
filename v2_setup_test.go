package main

import (
    "bytes"
    "errors"
    "os"
    "testing"
)

// First-run setup must never round-trip through v1, even temporarily.
func TestFirstRunCreatesV2OnlyAndSupportsRestart(t *testing.T) {
    withVaultDir(t)
    app := NewApp()
    if status := app.GetVaultStatus(); status.State != VaultStateUninitialized {
        t.Fatalf("new folder status = %+v", status)
    }
    if _, err := app.Login(migrationTestPassword); !errors.Is(err, ErrVaultV1CreationDisabled) {
        t.Fatalf("legacy login from empty folder = %v", err)
    }
    if _, err := os.Stat(dataFile); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("legacy v1 file was created: %v", err)
    }
    if err := app.CreateV2Vault("short"); err == nil {
        t.Fatal("short master password unexpectedly accepted")
    }
    if err := app.CreateV2Vault(migrationTestPassword); err != nil {
        t.Fatalf("first-run v2 setup = %v", err)
    }
    if status := app.GetVaultStatus(); status.State != VaultStateV2Active || !status.V2ContainerPresent || !status.V2BackupPresent {
        t.Fatalf("new v2 status = %+v", status)
    }
    for _, old := range []string{dataFile, dataFile + ".bak"} {
        if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
            t.Fatalf("unexpected legacy file %q: %v", old, err)
        }
    }
    primary, err := os.ReadFile(dataFileV2)
    if err != nil { t.Fatal(err) }
    backup, err := os.ReadFile(dataFileV2 + ".bak")
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(primary, backup) { t.Fatal("initial backup differs from encrypted primary") }
    selector, err := readVaultSelector(vaultSelectorFile)
    if err != nil || selector.Mode != selectorActiveV2 || selector.ActivatedV2SHA256 != digestHex(primary) {
        t.Fatalf("first-run selector = (%+v, %v)", selector, err)
    }
    reopened := NewApp()
    if needsTOTP, err := reopened.LoginV2(migrationTestPassword); err != nil || needsTOTP {
        t.Fatalf("new v2 login = (%v, %v)", needsTOTP, err)
    }
    if err := reopened.AddAccount("Example", "tester@example.invalid", "synthetic-only"); err != nil { t.Fatal(err) }
    reopened.Logout()
    again := NewApp()
    if needsTOTP, err := again.LoginV2(migrationTestPassword); err != nil || needsTOTP { t.Fatalf("login after save = (%v, %v)", needsTOTP, err) }
    records, err := again.GetAccounts()
    if err != nil || len(records) != 1 || records[0].Password != "synthetic-only" {
        t.Fatalf("reopened accounts = (%+v, %v)", records, err)
    }
    again.Logout()
    if err := app.CreateV2Vault(migrationTestPassword); !errors.Is(err, ErrVaultAlreadyInitialized) {
        t.Fatalf("repeated initialization = %v", err)
    }
}

func TestFirstRunRefusesToOverwriteLegacyOrOrphanFiles(t *testing.T) {
    for _, path := range []string{dataFile, dataFile + ".bak", dataFileV2, dataFileV2 + ".bak", vaultSelectorFile} {
        t.Run(path, func(t *testing.T) {
            withVaultDir(t)
            marker := []byte("existing test file")
            if err := os.WriteFile(path, marker, 0600); err != nil { t.Fatal(err) }
            app := NewApp()
            if err := app.CreateV2Vault(migrationTestPassword); !errors.Is(err, ErrVaultAlreadyInitialized) {
                t.Fatalf("overwrite protection = %v", err)
            }
            got, err := os.ReadFile(path)
            if err != nil || !bytes.Equal(got, marker) { t.Fatalf("file changed: %v", err) }
        })
    }
}

func TestNewVaultDoesNotLeaveActiveV2WhenBackupCreationFails(t *testing.T) {
    withVaultDir(t)
    // Preserve a preexisting backup to simulate an interrupted previous setup.
    marker := []byte("do not replace")
    if err := os.WriteFile(dataFileV2+".bak", marker, 0600); err != nil { t.Fatal(err) }
    app := NewApp()
    if err := app.CreateV2Vault(migrationTestPassword); !errors.Is(err, ErrVaultAlreadyInitialized) {
        t.Fatalf("existing backup must block initialization: %v", err)
    }
    if _, err := os.Stat(vaultSelectorFile); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("selector unexpectedly activated: %v", err)
    }
}
