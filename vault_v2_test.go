package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

const migrationTestPassword = "synthetic-migration-master-password"

func migrationEngine(t *testing.T) *cryptov2.Engine {
	t.Helper()
	engine, err := cryptov2.NewEngine(cryptov2.Options{KDF: cryptov2.KDFConfig{
		Time: cryptov2.MinArgonTime, MemoryKiB: cryptov2.MinArgonMemoryKiB, Threads: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func syntheticMigrationVault() *Vault {
	return &Vault{
		Accounts: []Account{
			{ID: "fixture-1", Title: "Synthetic mail", Login: "user@example.invalid", Password: "synthetic-password-one", UpdatedAt: 1710000000},
			{ID: "fixture-2", Title: "Synthetic bank", Login: "test-user", Password: "synthetic-password-two", UpdatedAt: 1710000123},
		},
		TwoFAEnabled: true,
		TwoFASecret:  "JBSWY3DPEHPK3PXP",
	}
}

func TestDetectVaultFormatDoesNotDowngradeDamagedV2(t *testing.T) {
	engine := migrationEngine(t)
	v2, err := engine.Encrypt(migrationTestPassword, []byte(`{"accounts":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	format, err := DetectVaultFormat(v2)
	if err != nil || format != VaultFormatV2 {
		t.Fatalf("v2 format = (%v, %v)", format, err)
	}
	damaged := bytes.Replace(v2, []byte(`"format"`), []byte(`"formax"`), 1)
	format, err = DetectVaultFormat(damaged)
	if format == VaultFormatV1 || !errors.Is(err, errVaultFormatUnknown) {
		t.Fatalf("damaged v2 must be rejected without v1 fallback: (%v, %v)", format, err)
	}
	if _, err := DetectVaultFormat([]byte("unknown legacy-ish bytes")); !errors.Is(err, errVaultFormatUnknown) {
		t.Fatalf("unknown format error = %v", err)
	}
	unknownV2 := bytes.Replace(v2, []byte(cryptov2.FormatID), []byte("passwordsaver-v9"), 1)
	format, err = DetectVaultFormat(unknownV2)
	if err != nil || format != VaultFormatV2 {
		t.Fatalf("unknown-version marker = (%v, %v), want v2 candidate", format, err)
	}
}

func TestV2VaultSaveLoadAndEncryptedBackup(t *testing.T) {
	engine := migrationEngine(t)
	path := filepath.Join(t.TempDir(), dataFileV2)
	want := syntheticMigrationVault()
	if err := SaveV2Vault(path, engine, migrationTestPassword, want); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("synthetic-password-one")) || bytes.Contains(first, []byte(want.TwoFASecret)) {
		t.Fatal("serialized v2 file contains clear-text vault secrets")
	}
	loaded, err := ReadV2Vault(path, engine, migrationTestPassword)
	if err != nil || !reflectVaultEqual(loaded, want) {
		t.Fatalf("loaded v2 vault = (%#v, %v)", loaded, err)
	}
	updated := syntheticMigrationVault()
	updated.Accounts[0].Password = "synthetic-updated-password"
	if err := SaveV2Vault(path, engine, migrationTestPassword, updated); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	backupVault, err := decryptV2VaultData(backup, engine, migrationTestPassword)
	if err != nil || !reflectVaultEqual(backupVault, want) {
		t.Fatalf("encrypted backup vault = (%#v, %v)", backupVault, err)
	}
	wipeVault(backupVault)
	wrong, err := ReadV2Vault(path, engine, "different-synthetic-master-password")
	if wrong != nil || !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("wrong password = (%#v, %v)", wrong, err)
	}
}

func TestV2SaveDoesNotOverwriteWithUnauthenticatedPassword(t *testing.T) {
	engine := migrationEngine(t)
	path := filepath.Join(t.TempDir(), dataFileV2)
	if err := SaveV2Vault(path, engine, migrationTestPassword, syntheticMigrationVault()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = SaveV2Vault(path, engine, "wrong-synthetic-master-password", &Vault{Accounts: []Account{{ID: "replacement"}}})
	if !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("unauthenticated update error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unauthenticated update changed primary: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unauthenticated update created backup: %v", err)
	}
}

func TestReadV2VaultRejectsDamagedAndUnsupportedContainers(t *testing.T) {
	engine := migrationEngine(t)
	path := filepath.Join(t.TempDir(), dataFileV2)
	if err := SaveV2Vault(path, engine, migrationTestPassword, syntheticMigrationVault()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var container cryptov2.Container
	if err := json.Unmarshal(data, &container); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := decodeB64(container.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	container.Ciphertext = encodeB64(ciphertext)
	damaged, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptV2VaultData(damaged, engine, migrationTestPassword); !errors.Is(err, ErrVaultV2Authentication) {
		t.Fatalf("damaged ciphertext error = %v", err)
	}
	if _, err := decryptV2VaultData([]byte(`{"format":"passwordsaver-v2"`), engine, migrationTestPassword); !errors.Is(err, ErrVaultV2Corrupt) {
		t.Fatalf("truncated v2 container error = %v", err)
	}
	container.Format = "passwordsaver-v99"
	unsupported, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptV2VaultData(unsupported, engine, migrationTestPassword); !errors.Is(err, ErrVaultUnsupportedFormat) {
		t.Fatalf("unsupported format error = %v", err)
	}
}

func TestReadV2VaultRejectsOversizedFileBeforeDecrypt(t *testing.T) {
	path := filepath.Join(t.TempDir(), dataFileV2)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(cryptov2.MaxContainerSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadV2Vault(path, migrationEngine(t), migrationTestPassword); !errors.Is(err, ErrVaultV2Corrupt) {
		t.Fatalf("oversized v2 error = %v", err)
	}
}

func TestV1ToV2MigrationPreservesAllFieldsAndOriginalFiles(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, dataFile)
	target := filepath.Join(dir, dataFileV2)
	cm, err := crypto.NewCryptoManager(migrationTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Wipe()
	want := syntheticMigrationVault()
	if err := saveVaultToPath(source, cm, want); err != nil {
		t.Fatal(err)
	}
	primaryBefore, _ := os.ReadFile(source)
	if err := os.WriteFile(source+".bak", primaryBefore, 0600); err != nil {
		t.Fatal(err)
	}
	backupBefore, _ := os.ReadFile(source + ".bak")
	if err := migrateV1ToV2Paths(source, target, migrationTestPassword, migrationEngine(t)); err != nil {
		t.Fatal(err)
	}
	primaryAfter, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(primaryBefore, primaryAfter) {
		t.Fatalf("v1 primary changed: %v", err)
	}
	backupAfter, err := os.ReadFile(source + ".bak")
	if err != nil || !bytes.Equal(backupBefore, backupAfter) {
		t.Fatalf("v1 backup changed: %v", err)
	}
	loaded, err := ReadV2Vault(target, migrationEngine(t), migrationTestPassword)
	if err != nil || !reflectVaultEqual(loaded, want) {
		t.Fatalf("migrated v2 vault = (%#v, %v)", loaded, err)
	}
	legacyStillReadable, err := loadVaultFromPath(cm, source)
	if err != nil || !reflectVaultEqual(legacyStillReadable, want) {
		t.Fatalf("original v1 vault no longer readable: (%#v, %v)", legacyStillReadable, err)
	}
}

func TestLegacyV1FixtureMigratesWithoutChangingFormat(t *testing.T) {
	fixture, err := legacyVaultFixture.ReadFile("testdata/vault_data_v1_legacy.enc")
	if err != nil {
		t.Fatal(err)
	}
	format, err := DetectVaultFormat(fixture)
	if err != nil || format != VaultFormatV1 {
		t.Fatalf("legacy fixture format = (%v, %v)", format, err)
	}
	dir := t.TempDir()
	source, target := filepath.Join(dir, dataFile), filepath.Join(dir, dataFileV2)
	if err := os.WriteFile(source, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	if err := migrateV1ToV2Paths(source, target, "legacy-fixture-key", migrationEngine(t)); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadV2Vault(target, migrationEngine(t), "legacy-fixture-key")
	if err != nil || len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "legacy-account" || loaded.Accounts[0].Password != "legacy-fixture-password" {
		t.Fatalf("migrated legacy fixture = (%#v, %v)", loaded, err)
	}
}

func TestMigrationRejectsWrongPasswordCorruptSourceAndExistingTarget(t *testing.T) {
	for _, scenario := range []string{"wrong password", "corrupt source", "existing target"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			source, target := filepath.Join(dir, dataFile), filepath.Join(dir, dataFileV2)
			cm, _ := crypto.NewCryptoManager(migrationTestPassword)
			defer cm.Wipe()
			if scenario == "corrupt source" {
				if err := os.WriteFile(source, []byte("damaged v1 source"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := saveVaultToPath(source, cm, syntheticMigrationVault()); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(source)
			if scenario == "existing target" {
				if err := os.WriteFile(target, []byte("existing candidate"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			password := migrationTestPassword
			if scenario == "wrong password" {
				password = "wrong-synthetic-master-password"
			}
			err := migrateV1ToV2Paths(source, target, password, migrationEngine(t))
			if err == nil {
				t.Fatal("migration unexpectedly succeeded")
			}
			if scenario == "wrong password" && !errors.Is(err, errVaultMigrationWrongPass) {
				t.Fatalf("wrong password migration error = %v", err)
			}
			if scenario == "corrupt source" && !errors.Is(err, errVaultCorrupt) {
				t.Fatalf("corrupt source migration error = %v", err)
			}
			if scenario == "existing target" && !errors.Is(err, ErrVaultV2TargetExists) {
				t.Fatalf("existing target error = %v", err)
			}
			after, readErr := os.ReadFile(source)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("source changed after failed migration: %v", readErr)
			}
			if scenario != "existing target" {
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed migration left target: %v", err)
				}
			}
		})
	}
}

func TestMigrationDirectorySyncFailureLeavesStagedCandidateAndPreservesV1(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, dataFile), filepath.Join(dir, dataFileV2)
	cm, _ := crypto.NewCryptoManager(migrationTestPassword)
	defer cm.Wipe()
	if err := saveVaultToPath(source, cm, syntheticMigrationVault()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(source)
	oldSync := syncVaultDirectory
	syncVaultDirectory = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { syncVaultDirectory = oldSync })
	err := migrateV1ToV2Paths(source, target, migrationTestPassword, migrationEngine(t))
	if !errors.Is(err, errVaultCommitUncertain) {
		t.Fatalf("directory sync error = %v, want uncertain commit", err)
	}
	after, readErr := os.ReadFile(source)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("v1 source changed after uncertain candidate commit: %v", readErr)
	}
	if _, err := ReadV2Vault(target, migrationEngine(t), migrationTestPassword); err != nil {
		t.Fatalf("committed staged candidate is not readable: %v", err)
	}
}

func TestMigrationWriteFailurePreservesV1AndLeavesNoTarget(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, dataFile), filepath.Join(dir, dataFileV2)
	cm, _ := crypto.NewCryptoManager(migrationTestPassword)
	defer cm.Wipe()
	if err := saveVaultToPath(source, cm, syntheticMigrationVault()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(source)
	oldCreate := createVaultFileNoReplace
	createVaultFileNoReplace = func(string, string) error { return os.ErrPermission }
	t.Cleanup(func() { createVaultFileNoReplace = oldCreate })
	if err := migrateV1ToV2Paths(source, target, migrationTestPassword, migrationEngine(t)); err == nil {
		t.Fatal("expected injected no-replace commit failure")
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("v1 source changed after failed v2 commit: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target exists after failed commit: %v", err)
	}
}

func TestMigrationDetectsConcurrentSourceModification(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, dataFile), filepath.Join(dir, dataFileV2)
	cm, _ := crypto.NewCryptoManager(migrationTestPassword)
	defer cm.Wipe()
	if err := saveVaultToPath(source, cm, syntheticMigrationVault()); err != nil {
		t.Fatal(err)
	}
	oldCreate := createVaultFileNoReplace
	createVaultFileNoReplace = func(temp, destination string) error {
		if err := os.WriteFile(source, []byte("external concurrent change"), 0600); err != nil {
			return err
		}
		return replaceFileNoReplace(temp, destination)
	}
	t.Cleanup(func() { createVaultFileNoReplace = oldCreate })
	err := migrateV1ToV2Paths(source, target, migrationTestPassword, migrationEngine(t))
	if !errors.Is(err, ErrVaultMigrationSourceChanged) {
		t.Fatalf("concurrent source change error = %v", err)
	}
	if _, err := ReadV2Vault(target, migrationEngine(t), migrationTestPassword); err != nil {
		t.Fatalf("verified snapshot candidate should remain safely staged: %v", err)
	}
}

func TestMigrationRejectsSourceAsTargetAndV1BackupTarget(t *testing.T) {
	dir := t.TempDir()
	for _, target := range []string{filepath.Join(dir, dataFile), filepath.Join(dir, dataFile+".bak")} {
		if err := migrateV1ToV2Paths(filepath.Join(dir, dataFile), target, migrationTestPassword, migrationEngine(t)); err == nil {
			t.Fatalf("unsafe target %q was accepted", target)
		}
	}
}

func reflectVaultEqual(a, b *Vault) bool {
	return a != nil && b != nil && reflect.DeepEqual(a, b)
}

func decodeB64(value string) ([]byte, error) { return base64.StdEncoding.DecodeString(value) }
func encodeB64(value []byte) string          { return base64.StdEncoding.EncodeToString(value) }
