package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	cryptov2 "password-saver/crypto/v2"
)

var (
	ErrVaultAlreadyInitialized = errors.New("vault files already exist; new v2 initialization is refused")
	ErrVaultV1CreationDisabled = errors.New("new vaults must be initialized as v2")
)

// CreateV2Vault initializes a new empty AES-256-GCM vault directly in v2.
// It never creates or reads a v1 vault and cannot overwrite any existing
// primary, backup, or selector, including incomplete previous initialization.
func (a *App) CreateV2Vault(masterPassword string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.selectedLegacyStorage.token != "" || a.storageSelectionDialogOpen || a.pendingStorageMigration.token != "" {
		return ErrVaultStorageMigrationBusy
	}
	if a.cm != nil || a.v2Session != nil || a.vault != nil ||
		a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil {
		return errors.New("close the current session before creating a vault")
	}
	// The engine checks length and KDF parameters before any file is written.
	engine, err := a.v2EngineLocked()
	if err != nil {
		return err
	}
	if len(masterPassword) < 12 {
		return cryptov2.ErrPasswordTooShort
	}

	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return err
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	for _, path := range []string{paths.selector, paths.v1, paths.v1 + ".bak", paths.v2, paths.v2 + ".bak"} {
		exists, err := pathExists(path)
		if err != nil {
			return fmt.Errorf("cannot inspect existing vault files: %w", err)
		}
		if exists {
			return ErrVaultAlreadyInitialized
		}
	}

	empty := &Vault{Accounts: []Account{}}
	plaintext, err := json.Marshal(empty)
	if err != nil {
		return err
	}
	container, err := engine.Encrypt(masterPassword, plaintext)
	wipeBytes(plaintext)
	if err != nil {
		return err
	}

	// Write a primary and a byte-identical encrypted backup, both with
	// no-replace semantics. Only afterward publish the active selector.
	if err := writeFileAtomicNoReplace(paths.v2, container); err != nil {
		return fmt.Errorf("cannot create v2 vault: %w", err)
	}
	if err := writeFileAtomicNoReplace(paths.v2+".bak", container); err != nil {
		return fmt.Errorf("v2 vault was staged but backup creation failed; inspect files before retrying: %w", err)
	}
	primary, err := readV2File(paths.v2)
	if err != nil || !bytes.Equal(primary, container) {
		return errors.New("new v2 primary failed verification; selector was not activated")
	}
	backup, err := readV2File(paths.v2 + ".bak")
	if err != nil || !bytes.Equal(backup, container) {
		return errors.New("new v2 backup failed verification; selector was not activated")
	}
	checked, err := decryptV2VaultData(primary, engine, masterPassword)
	if err != nil || !reflect.DeepEqual(checked, empty) {
		wipeVault(checked)
		return errors.New("new v2 vault could not be authenticated; selector was not activated")
	}
	wipeVault(checked)
	checkedBackup, err := decryptV2VaultData(backup, engine, masterPassword)
	if err != nil || !reflect.DeepEqual(checkedBackup, empty) {
		wipeVault(checkedBackup)
		return errors.New("new v2 backup could not be authenticated; selector was not activated")
	}
	wipeVault(checkedBackup)
	record := vaultSelectorRecord{
		Format:            "passwordsaver-vault-selector",
		Version:           1,
		Mode:              selectorActiveV2,
		NativeV2:          true,
		ActivatedV2SHA256: digestHex(container),
	}
	if err := validateVaultSelectorRecord(record); err != nil {
		return err
	}
	serializedSelector, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if exists, err := pathExists(paths.selector); err != nil || exists {
		return ErrVaultSelectionAmbiguous
	}
	if err := writeFileAtomicNoReplace(paths.selector, serializedSelector); err != nil {
		return fmt.Errorf("v2 vault and backup exist, but activation is incomplete: %w", err)
	}
	// There is deliberately no v1 fallback, even if the selector's final
	// directory sync later proves uncertain.
	if _, err := os.Stat(paths.selector); err != nil {
		return fmt.Errorf("v2 selector could not be confirmed: %w", err)
	}
	return nil
}
