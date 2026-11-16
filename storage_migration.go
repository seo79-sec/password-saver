package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

var storageMigrationChallengeLifetime = 2 * time.Minute

type storageMigrationChallenge struct {
	token          string
	expires        time.Time
	timer          *time.Timer
	sourceDir      string
	explicitSource string
	targetDir      string
	files          map[string][]byte
}

var (
	storageMigrationRenameDirectory = renameStorageDirectoryNoReplace
	storageMigrationWriteFile       = writeFileAtomicNoReplace
	storageMigrationSyncDirectory   = syncDirectory
)

// PrepareStorageLocationMigration verifies the currently selected encrypted
// vault while the application is fully locked and snapshots its encrypted
// files. No files are copied or selected until ConfirmStorageLocationMigration.
func (a *App) PrepareStorageLocationMigration(password, totpCode string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.selectedLegacyStorage.token != "" || a.storageSelectionDialogOpen {
		return "", ErrVaultStorageMigrationBusy
	}
	return a.prepareStorageLocationMigrationLocked(password, totpCode, "")
}

func (a *App) prepareStorageLocationMigrationLocked(password, totpCode, explicitSource string) (string, error) {
	if a.storageMigrationSessionLocked() {
		return "", errors.New("заблокируйте хранилище и завершите текущую операцию перед переносом")
	}
	if a.pendingStorageMigration.token != "" {
		return "", ErrVaultStorageMigrationBusy
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return "", err
	}
	route, err := discoverStorageRouteWithSource(explicitSource)
	if err != nil {
		return "", err
	}
	if route.State == storageRouteConflict {
		return "", ErrVaultStorageConflict
	}
	if route.State != storageRouteNeedsMigration || route.SourceDir == "" {
		return "", ErrVaultStorageMigration
	}
	if err := ensureStorageScaffold(route.Location, false); err != nil {
		return "", err
	}

	// Serialize with every in-process operation that could change a source
	// container while it is being authenticated and copied.
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	latest, err := discoverStorageRouteWithSource(explicitSource)
	if err != nil {
		return "", err
	}
	if latest.State != storageRouteNeedsMigration || !sameStoragePath(latest.SourceDir, route.SourceDir) {
		if latest.State == storageRouteConflict {
			return "", ErrVaultStorageConflict
		}
		return "", ErrVaultStorageMigrationExpired
	}
	sourceInventory, err := inspectLegacyVaultFiles(route.SourceDir)
	if err != nil || !sourceInventory.HasVaultFiles {
		return "", ErrVaultStorageMigrationExpired
	}
	targetInventory, err := inspectVaultFiles(route.Location.Root)
	if err != nil || targetInventory.HasVaultFiles {
		return "", ErrVaultStorageConflict
	}
	if err := requireEmptyDirectoryIfPresent(route.Location.Root); err != nil {
		return "", err
	}
	engine, err := a.v2EngineLocked()
	if err != nil {
		return "", err
	}
	format, verified, err := authenticateStorageInventory(sourceInventory, password, totpCode, engine)
	if err != nil {
		if errors.Is(err, errStorageMigrationTOTP) {
			a.recordTOTPFailureLocked()
		}
		return "", err
	}
	defer wipeVault(verified)
	if err := ensureInventoryUnchanged(route.SourceDir, sourceInventory); err != nil {
		return "", err
	}
	if err := requireEmptyDirectoryIfPresent(route.Location.Root); err != nil {
		return "", err
	}
	// A valid master password plus the required TOTP (or a vault without
	// second-factor protection) is a completed authorization flow.
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}
	_ = format // Format is retained for the public status derived from the copied selector.
	token, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	files := make(map[string][]byte, len(sourceInventory.Files))
	for name, data := range sourceInventory.Files {
		files[name] = append([]byte(nil), data...)
	}
	expires := time.Now().Add(storageMigrationChallengeLifetime)
	a.pendingStorageMigration = storageMigrationChallenge{
		token: token, expires: expires, sourceDir: route.SourceDir,
		targetDir: route.Location.Root, files: files, explicitSource: explicitSource,
	}
	a.pendingStorageMigration.timer = time.AfterFunc(time.Until(expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.pendingStorageMigration.token, token) && !time.Now().Before(a.pendingStorageMigration.expires) {
			a.clearPendingStorageMigrationLocked()
		}
	})
	return token, nil
}

var errStorageMigrationTOTP = errors.New("storage migration TOTP verification failed")

// ConfirmStorageLocationMigration copies only the encrypted snapshot prepared
// by PrepareStorageLocationMigration. The legacy directory is never removed.
func (a *App) ConfirmStorageLocationMigration(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storageMigrationSessionLocked() {
		a.clearPendingStorageMigrationLocked()
		return errors.New("перенос доступен только при полностью заблокированном хранилище")
	}
	pending := a.pendingStorageMigration
	if pending.token == "" || !challengeValid(pending.token, pending.expires, token) {
		a.clearPendingStorageMigrationLocked()
		return ErrVaultStorageMigrationExpired
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		a.clearPendingStorageMigrationLocked()
		return err
	}

	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	defer a.clearPendingStorageMigrationLocked()
	location, err := newStorageLocation(pending.targetDir)
	if err != nil {
		return err
	}
	route, err := discoverStorageRouteWithSource(pending.explicitSource)
	if err != nil {
		return err
	}
	if route.State != storageRouteNeedsMigration || !sameStoragePath(route.SourceDir, pending.sourceDir) || !sameStoragePath(route.Location.Root, pending.targetDir) {
		if route.State == storageRouteConflict {
			return ErrVaultStorageConflict
		}
		return ErrVaultStorageMigrationExpired
	}
	sourceSnapshot := vaultFileInventory{HasVaultFiles: len(pending.files) > 0, Files: pending.files}
	if err := ensureInventoryUnchanged(pending.sourceDir, sourceSnapshot); err != nil {
		return err
	}
	target, err := inspectVaultFiles(pending.targetDir)
	if err != nil || target.HasVaultFiles {
		return ErrVaultStorageConflict
	}
	if err := requireEmptyDirectoryIfPresent(pending.targetDir); err != nil {
		return err
	}
	if err := ensureStorageScaffold(location, false); err != nil {
		return err
	}
	stageDir, err := os.MkdirTemp(location.Vaults, ".default-migration-")
	if err != nil {
		return fmt.Errorf("cannot create migration staging directory: %w", err)
	}
	stageDir = filepath.Clean(stageDir)
	if err := secureStorageDirectory(stageDir); err != nil {
		_ = os.Remove(stageDir)
		return fmt.Errorf("cannot secure migration staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed && filepath.Dir(stageDir) == filepath.Clean(location.Vaults) && strings.HasPrefix(filepath.Base(stageDir), ".default-migration-") {
			_ = os.RemoveAll(stageDir)
		}
	}()
	for name, data := range pending.files {
		if filepath.Base(name) != name {
			return ErrVaultStorageUnsafe
		}
		if err := storageMigrationWriteFile(filepath.Join(stageDir, name), data); err != nil {
			return fmt.Errorf("cannot stage encrypted vault file: %w", err)
		}
	}
	receipt := storageMigrationReceipt{
		Format: "passwordsaver-storage-migration", Version: 1,
		Source: pending.sourceDir, SourceFiles: inventoryHashes(sourceSnapshot),
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err := storageMigrationWriteFile(filepath.Join(stageDir, storageMigrationReceiptFile), receiptBytes); err != nil {
		return fmt.Errorf("cannot stage migration receipt: %w", err)
	}
	staged, err := inspectVaultFiles(stageDir)
	if err != nil || !sameInventory(sourceSnapshot, staged) || !validStorageMigrationReceipt(stageDir, pending.sourceDir, sourceSnapshot) {
		return errors.New("staged encrypted copy failed byte verification")
	}
	if err := storageMigrationSyncDirectory(stageDir); err != nil {
		return fmt.Errorf("cannot synchronize staged vault directory: %w", err)
	}
	if err := ensureInventoryUnchanged(pending.sourceDir, sourceSnapshot); err != nil {
		return err
	}
	if err := requireEmptyDirectoryIfPresent(pending.targetDir); err != nil {
		return err
	}
	if err := removeEmptyDirectoryIfPresent(pending.targetDir); err != nil {
		return err
	}
	if err := storageMigrationRenameDirectory(stageDir, pending.targetDir); err != nil {
		return fmt.Errorf("cannot atomically publish migrated vault: %w", err)
	}
	committed = true
	if err := storageMigrationSyncDirectory(location.Vaults); err != nil {
		return fmt.Errorf("%w: %v", ErrVaultStorageCommitUncertain, err)
	}
	return nil
}

// CancelStorageLocationMigration discards only the in-memory copy challenge.
// It never touches either the legacy files or the AppData directory.
func (a *App) CancelStorageLocationMigration(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pendingStorageMigration.token == "" || !challengeMatches(a.pendingStorageMigration.token, token) {
		return ErrVaultStorageMigrationExpired
	}
	a.clearPendingStorageMigrationLocked()
	return nil
}

func (a *App) clearPendingStorageMigrationLocked() {
	if a.pendingStorageMigration.timer != nil {
		a.pendingStorageMigration.timer.Stop()
	}
	for _, data := range a.pendingStorageMigration.files {
		wipeBytes(data)
	}
	a.pendingStorageMigration = storageMigrationChallenge{}
}

func requireEmptyDirectoryIfPresent(path string) error {
	if !filepath.IsAbs(path) {
		return ErrVaultDataLocation
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrVaultStorageUnsafe
	}
	if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
		return ErrVaultStorageUnsafe
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return ErrVaultStorageConflict
	}
	return nil
}

func removeEmptyDirectoryIfPresent(path string) error {
	if err := requireEmptyDirectoryIfPresent(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return storageMigrationSyncDirectory(filepath.Dir(path))
}

func ensureInventoryUnchanged(directory string, expected vaultFileInventory) error {
	current, err := inspectLegacyVaultFiles(directory)
	if err != nil || !sameInventory(expected, current) {
		return ErrVaultStorageMigrationExpired
	}
	return nil
}

func authenticateStorageInventory(inventory vaultFileInventory, password, totpCode string, engine *cryptov2.Engine) (string, *Vault, error) {
	var selector *vaultSelectorRecord
	if data, exists := inventory.Files[vaultSelectorFile]; exists {
		record, err := parseVaultSelectorBytes(data)
		if err != nil {
			return "", nil, err
		}
		selector = &record
	}
	mode := selectorActiveV1
	if selector != nil {
		mode = selector.Mode
	}
	if selector == nil {
		if _, hasV2 := inventory.Files[dataFileV2]; hasV2 {
			return "", nil, ErrVaultSelectionAmbiguous
		}
		if _, hasV2Backup := inventory.Files[dataFileV2+".bak"]; hasV2Backup {
			return "", nil, ErrVaultSelectionAmbiguous
		}
	}

	var vault *Vault
	format := "v1"
	switch mode {
	case selectorActiveV1:
		if _, hasV2 := inventory.Files[dataFileV2]; hasV2 && selector == nil {
			return "", nil, ErrVaultSelectionAmbiguous
		}
		primary := inventory.Files[dataFile]
		if len(primary) > 0 {
			vault, _ = decryptV1StorageData(primary, password)
		}
		if vault == nil {
			backup := inventory.Files[dataFile+".bak"]
			if len(backup) == 0 {
				return "", nil, errors.New("не удалось подтвердить подлинность активного хранилища")
			}
			vault, _ = decryptV1StorageData(backup, password)
			if vault == nil {
				return "", nil, errors.New("неверный мастер-пароль или резервная копия повреждена")
			}
		}
	case selectorPreparedV2:
		primary := inventory.Files[dataFile]
		candidate := inventory.Files[dataFileV2]
		if len(primary) == 0 || len(candidate) == 0 {
			return "", nil, ErrVaultSelectionAmbiguous
		}
		if selector == nil || digestHex(primary) != selector.SourceV1SHA256 || digestHex(candidate) != selector.PreparedV2SHA256 {
			return "", nil, ErrVaultSelectionAmbiguous
		}
		v1Vault, err := decryptV1StorageData(primary, password)
		if err != nil {
			return "", nil, err
		}
		v2Vault, err := decryptV2VaultData(candidate, engine, password)
		if err != nil {
			wipeVault(v1Vault)
			return "", nil, err
		}
		if !reflect.DeepEqual(v1Vault, v2Vault) {
			wipeVault(v1Vault)
			wipeVault(v2Vault)
			return "", nil, ErrVaultV2StalePreparation
		}
		wipeVault(v2Vault)
		vault = v1Vault
		format = "v1-prepared"
	case selectorActiveV2:
		format = "v2"
		primary := inventory.Files[dataFileV2]
		if len(primary) > 0 {
			var primaryErr error
			vault, primaryErr = decryptV2VaultData(primary, engine, password)
			if errors.Is(primaryErr, ErrVaultUnsupportedFormat) {
				return "", nil, primaryErr
			}
		}
		if vault == nil {
			backup := inventory.Files[dataFileV2+".bak"]
			if len(backup) == 0 {
				return "", nil, errors.New("не удалось подтвердить подлинность активного контейнера v2")
			}
			var backupErr error
			vault, backupErr = decryptV2VaultData(backup, engine, password)
			if backupErr != nil {
				return "", nil, backupErr
			}
		}
	default:
		return "", nil, ErrVaultSelectionAmbiguous
	}
	if vault == nil {
		return "", nil, errors.New("неверный мастер-пароль или контейнер повреждён")
	}
	if vault.TwoFAEnabled && !totp.Validate(totpCode, vault.TwoFASecret) {
		wipeVault(vault)
		return "", nil, errStorageMigrationTOTP
	}
	return format, vault, nil
}

func parseVaultSelectorBytes(data []byte) (vaultSelectorRecord, error) {
	var record vaultSelectorRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, ErrVaultSelectionAmbiguous
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return vaultSelectorRecord{}, ErrVaultSelectionAmbiguous
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, data) || validateVaultSelectorRecord(record) != nil {
		return vaultSelectorRecord{}, ErrVaultSelectionAmbiguous
	}
	return record, nil
}

func decryptV1StorageData(data []byte, password string) (*Vault, error) {
	format, err := DetectVaultFormat(data)
	if err != nil || format != VaultFormatV1 {
		return nil, errVaultCorrupt
	}
	cm, err := crypto.NewCryptoManager(password)
	if err != nil {
		return nil, err
	}
	defer cm.Wipe()
	vault, err := loadVaultData(cm, data)
	if err != nil {
		if errors.Is(err, errVaultWrongPassword) {
			return nil, errVaultWrongPassword
		}
		return nil, errVaultCorrupt
	}
	return vault, nil
}
