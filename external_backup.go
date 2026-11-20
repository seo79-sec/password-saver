package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Only the native dialogs supply paths. Neither operation accepts a path from
// JavaScript, and neither writes into the managed vault directory.
var chooseBackupExportFile = func(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", ErrVaultDataLocation
	}
	return wailsruntime.SaveFileDialog(ctx, wailsruntime.SaveDialogOptions{
		Title:           "Экспорт зашифрованной копии PasswordSaver",
		DefaultFilename: "PasswordSaver-" + time.Now().Format("20060102-150405") + ".v2.enc",
	})
}

var chooseBackupImportFile = func(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", ErrVaultDataLocation
	}
	return wailsruntime.OpenFileDialog(ctx, wailsruntime.OpenDialogOptions{
		Title: "Выберите зашифрованную копию PasswordSaver v2",
	})
}

type ExternalRestorePreview struct {
	Token          string `json:"token"`
	FileName       string `json:"fileName"`
	AccountCount   int    `json:"accountCount"`
	TOTPEnabled    bool   `json:"totpEnabled"`
	PrimaryPresent bool   `json:"primaryPresent"`
	BackupPresent  bool   `json:"backupPresent"`
}

type externalRestoreChallenge struct {
	token       string
	expires     time.Time
	timer       *time.Timer
	sourcePath  string
	sourceInfo  os.FileInfo
	bytes       []byte
	digest      [sha256.Size]byte
	directory   string
	dirInfo     os.FileInfo
	selector    vaultSelectorRecord
	primary     passwordChangeRevision
	backup      passwordChangeRevision
	primaryData []byte
	backupData  []byte
}

func externalBackupPath(path, vaultDir string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrVaultDataLocation
	}
	path = filepath.Clean(path)
	if err := checkExistingPathComponents(filepath.Dir(path)); err != nil {
		return "", err
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return "", ErrVaultDataLocation
	}
	rel, err := filepath.Rel(vaultDir, path)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
		return "", errors.New("выберите файл вне папки активного хранилища")
	}
	return path, nil
}

// ExportEncryptedV2Backup copies the exact active encrypted revision. A save
// dialog may suggest overwriting, but the actual write always refuses it.
func (a *App) ExportEncryptedV2Backup() (string, error) {
	a.mu.Lock()
	if a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout {
		a.logoutLocked()
	}
	if a.isLockedLocked() || a.v2Session == nil || a.backupDialogOpen || a.pendingExternalRestore.token != "" {
		a.mu.Unlock()
		return "", errors.New("экспорт доступен только для разблокированного хранилища v2")
	}
	generation, ctx := a.backupDialogGeneration, a.ctx
	a.backupDialogOpen = true
	a.mu.Unlock()

	chosen, dialogErr := chooseBackupExportFile(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.backupDialogGeneration {
		return "", ErrVaultSessionChanged
	}
	a.backupDialogOpen = false
	if dialogErr != nil || chosen == "" {
		return "", dialogErr
	}
	if a.isLockedLocked() || a.v2Session == nil {
		return "", ErrVaultSessionClosed
	}

	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return "", err
	}
	path, err := externalBackupPath(chosen, directory)
	if err != nil {
		return "", err
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	selection, err := resolveVaultSelectionLocked(directory)
	if err != nil || !selection.ActiveV2 {
		return "", ErrVaultV2NotActive
	}
	current, err := readV2File(vaultPaths(directory).v2)
	if err != nil {
		return "", err
	}
	if sha256.Sum256(current) != a.v2Session.digest {
		return "", ErrVaultSessionChanged
	}
	if err := writeFileAtomicNoReplace(path, current); err != nil {
		return "", err
	}
	verified, err := readV2File(path)
	if err != nil || !bytes.Equal(verified, current) {
		return "", errors.New("копия записана, но её проверка не завершилась; проверьте выбранный файл")
	}
	return path, nil
}

// SelectExternalV2Backup opens the native file picker before the UI requests
// credentials, so secrets are not retained while a dialog is open.
func (a *App) SelectExternalV2Backup() (string, error) {
	a.mu.Lock()
	if a.cm != nil || a.v2Session != nil || a.vault != nil || a.backupDialogOpen ||
		a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil || a.pendingExternalRestore.token != "" {
		a.mu.Unlock()
		return "", errors.New("восстановление доступно только после полного выхода из хранилища")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		a.mu.Unlock()
		return "", err
	}
	a.selectedExternalBackup = ""
	generation, ctx := a.backupDialogGeneration, a.ctx
	a.backupDialogOpen = true
	a.mu.Unlock()

	chosen, dialogErr := chooseBackupImportFile(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.backupDialogGeneration {
		return "", ErrVaultSessionChanged
	}
	a.backupDialogOpen = false
	if dialogErr != nil || chosen == "" {
		return "", dialogErr
	}
	if a.cm != nil || a.v2Session != nil || a.vault != nil {
		return "", ErrVaultSessionChanged
	}
	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return "", err
	}
	path, err := externalBackupPath(chosen, directory)
	if err != nil {
		return "", err
	}
	a.selectedExternalBackup = path
	return filepath.Base(path), nil
}

// PrepareExternalV2Restore authenticates a selected file before replacement.
// The preview contains counts only; account data never reaches UI.
func (a *App) PrepareExternalV2Restore(password, totpCode string) (ExternalRestorePreview, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cm != nil || a.v2Session != nil || a.vault != nil || a.backupDialogOpen ||
		a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil || a.pendingExternalRestore.token != "" {
		return ExternalRestorePreview{}, errors.New("восстановление доступно только после полного выхода из хранилища")
	}
	path := a.selectedExternalBackup
	a.selectedExternalBackup = ""
	if path == "" {
		return ExternalRestorePreview{}, errors.New("сначала выберите зашифрованную копию")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return ExternalRestorePreview{}, err
	}
	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	path, err = externalBackupPath(path, directory)
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	dirInfo, err := passwordChangeDirectoryInfo(directory)
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 {
		return ExternalRestorePreview{}, ErrVaultSelectionAmbiguous
	}
	data, err := readV2File(path)
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	engine, err := a.v2EngineLocked()
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	vault, err := decryptV2VaultData(data, engine, password)
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	defer wipeVault(vault)
	if vault.TwoFAEnabled {
		if !totp.Validate(totpCode, vault.TwoFASecret) {
			a.recordTOTPFailureLocked()
			return ExternalRestorePreview{}, errors.New("неверный код 2FA")
		}
	}
	primaryData, err := readOptionalV2Revision(paths.v2)
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	backupData, err := readOptionalV2Revision(paths.v2 + ".bak")
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	if len(primaryData) > 0 && recoveryHeaderIsUnsupported(primaryData) {
		return ExternalRestorePreview{}, ErrVaultUnsupportedFormat
	}
	if len(backupData) > 0 && recoveryHeaderIsUnsupported(backupData) {
		return ExternalRestorePreview{}, ErrVaultUnsupportedFormat
	}
	if bytes.Equal(primaryData, data) {
		return ExternalRestorePreview{}, errors.New("выбранная копия уже совпадает с основным хранилищем")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ExternalRestorePreview{}, ErrVaultStorageUnsafe
	}
	token, err := newChallengeToken()
	if err != nil {
		return ExternalRestorePreview{}, err
	}
	expires := time.Now().Add(recoveryChallengeLifetime)
	a.pendingExternalRestore = externalRestoreChallenge{
		token: token, expires: expires, sourcePath: path, sourceInfo: info,
		bytes: append([]byte(nil), data...), digest: sha256.Sum256(data),
		directory: directory, dirInfo: dirInfo, selector: selector,
		primary: revisionOf(primaryData), backup: revisionOf(backupData),
		primaryData: append([]byte(nil), primaryData...), backupData: append([]byte(nil), backupData...),
	}
	a.pendingExternalRestore.timer = time.AfterFunc(time.Until(expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.pendingExternalRestore.token, token) && !time.Now().Before(a.pendingExternalRestore.expires) {
			a.clearPendingExternalRestoreLocked()
		}
	})
	a.totpFailures, a.totpBlockedUntil = 0, time.Time{}
	return ExternalRestorePreview{Token: token, FileName: filepath.Base(path), AccountCount: len(vault.Accounts),
		TOTPEnabled: vault.TwoFAEnabled, PrimaryPresent: primaryData != nil, BackupPresent: backupData != nil}, nil
}

func readOptionalV2Revision(path string) ([]byte, error) {
	data, err := readV2File(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func revisionOf(data []byte) passwordChangeRevision {
	if data == nil {
		return passwordChangeRevision{}
	}
	return passwordChangeRevision{present: true, digest: sha256.Sum256(data)}
}

func (a *App) ConfirmExternalV2Restore(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := a.pendingExternalRestore
	if !challengeValid(pending.token, pending.expires, token) {
		a.clearPendingExternalRestoreLocked()
		return errors.New("подтверждение восстановления отсутствует или истекло")
	}
	defer a.clearPendingExternalRestoreLocked()
	if a.cm != nil || a.v2Session != nil || a.vault != nil {
		return ErrVaultSessionChanged
	}
	directory, err := activeVaultStorageDirectory()
	if err != nil || !sameStoragePath(directory, pending.directory) {
		return ErrVaultSessionChanged
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	check := func(primary, backup passwordChangeRevision) error {
		info, err := passwordChangeDirectoryInfo(directory)
		if err != nil || !os.SameFile(info, pending.dirInfo) {
			return ErrVaultStorageUnsafe
		}
		selector, err := readVaultSelector(paths.selector)
		if err != nil || selector != pending.selector {
			return ErrVaultSelectionAmbiguous
		}
		if !primary.matches(paths.v2) || !backup.matches(paths.v2+".bak") {
			return ErrVaultSessionChanged
		}
		return nil
	}
	if err := check(pending.primary, pending.backup); err != nil {
		return err
	}
	info, err := os.Lstat(pending.sourcePath)
	if err != nil || !os.SameFile(info, pending.sourceInfo) {
		return ErrVaultSessionChanged
	}
	currentSource, err := readV2File(pending.sourcePath)
	if err != nil || sha256.Sum256(currentSource) != pending.digest || !bytes.Equal(currentSource, pending.bytes) {
		return errors.New("выбранная копия изменилась; повторите проверку")
	}
	// Preserve every previous encrypted revision before replacing either file.
	for _, item := range []struct {
		path string
		data []byte
	}{{paths.v2, pending.primaryData}, {paths.v2 + ".bak", pending.backupData}} {
		if item.data == nil {
			continue
		}
		archive, err := unusedExternalArchivePath(item.path)
		if err != nil {
			return err
		}
		if err := writeFileAtomicNoReplace(archive, item.data); err != nil {
			return err
		}
		verified, err := readV2File(archive)
		if err != nil || !bytes.Equal(verified, item.data) {
			return errors.New("архив прежней версии не прошёл проверку")
		}
		if err := check(pending.primary, pending.backup); err != nil {
			return err
		}
	}
	newRevision := revisionOf(pending.bytes)
	if err := writeFileAtomicChecked(paths.v2+".bak", pending.bytes, func() error { return check(pending.primary, pending.backup) }); err != nil {
		return fmt.Errorf("результат восстановления не подтверждён; проверьте основной файл и резервную копию: %w", err)
	}
	if err := writeFileAtomicChecked(paths.v2, pending.bytes, func() error { return check(pending.primary, newRevision) }); err != nil {
		return fmt.Errorf("результат восстановления не подтверждён; проверьте основной файл и резервную копию: %w", err)
	}
	if err := check(newRevision, newRevision); err != nil {
		return fmt.Errorf("результат восстановления не подтверждён: %w", err)
	}
	return nil // remain locked; normal login must authenticate again
}

func unusedExternalArchivePath(path string) (string, error) {
	token, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	return path + ".pre-restore-" + token, nil
}

func (a *App) CancelExternalV2Restore(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if token == "" {
		a.selectedExternalBackup = ""
	}
	if challengeMatches(a.pendingExternalRestore.token, token) {
		a.clearPendingExternalRestoreLocked()
	}
}

func (a *App) clearPendingExternalRestoreLocked() {
	pending := a.pendingExternalRestore
	if pending.timer != nil {
		pending.timer.Stop()
	}
	wipeBytes(pending.bytes)
	wipeBytes(pending.primaryData)
	wipeBytes(pending.backupData)
	a.pendingExternalRestore = externalRestoreChallenge{}
}
