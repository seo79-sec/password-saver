package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/pquerna/otp/totp"
)

var (
	errPasswordChangeLocked      = errors.New("разблокируйте хранилище перед сменой мастер-пароля")
	errPasswordChangeRequiresV2  = errors.New("для смены мастер-пароля сначала перейдите на формат v2")
	errPasswordChangeShort       = errors.New("новый мастер-пароль должен содержать минимум 12 символов")
	errPasswordChangeMismatch    = errors.New("новый мастер-пароль и подтверждение не совпадают")
	errPasswordChangeSame        = errors.New("новый мастер-пароль должен отличаться от текущего")
	errPasswordChangeUnconfirmed = errors.New("Результат смены мастер-пароля не подтверждён")
)

// ChangeMasterPassword reauthenticates and replaces only the active v2
// container and its normal backup. It closes the session on success or
// whenever the persistence attempt can no longer be treated as read-only.
func (a *App) ChangeMasterPassword(currentPassword, newPassword, confirmation, totpCode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.vault == nil || a.isLockedLocked() {
		return errPasswordChangeLocked
	}
	if a.v2Session == nil {
		return errPasswordChangeRequiresV2
	}
	lockSession := false
	defer func() {
		if lockSession {
			a.logoutLocked()
		}
	}()
	expired := func() bool {
		return a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout
	}
	if expired() {
		lockSession = true
		return errPasswordChangeLocked
	}
	if !utf8.ValidString(newPassword) || utf8.RuneCountInString(newPassword) < 12 {
		return errPasswordChangeShort
	}
	if newPassword != confirmation {
		return errPasswordChangeMismatch
	}
	if newPassword == currentPassword {
		return errPasswordChangeSame
	}
	if a.storageSelectionDialogOpen || a.selectedLegacyStorage.token != "" ||
		a.pendingStorageMigration.token != "" || a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil {
		return ErrVaultStorageMigrationBusy
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return err
	}

	// Match CRUD's lock order. The logout defer runs after these locks are
	// released, including the session mutex acquired again by close().
	session := a.v2Session
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.engine == nil || session.crypto == nil {
		lockSession = true
		return errPasswordChangeLocked
	}
	dir, err := activeVaultStorageDirectory()
	if err != nil || !sameStoragePath(dir, filepath.Dir(session.path)) {
		lockSession = true
		return errors.Join(ErrVaultSessionChanged, err)
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	paths := vaultPaths(dir)
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 {
		lockSession = true
		return ErrVaultSelectionAmbiguous
	}
	folder, err := passwordChangeDirectoryInfo(dir)
	if err != nil {
		lockSession = true
		return err
	}
	current, err := readV2File(paths.v2)
	if err != nil || sha256.Sum256(current) != session.digest {
		lockSession = true
		return ErrVaultSessionChanged
	}
	backupPath := paths.v2 + ".bak"
	backup, err := readPasswordChangeRevision(backupPath)
	if err != nil {
		lockSession = true
		return err
	}

	rotated, err := session.engine.ChangeMasterPassword(current, currentPassword, newPassword)
	if err != nil {
		return mapV2RecoveryError(err)
	}
	if a.vault.TwoFAEnabled && !totp.Validate(totpCode, a.vault.TwoFASecret) {
		a.recordTOTPFailureLocked()
		return errors.New("неверный код 2FA")
	}
	plaintext, err := session.engine.Decrypt(newPassword, rotated)
	wipeBytes(plaintext)
	if err != nil {
		return errors.New("не удалось проверить контейнер с новым мастер-паролем")
	}
	a.totpFailures, a.totpBlockedUntil = 0, time.Time{}

	oldPrimary := passwordChangeRevision{present: true, digest: session.digest}
	newRevision := passwordChangeRevision{present: true, digest: sha256.Sum256(rotated)}
	checkLocation := func() error {
		route, err := discoverStorageRoute()
		if err != nil || route.State != storageRouteReady || !sameStoragePath(dir, route.Location.Root) {
			return ErrVaultSessionChanged
		}
		info, err := passwordChangeDirectoryInfo(dir)
		if err != nil || !os.SameFile(folder, info) {
			return ErrVaultStorageUnsafe
		}
		liveSelector, err := readVaultSelector(paths.selector)
		if err != nil || liveSelector != selector {
			return ErrVaultSelectionAmbiguous
		}
		return nil
	}
	checkFiles := func(primary, backup passwordChangeRevision) error {
		if err := checkLocation(); err != nil {
			return err
		}
		if !primary.matches(paths.v2) || !backup.matches(backupPath) {
			return ErrVaultSessionChanged
		}
		return nil
	}
	unconfirmed := func(cause error) error {
		if checkLocation() != nil {
			return errors.Join(errPasswordChangeUnconfirmed, cause)
		}
		status := fmt.Errorf("%w. Основной файл — %s. Резервная копия — %s.",
			errPasswordChangeUnconfirmed,
			passwordChangeFileState(paths.v2, oldPrimary, newRevision),
			passwordChangeFileState(backupPath, backup, newRevision))
		return errors.Join(status, cause)
	}

	lockSession = true
	// Leave the old primary intact until a durable, byte-verified copy of
	// the latest revision exists under the new password. No auxiliary file
	// contains the old wrapper. A crash between replacements can be recovered
	// explicitly from .bak with the new password.
	if err := checkLocation(); err != nil {
		return unconfirmed(err)
	}
	if err := writeFileAtomicChecked(backupPath, rotated, func() error {
		if expired() {
			return errPasswordChangeLocked
		}
		return checkFiles(oldPrimary, backup)
	}); err != nil {
		return unconfirmed(err)
	}
	if err := checkLocation(); err != nil {
		return unconfirmed(err)
	}
	if err := writeFileAtomicChecked(paths.v2, rotated, func() error {
		return checkFiles(oldPrimary, newRevision)
	}); err != nil {
		return unconfirmed(err)
	}
	if err := checkFiles(newRevision, newRevision); err != nil {
		return unconfirmed(err)
	}
	return nil
}

type passwordChangeRevision struct {
	present bool
	digest  [sha256.Size]byte
}

func readPasswordChangeRevision(path string) (passwordChangeRevision, error) {
	data, err := readV2File(path)
	if errors.Is(err, os.ErrNotExist) {
		return passwordChangeRevision{}, nil
	}
	if err != nil {
		return passwordChangeRevision{}, err
	}
	return passwordChangeRevision{present: true, digest: sha256.Sum256(data)}, nil
}

func (r passwordChangeRevision) matches(path string) bool {
	current, err := readPasswordChangeRevision(path)
	return err == nil && current == r
}

func passwordChangeFileState(path string, original, rotated passwordChangeRevision) string {
	current, err := readPasswordChangeRevision(path)
	switch {
	case err != nil:
		return "недоступен"
	case !current.present:
		return "отсутствует"
	case current == rotated:
		return "записана версия с новым паролем"
	case current == original:
		return "состояние до операции"
	default:
		return "не совпадает с проверенными данными"
	}
}

// Stat through a handle to capture the identity now, including on Windows
// where FileInfo obtained by path may defer resolving its file ID.
func passwordChangeDirectoryInfo(path string) (os.FileInfo, error) {
	if err := checkExistingPathComponents(path); err != nil {
		return nil, err
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, ErrVaultStorageUnsafe
	}
	return info, nil
}
