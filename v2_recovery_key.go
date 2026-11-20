package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	cryptov2 "password-saver/crypto/v2"

	"github.com/pquerna/otp/totp"
)

var (
	errRecoveryKeyLocked      = errors.New("разблокируйте хранилище v2 для управления ключом восстановления")
	errRecoveryKeySession     = errors.New("выйдите из хранилища и закройте другие операции восстановления")
	errRecoveryKeyUnavailable = errors.New("ключ восстановления не был настроен для этой версии хранилища")
	errRecoveryKeyInvalid     = errors.New("не удалось аутентифицировать ключ восстановления и контейнер")
	errRecoveryKeyUsePrimary  = errors.New("основной файл доступен; требуется восстановление из основного файла")
	errRecoveryKeyExpired     = errors.New("подтверждение восстановления по ключу истекло")
	errRecoveryKeyCommit      = errors.New("результат операции с ключом восстановления не подтверждён; проверьте вход перед повтором")
)

type recoveryKeyResetChallenge struct {
	token       string
	expires     time.Time
	timer       *time.Timer
	disk        recoveryKeyDisk
	replacement []byte
}

type recoveryKeyDisk struct {
	directory string
	dirInfo   os.FileInfo
	selector  vaultSelectorRecord
	primary   recoveryKeyRevision
	backup    recoveryKeyRevision
}

type recoveryKeyRevision struct {
	data []byte
	info os.FileInfo
	hash passwordChangeRevision
}

// CreateRecoveryKey replaces any existing slot and returns the new key once,
// after both encrypted files were verified. It requires fresh password and
// TOTP authentication even when the current Wails session is unlocked.
func (a *App) CreateRecoveryKey(password, code string) (string, error) {
	return a.manageRecoveryKey(password, code, "", recoveryKeyCreate)
}

func (a *App) VerifyRecoveryKey(password, code, key string) error {
	_, err := a.manageRecoveryKey(password, code, key, recoveryKeyVerify)
	return err
}

func (a *App) DisableRecoveryKey(password, code string) error {
	_, err := a.manageRecoveryKey(password, code, "", recoveryKeyDisable)
	return err
}

type recoveryKeyOperation uint8

const (
	recoveryKeyCreate recoveryKeyOperation = iota
	recoveryKeyVerify
	recoveryKeyDisable
)

func (a *App) manageRecoveryKey(password, code, key string, operation recoveryKeyOperation) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.v2Session == nil || a.vault == nil || a.isLockedLocked() {
		return "", errRecoveryKeyLocked
	}
	expired := func() bool {
		return a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout
	}
	if expired() {
		a.logoutLocked()
		return "", errRecoveryKeyLocked
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return "", err
	}

	var closeSession bool
	defer func() {
		if closeSession {
			a.logoutLocked()
		}
	}()
	session := a.v2Session
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.crypto == nil || session.engine == nil {
		closeSession = true
		return "", errRecoveryKeyLocked
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	disk, err := captureRecoveryKeyDisk()
	if err != nil {
		return "", err
	}
	paths := vaultPaths(disk.directory)
	if !sameStoragePath(session.path, paths.v2) || !disk.primary.hash.present || disk.primary.hash.digest != session.digest {
		closeSession = true
		return "", ErrVaultSessionChanged
	}
	plaintext, err := session.engine.Decrypt(password, disk.primary.data)
	if err != nil {
		return "", mapV2RecoveryError(err)
	}
	defer wipeBytes(plaintext)
	if err := a.authenticateRecoveryPayload(plaintext, code); err != nil {
		return "", err
	}
	if expired() {
		closeSession = true
		return "", errRecoveryKeyLocked
	}
	if operation == recoveryKeyVerify {
		if err := verifyRecoveryKeyPayload(session.engine, key, disk.primary.data, plaintext); err != nil {
			return "", err
		}
		return "", disk.check(disk.primary, disk.backup)
	}
	if operation == recoveryKeyDisable && !session.crypto.HasRecoveryKey() {
		return "", errRecoveryKeyUnavailable
	}

	var replacement []byte
	if operation == recoveryKeyCreate {
		replacement, key, err = session.engine.EncryptWithRecoveryKey(password, plaintext)
	} else {
		replacement, err = session.engine.Encrypt(password, plaintext)
	}
	if err != nil {
		return "", err
	}
	replacementSession, verified, err := session.engine.Unlock(password, replacement)
	defer wipeBytes(verified)
	if err != nil || !bytes.Equal(verified, plaintext) {
		replacementSession.Close()
		return "", ErrVaultV2Corrupt
	}
	defer func() { replacementSession.Close() }()
	if operation == recoveryKeyCreate {
		if err := verifyRecoveryKeyPayload(session.engine, key, replacement, plaintext); err != nil {
			return "", err
		}
	}

	if err := disk.commit(replacement, func() error {
		if expired() {
			return errRecoveryKeyLocked
		}
		return nil
	}); err != nil {
		closeSession = true
		return "", err
	}
	session.crypto.Close()
	session.crypto, replacementSession = replacementSession, nil
	session.digest = revisionOf(replacement).digest
	return key, nil
}

// PrepareRecoveryKeyReset authenticates a snapshot and encrypts it with a new
// DEK and password. Only encrypted bytes are retained between the two steps.
// The replacement has no recovery slot: a successful reset consumes the key.
func (a *App) PrepareRecoveryKeyReset(key, code, password, confirmation string, fromBackup bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.requireRecoveryKeyResetLocked(); err != nil {
		return "", err
	}
	if a.pendingRecoveryKey.token != "" {
		return "", errRecoveryKeySession
	}
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 {
		return "", errPasswordChangeShort
	}
	if password != confirmation {
		return "", errPasswordChangeMismatch
	}
	engine, err := a.v2EngineLocked()
	if err != nil {
		return "", err
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	disk, err := captureRecoveryKeyDisk()
	if err != nil {
		return "", err
	}
	var plaintext []byte
	if fromBackup {
		if err := checkRecoveryKeyBackupAllowed(engine, key, disk.primary.data); err != nil {
			return "", err
		}
		if !disk.backup.hash.present {
			return "", errors.New("резервная копия v2 отсутствует")
		}
		plaintext, err = engine.DecryptWithRecoveryKey(key, disk.backup.data)
	} else {
		if !disk.primary.hash.present {
			return "", ErrVaultV2Corrupt
		}
		plaintext, err = engine.DecryptWithRecoveryKey(key, disk.primary.data)
	}
	if err != nil {
		return "", mapRecoveryKeyError(err)
	}
	defer wipeBytes(plaintext)
	if err := a.authenticateRecoveryPayload(plaintext, code); err != nil {
		return "", err
	}
	replacement, err := engine.Encrypt(password, plaintext)
	if err != nil {
		return "", err
	}
	verified, err := engine.Decrypt(password, replacement)
	defer wipeBytes(verified)
	if err != nil || !bytes.Equal(verified, plaintext) {
		return "", ErrVaultV2Corrupt
	}

	token, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(recoveryChallengeLifetime)
	a.pendingRecoveryKey = recoveryKeyResetChallenge{token: token, expires: expires, disk: disk, replacement: replacement}
	a.pendingRecoveryKey.timer = time.AfterFunc(time.Until(expires), func() {
		a.CancelRecoveryKeyReset(token)
	})
	return token, nil
}

func (a *App) ConfirmRecoveryKeyReset(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := a.pendingRecoveryKey
	if !challengeMatches(pending.token, token) {
		return errRecoveryKeyExpired
	}
	defer a.clearRecoveryKeyResetLocked()
	if err := a.requireRecoveryKeyResetLocked(); err != nil {
		return err
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	return pending.disk.commit(pending.replacement, func() error {
		if !time.Now().Before(pending.expires) {
			return errRecoveryKeyExpired
		}
		return nil
	})
}

func (a *App) CancelRecoveryKeyReset(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if challengeMatches(a.pendingRecoveryKey.token, token) {
		a.clearRecoveryKeyResetLocked()
	}
}

func (a *App) clearRecoveryKeyResetLocked() {
	if a.pendingRecoveryKey.timer != nil {
		a.pendingRecoveryKey.timer.Stop()
	}
	a.pendingRecoveryKey = recoveryKeyResetChallenge{}
}

func (a *App) requireRecoveryKeyResetLocked() error {
	if a.cm != nil || a.v2Session != nil || a.vault != nil || a.twoFAVerified ||
		a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil || a.pendingExternalRestore.token != "" ||
		a.backupDialogOpen || a.selectedExternalBackup != "" || a.storageSelectionDialogOpen ||
		a.selectedLegacyStorage.token != "" || a.pendingStorageMigration.token != "" {
		return errRecoveryKeySession
	}
	return a.checkTOTPAttemptsLocked()
}

func (a *App) authenticateRecoveryPayload(plaintext []byte, code string) error {
	var vault *Vault
	err := json.Unmarshal(plaintext, &vault)
	defer wipeVault(vault)
	if err != nil || vault == nil {
		return ErrVaultV2Corrupt
	}
	if vault.TwoFAEnabled && !totp.Validate(code, vault.TwoFASecret) {
		a.recordTOTPFailureLocked()
		return errors.New("неверный код 2FA")
	}
	a.totpFailures, a.totpBlockedUntil = 0, time.Time{}
	return nil
}

// Backup use is explicit. A valid primary with a disabled, revoked or wrong
// key must never fall back to a copy where that key may still work.
func checkRecoveryKeyBackupAllowed(engine *cryptov2.Engine, key string, primary []byte) error {
	if primary == nil {
		return nil
	}
	err := engine.ValidateContainer(primary)
	if err != nil {
		if !errors.Is(err, cryptov2.ErrUnsupportedFormat) && !errors.Is(err, cryptov2.ErrUnsupportedAlgorithm) &&
			!recoveryHeaderIsUnsupported(primary) {
			return nil
		}
		return ErrVaultUnsupportedFormat
	}
	plaintext, err := engine.DecryptWithRecoveryKey(key, primary)
	wipeBytes(plaintext)
	switch {
	case err == nil:
		return errRecoveryKeyUsePrimary
	case errors.Is(err, cryptov2.ErrRecoveryPayload):
		return nil
	default:
		return mapRecoveryKeyError(err)
	}
}

func verifyRecoveryKeyPayload(engine *cryptov2.Engine, key string, encrypted, expected []byte) error {
	plaintext, err := engine.DecryptWithRecoveryKey(key, encrypted)
	defer wipeBytes(plaintext)
	if err != nil {
		return mapRecoveryKeyError(err)
	}
	if !bytes.Equal(plaintext, expected) {
		return ErrVaultV2Corrupt
	}
	return nil
}

func mapRecoveryKeyError(err error) error {
	switch {
	case errors.Is(err, cryptov2.ErrRecoveryKeyUnavailable):
		return errRecoveryKeyUnavailable
	case errors.Is(err, cryptov2.ErrRecoveryKeyInvalid), errors.Is(err, cryptov2.ErrRecoveryPayload):
		return errRecoveryKeyInvalid
	default:
		return mapV2RecoveryError(err)
	}
}

// Callers hold the selector and v2 file locks. Discovery performs no writes.
func captureRecoveryKeyDisk() (recoveryKeyDisk, error) {
	route, err := discoverStorageRoute()
	if err != nil || route.State != storageRouteReady {
		return recoveryKeyDisk{}, errors.Join(ErrVaultSessionChanged, err)
	}
	dir := route.Location.Root
	info, err := passwordChangeDirectoryInfo(dir)
	if err != nil {
		return recoveryKeyDisk{}, err
	}
	paths := vaultPaths(dir)
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 {
		return recoveryKeyDisk{}, ErrVaultSelectionAmbiguous
	}
	primary, err := readRecoveryKeyRevision(paths.v2)
	if err != nil {
		return recoveryKeyDisk{}, err
	}
	backup, err := readRecoveryKeyRevision(paths.v2 + ".bak")
	if err != nil {
		return recoveryKeyDisk{}, err
	}
	if (len(primary.data) > 0 && recoveryHeaderIsUnsupported(primary.data)) ||
		(len(backup.data) > 0 && recoveryHeaderIsUnsupported(backup.data)) {
		return recoveryKeyDisk{}, ErrVaultUnsupportedFormat
	}
	return recoveryKeyDisk{dir, info, selector, primary, backup}, nil
}

func readRecoveryKeyRevision(path string) (recoveryKeyRevision, error) {
	data, info, err := readV2FileSnapshot(path)
	if errors.Is(err, os.ErrNotExist) {
		return recoveryKeyRevision{}, nil
	}
	if err != nil {
		return recoveryKeyRevision{}, err
	}
	if data == nil {
		data = []byte{} // An empty existing file must still be archived.
	}
	return recoveryKeyRevision{data, info, revisionOf(data)}, nil
}

func (r recoveryKeyRevision) matches(path string) bool {
	data, info, err := readV2FileSnapshot(path)
	if !r.hash.present {
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && revisionOf(data) == r.hash && (r.info == nil || os.SameFile(info, r.info))
}

func (disk recoveryKeyDisk) check(primary, backup recoveryKeyRevision) error {
	route, err := discoverStorageRoute()
	if err != nil || route.State != storageRouteReady || !sameStoragePath(disk.directory, route.Location.Root) {
		return ErrVaultSessionChanged
	}
	info, err := passwordChangeDirectoryInfo(disk.directory)
	if err != nil || !os.SameFile(disk.dirInfo, info) {
		return ErrVaultStorageUnsafe
	}
	paths := vaultPaths(disk.directory)
	selector, err := readVaultSelector(paths.selector)
	if err != nil || selector != disk.selector {
		return ErrVaultSelectionAmbiguous
	}
	if !primary.matches(paths.v2) || !backup.matches(paths.v2+".bak") {
		return ErrVaultSessionChanged
	}
	return nil
}

func (disk recoveryKeyDisk) commit(replacement []byte, guard func() error) error {
	paths := vaultPaths(disk.directory)
	backupPath := paths.v2 + ".bak"
	checkOriginal := func() error {
		if err := disk.check(disk.primary, disk.backup); err != nil {
			return err
		}
		return guard()
	}
	for _, item := range []struct {
		path     string
		revision recoveryKeyRevision
	}{{paths.v2, disk.primary}, {backupPath, disk.backup}} {
		if err := checkOriginal(); err != nil {
			return err
		}
		if !item.revision.hash.present {
			continue
		}
		archive, err := unusedExternalArchivePath(item.path)
		if err != nil {
			return err
		}
		if err := writeFileAtomicNoReplaceChecked(archive, item.revision.data, checkOriginal); err != nil {
			return fmt.Errorf("не удалось сохранить прежний зашифрованный файл: %w", err)
		}
		if !(recoveryKeyRevision{hash: item.revision.hash}).matches(archive) {
			return ErrVaultV2Corrupt
		}
	}

	// Keep the prior primary until a usable copy of the replacement exists.
	// Once the backup is replaced, finish the primary write if revisions
	// still match, even if the original authentication deadline has elapsed.
	newRevision := recoveryKeyRevision{hash: revisionOf(replacement)}
	if err := writeFileAtomicChecked(backupPath, replacement, checkOriginal); err != nil {
		return errors.Join(errRecoveryKeyCommit, err)
	}
	if err := writeFileAtomicChecked(paths.v2, replacement, func() error {
		return disk.check(disk.primary, newRevision)
	}); err != nil {
		return errors.Join(errRecoveryKeyCommit, err)
	}
	if err := disk.check(newRevision, newRevision); err != nil {
		return errors.Join(errRecoveryKeyCommit, err)
	}
	return nil
}
