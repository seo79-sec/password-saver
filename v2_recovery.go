package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	cryptov2 "password-saver/crypto/v2"
)

// v2RecoveryChallenge retains the exact authenticated backup bytes and the
// already-unwrapped session until explicit confirmation. Expiry, cancellation,
// logout, and every failed confirmation clear its key and plaintext state.
type v2RecoveryChallenge struct {
	token         string
	expires       time.Time
	timer         *time.Timer
	selector      vaultSelectorRecord
	backupBytes   []byte
	backupDigest  [sha256.Size]byte
	primaryBytes  []byte
	primaryExists bool
	primaryDigest [sha256.Size]byte
	session       *v2VaultSession
	vault         *Vault
}

// PrepareV2VaultRecovery authenticates a v2 backup while the app is locked.
// It refuses recovery if the primary still opens with this password. No file
// is changed until ConfirmV2VaultRecovery consumes the explicit challenge.
func (a *App) PrepareV2VaultRecovery(password string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// A session waiting for TOTP is still a live, password-authenticated
	// session with key material. isLockedLocked alone is insufficient because
	// it also returns true while the second factor is pending.
	if a.cm != nil || a.v2Session != nil || a.vault != nil || a.twoFAVerified {
		return "", errors.New("восстановление доступно только после полного выхода из хранилища")
	}
	if a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil {
		return "", errors.New("сначала отмените или дождитесь завершения предыдущей операции восстановления")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return "", err
	}
	engine, err := a.v2EngineLocked()
	if err != nil {
		return "", err
	}

	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return "", err
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 {
		return "", ErrVaultSelectionAmbiguous
	}

	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	primaryBytes, primaryErr := readV2File(paths.v2)
	primaryExists := primaryErr == nil
	if errors.Is(primaryErr, os.ErrNotExist) {
		primaryBytes = nil
	} else if primaryErr != nil {
		// Do not overwrite files that cannot be safely snapshotted for
		// diagnostics, including non-regular or over-limit files.
		return "", primaryErr
	} else {
		if recoveryHeaderIsUnsupported(primaryBytes) {
			return "", ErrVaultUnsupportedFormat
		}
		if primaryVault, openErr := decryptV2VaultData(primaryBytes, engine, password); openErr == nil {
			wipeVault(primaryVault)
			return "", errors.New("основное хранилище открывается; восстановление резервной копии не требуется")
		} else if !errors.Is(openErr, ErrVaultV2Authentication) && !errors.Is(openErr, ErrVaultV2Corrupt) {
			return "", openErr
		}
	}

	backupBytes, err := readV2File(paths.v2 + ".bak")
	if err != nil {
		return "", errors.New("резервная копия v2 отсутствует или недоступна")
	}
	cryptoSession, plaintext, err := engine.Unlock(password, backupBytes)
	if err != nil {
		return "", mapV2RecoveryError(err)
	}
	defer wipeBytes(plaintext)
	var recovered Vault
	if err := json.Unmarshal(plaintext, &recovered); err != nil {
		cryptoSession.Close()
		return "", ErrVaultV2Corrupt
	}

	token, err := newChallengeToken()
	if err != nil {
		cryptoSession.Close()
		wipeVault(&recovered)
		return "", err
	}
	absPath, err := filepath.Abs(paths.v2)
	if err != nil {
		cryptoSession.Close()
		wipeVault(&recovered)
		return "", err
	}
	expires := time.Now().Add(recoveryChallengeLifetime)
	challenge := v2RecoveryChallenge{
		token: token, expires: expires, selector: selector,
		backupBytes: append([]byte(nil), backupBytes...), backupDigest: sha256.Sum256(backupBytes),
		primaryBytes: append([]byte(nil), primaryBytes...), primaryExists: primaryExists,
		session: &v2VaultSession{crypto: cryptoSession, engine: engine, path: absPath, digest: sha256.Sum256(backupBytes)},
		vault:   &recovered,
	}
	if primaryExists {
		challenge.primaryDigest = sha256.Sum256(primaryBytes)
	}
	a.pendingV2Recover = challenge
	a.pendingV2Recover.timer = time.AfterFunc(time.Until(expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.pendingV2Recover.token, token) && !time.Now().Before(a.pendingV2Recover.expires) {
			a.clearPendingV2RecoveryLocked()
		}
	})
	return token, nil
}

// recoveryHeaderIsUnsupported inspects format metadata independently of the
// canonical parser. This deliberately blocks backup recovery if even a
// partially readable header declares another format, version, AEAD, or KDF.
// Corrupt bytes without recognizable future-format metadata can proceed only
// through backup authentication and the separate user confirmation.
func recoveryHeaderIsUnsupported(data []byte) bool {
	fields, duplicateField := readPartialJSONObject(data)
	if duplicateField {
		// A duplicate metadata key is ambiguous and noncanonical. Refuse to
		// interpret it as a repairable current-format container.
		return true
	}
	format, hasFormat := rawJSONString(fields["format"])
	version, hasVersion := rawJSONUint(fields["version"])
	aead, hasAEAD := rawJSONString(fields["aead"])
	if hasFormat && format != cryptov2.FormatID {
		return true
	}
	if hasFormat && format == cryptov2.FormatID && hasVersion && version != cryptov2.FormatVersion && version != cryptov2.RecoveryFormatVersion {
		return true
	}
	if hasFormat && hasAEAD && aead != cryptov2.AEADAES256GCM {
		return true
	}
	if hasFormat {
		slot, duplicate := readPartialJSONObject(fields["recovery"])
		slotVersion, hasSlotVersion := rawJSONUint(slot["version"])
		if duplicate || (hasSlotVersion && slotVersion != cryptov2.RecoverySlotVersion) {
			return true
		}
		var kdf struct {
			ID      string `json:"id"`
			Version uint32 `json:"version"`
		}
		if json.Unmarshal(fields["kdf"], &kdf) == nil &&
			(kdf.ID != cryptov2.KDFArgon2id || kdf.Version != cryptov2.Argon2idVersion) {
			return true
		}
	}
	return false
}

// readPartialJSONObject retains top-level values decoded before a JSON parse
// error. Recovery must still recognize an unsupported version or algorithm
// when later bytes in that container are truncated or damaged.
func readPartialJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	fields := make(map[string]json.RawMessage)
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fields, false
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			break
		}
		key, ok := keyToken.(string)
		if !ok {
			break
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			break
		}
		if _, exists := fields[key]; exists {
			return fields, true
		}
		fields[key] = append(json.RawMessage(nil), value...)
	}
	return fields, false
}

func rawJSONString(value json.RawMessage) (string, bool) {
	var result string
	if len(value) == 0 || json.Unmarshal(value, &result) != nil {
		return "", false
	}
	return result, true
}

func rawJSONUint(value json.RawMessage) (uint64, bool) {
	if len(value) == 0 {
		return 0, false
	}
	result, err := strconv.ParseUint(string(value), 10, 64)
	return result, err == nil
}

// ConfirmV2VaultRecovery archives a damaged primary without replacing it in
// place, then atomically restores exactly the backup bytes authenticated by
// PrepareV2VaultRecovery. The selector stays v2-active throughout.
func (a *App) ConfirmV2VaultRecovery(token string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := a.pendingV2Recover
	if !challengeValid(pending.token, pending.expires, token) || pending.session == nil || pending.vault == nil {
		a.clearPendingV2RecoveryLocked()
		return false, errors.New("подтверждение восстановления v2 отсутствует или истекло")
	}
	transferred := false
	defer func() {
		if !transferred && challengeMatches(a.pendingV2Recover.token, pending.token) {
			a.clearPendingV2RecoveryLocked()
		}
	}()

	directory, err := activeVaultStorageDirectory()
	if err != nil {
		return false, err
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 || selector != pending.selector {
		return false, ErrVaultSelectionAmbiguous
	}

	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	currentBackup, err := readV2File(paths.v2 + ".bak")
	if err != nil || !bytes.Equal(currentBackup, pending.backupBytes) || sha256.Sum256(currentBackup) != pending.backupDigest {
		return false, errors.New("резервная копия изменилась; повторите проверку восстановления")
	}
	if !v2RecoveryFileMatches(paths.v2, pending.primaryExists, pending.primaryBytes, pending.primaryDigest) {
		return false, errors.New("основное хранилище изменилось; повторите проверку восстановления")
	}

	if pending.primaryExists {
		archivePath, err := unusedCorruptArchivePath(paths.v2)
		if err != nil {
			return false, err
		}
		if err := writeFileAtomicNoReplace(archivePath, pending.primaryBytes); err != nil {
			return false, fmt.Errorf("повреждённое хранилище не удалось сохранить для диагностики: %w", err)
		}
		archived, err := readV2File(archivePath)
		if err != nil || !bytes.Equal(archived, pending.primaryBytes) {
			return false, errors.New("архив повреждённого хранилища не прошёл проверку")
		}
	}
	// Recheck both file snapshots after archiving and immediately before the
	// atomic replacement to catch edits by processes that do not share our locks.
	if !v2RecoveryFileMatches(paths.v2, pending.primaryExists, pending.primaryBytes, pending.primaryDigest) {
		return false, errors.New("основное хранилище изменилось; резервная копия не восстановлена")
	}
	currentBackup, err = readV2File(paths.v2 + ".bak")
	if err != nil || !bytes.Equal(currentBackup, pending.backupBytes) || sha256.Sum256(currentBackup) != pending.backupDigest {
		return false, errors.New("резервная копия изменилась; восстановление отменено")
	}
	selector, err = readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 || selector != pending.selector {
		return false, ErrVaultSelectionAmbiguous
	}
	if err := writeFileAtomic(paths.v2, pending.backupBytes); err != nil {
		if errors.Is(err, errVaultCommitUncertain) {
			return false, fmt.Errorf("состояние восстановления неоднозначно; резервная копия сохранена, повторно проверьте вход: %w", err)
		}
		return false, err
	}
	a.v2Session = pending.session
	a.cm = nil
	a.vault = pending.vault
	needsTOTP := pending.vault.TwoFAEnabled
	a.twoFAVerified = !needsTOTP
	if !needsTOTP {
		a.totpFailures = 0
		a.totpBlockedUntil = time.Time{}
	}
	a.lastActivity = time.Now()
	a.armIdleTimerLocked()
	transferred = true
	a.clearPendingV2RecoveryLockedWithoutSession()
	return needsTOTP, nil
}

// CancelV2VaultRecovery clears an unconsumed recovery challenge.
func (a *App) CancelV2VaultRecovery(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if challengeMatches(a.pendingV2Recover.token, token) {
		a.clearPendingV2RecoveryLocked()
	}
}

func (a *App) clearPendingV2RecoveryLocked() {
	if a.pendingV2Recover.timer != nil {
		a.pendingV2Recover.timer.Stop()
	}
	if a.pendingV2Recover.session != nil {
		a.pendingV2Recover.session.close()
	}
	if a.pendingV2Recover.vault != nil {
		wipeVault(a.pendingV2Recover.vault)
	}
	wipeBytes(a.pendingV2Recover.backupBytes)
	wipeBytes(a.pendingV2Recover.primaryBytes)
	a.pendingV2Recover = v2RecoveryChallenge{}
}

// clearPendingV2RecoveryLockedWithoutSession transfers the session and Vault
// into App state before clearing the remaining challenge buffers.
func (a *App) clearPendingV2RecoveryLockedWithoutSession() {
	pending := a.pendingV2Recover
	if pending.timer != nil {
		pending.timer.Stop()
	}
	wipeBytes(pending.backupBytes)
	wipeBytes(pending.primaryBytes)
	a.pendingV2Recover = v2RecoveryChallenge{}
}

func unusedCorruptArchivePath(path string) (string, error) {
	dir := filepath.Dir(path)
	pattern := filepath.Base(path) + ".corrupt-*"
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	archive := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(archive)
		return "", err
	}
	if err := os.Remove(archive); err != nil {
		return "", err
	}
	return archive, nil
}

func mapV2RecoveryError(err error) error {
	switch {
	case errors.Is(err, cryptov2.ErrAuthentication):
		return ErrVaultV2Authentication
	case errors.Is(err, cryptov2.ErrInvalidContainer), errors.Is(err, cryptov2.ErrInputTooLarge):
		return ErrVaultV2Corrupt
	case errors.Is(err, cryptov2.ErrUnsupportedFormat), errors.Is(err, cryptov2.ErrUnsupportedAlgorithm):
		return ErrVaultUnsupportedFormat
	default:
		return err
	}
}

func v2RecoveryFileMatches(path string, expectedExists bool, expected []byte, digest [sha256.Size]byte) bool {
	current, err := readV2File(path)
	if !expectedExists {
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && bytes.Equal(current, expected) && sha256.Sum256(current) == digest
}
