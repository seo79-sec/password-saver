package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

const maxExternalImportRecords = 10000

var (
	errExternalImportExpired = errors.New("проверка копии отсутствует или истекла; выберите файл заново")
	errExternalImportChanged = errors.New("выбранная копия изменилась; повторите проверку")
	errExternalImportChoice  = errors.New("выбор записей недействителен")
	errExternalImportLocked  = errors.New("разблокируйте активное хранилище v2")
)

type ExternalImportSelection struct {
	Token    string `json:"token"`
	FileName string `json:"fileName"`
}

type ExternalImportRow struct {
	Index    int    `json:"index"`
	Title    string `json:"title"`
	Login    string `json:"login"`
	Conflict bool   `json:"conflict"`
}

type ExternalImportReview struct {
	Token        string              `json:"token"`
	FileName     string              `json:"fileName"`
	AccountCount int                 `json:"accountCount"`
	TOTPEnabled  bool                `json:"totpEnabled"`
	Records      []ExternalImportRow `json:"records"`
}

type ExternalImportChoice struct {
	Index    int  `json:"index"`
	Separate bool `json:"separate"`
}

type externalImportChallenge struct {
	token      string
	expires    time.Time
	timer      *time.Timer
	path       string
	forImport  bool
	session    *v2VaultSession
	sourceInfo os.FileInfo
	sourceHash [sha256.Size]byte
	target     externalImportTarget
	records    []Account
}

type externalImportTarget struct {
	directory string
	info      os.FileInfo
	selector  vaultSelectorRecord
	primary   passwordChangeRevision
	backup    passwordChangeRevision
}

func (a *App) requireExternalImportSessionLocked() error {
	if a.v2Session != nil && a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout {
		a.logoutLocked()
	}
	if a.isLockedLocked() || a.vault == nil || a.v2Session.isClosed() {
		return errExternalImportLocked
	}
	return nil
}

// SelectExternalV2Import takes no path or credentials from the caller. A
// selection made for verification can never authorize an import.
func (a *App) SelectExternalV2Import(forImport bool) (ExternalImportSelection, error) {
	a.mu.Lock()
	if err := a.requireExternalImportSessionLocked(); err != nil {
		a.mu.Unlock()
		return ExternalImportSelection{}, err
	}
	if a.backupDialogOpen || a.pendingExternalImport.token != "" {
		a.mu.Unlock()
		return ExternalImportSelection{}, errors.New("закройте текущую операцию с копией")
	}
	session, generation, ctx := a.v2Session, a.backupDialogGeneration, a.ctx
	a.backupDialogOpen = true
	a.mu.Unlock()

	path, dialogErr := chooseBackupImportFile(ctx)

	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.backupDialogGeneration {
		return ExternalImportSelection{}, errExternalImportExpired
	}
	a.backupDialogOpen = false
	if err := a.requireExternalImportSessionLocked(); err != nil || a.v2Session != session {
		return ExternalImportSelection{}, errExternalImportLocked
	}
	if dialogErr != nil || path == "" {
		return ExternalImportSelection{}, dialogErr
	}
	directory := filepath.Dir(session.path)
	path, err := externalImportPath(path, directory)
	if err != nil {
		return ExternalImportSelection{}, err
	}
	token, err := a.setExternalImportLocked(externalImportChallenge{
		path: path, forImport: forImport, session: session,
	})
	if err != nil {
		return ExternalImportSelection{}, err
	}
	return ExternalImportSelection{Token: token, FileName: filepath.Base(path)}, nil
}

// CheckSelectedExternalV2Backup is read only. In import mode it also enables a
// separate confirmation, exposing titles and logins but never passwords.
func (a *App) CheckSelectedExternalV2Backup(token, password, code string) (ExternalImportReview, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.requireExternalImportSessionLocked(); err != nil {
		return ExternalImportReview{}, err
	}
	selected := a.pendingExternalImport
	if selected.session != a.v2Session || selected.sourceInfo != nil || !challengeMatches(selected.token, token) {
		return ExternalImportReview{}, errExternalImportExpired
	}
	a.clearExternalImportLocked()
	if !time.Now().Before(selected.expires) {
		return ExternalImportReview{}, errExternalImportExpired
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return ExternalImportReview{}, err
	}
	path, err := externalImportPath(selected.path, filepath.Dir(selected.session.path))
	if err != nil {
		return ExternalImportReview{}, err
	}
	data, info, err := readV2FileSnapshot(path)
	if err != nil {
		return ExternalImportReview{}, err
	}
	plaintext, err := selected.session.engine.Decrypt(password, data)
	if err != nil {
		return ExternalImportReview{}, mapV2RecoveryError(err)
	}
	var decoded *Vault
	err = json.Unmarshal(plaintext, &decoded)
	wipeBytes(plaintext)
	defer func() { wipeVault(decoded) }()
	if err != nil || decoded == nil {
		return ExternalImportReview{}, ErrVaultV2Corrupt
	}
	if decoded.TwoFAEnabled {
		if !totp.Validate(code, decoded.TwoFASecret) {
			a.recordTOTPFailureLocked()
			return ExternalImportReview{}, errors.New("неверный код 2FA")
		}
		a.totpFailures, a.totpBlockedUntil = 0, time.Time{}
	}
	if err := a.requireExternalImportSessionLocked(); err != nil {
		return ExternalImportReview{}, err
	}
	result := ExternalImportReview{
		FileName: filepath.Base(path), AccountCount: len(decoded.Accounts), TOTPEnabled: decoded.TwoFAEnabled,
		Records: []ExternalImportRow{},
	}
	if !selected.forImport {
		return result, nil
	}
	if len(decoded.Accounts) > maxExternalImportRecords {
		return ExternalImportReview{}, errors.New("в копии больше 10 000 записей; предпросмотр импорта недоступен")
	}
	target, err := readExternalImportTarget(selected.session)
	if err != nil {
		if errors.Is(err, ErrVaultSessionChanged) || errors.Is(err, ErrVaultSelectionAmbiguous) {
			a.logoutLocked()
		}
		return ExternalImportReview{}, err
	}
	result.Records = externalImportRows(a.vault.Accounts, decoded.Accounts)
	selected.sourceInfo = info
	selected.sourceHash = sha256.Sum256(data)
	selected.target = target
	if err := a.requireExternalImportSessionLocked(); err != nil {
		return ExternalImportReview{}, err
	}
	selected.records = decoded.Accounts
	decoded.Accounts = nil // ownership transfers to the expiring capability
	result.Token, err = a.setExternalImportLocked(selected)
	if err != nil {
		clear(selected.records)
		return ExternalImportReview{}, err
	}
	return result, nil
}

// ConfirmExternalV2Import commits all accepted choices as one vault revision.
// No current entry is replaced. The destination session provides its own DEK
// and wrapper, and the copied settings come exclusively from the destination.
func (a *App) ConfirmExternalV2Import(token string, choices []ExternalImportChoice) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.requireExternalImportSessionLocked(); err != nil {
		return 0, err
	}
	pending := a.pendingExternalImport
	if pending.session != a.v2Session || pending.sourceInfo == nil || !challengeMatches(pending.token, token) {
		return 0, errExternalImportExpired
	}
	defer a.clearExternalImportLocked()
	if !time.Now().Before(pending.expires) {
		return 0, errExternalImportExpired
	}
	if pending.session.digest != pending.target.primary.digest {
		return 0, errors.New("основное хранилище изменилось после предпросмотра; повторите проверку копии")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return 0, err
	}
	if len(choices) == 0 || len(choices) > len(pending.records) {
		return 0, errExternalImportChoice
	}
	seen := make(map[int]struct{}, len(choices))
	for _, choice := range choices {
		if choice.Index < 0 || choice.Index >= len(pending.records) {
			return 0, errExternalImportChoice
		}
		if _, duplicate := seen[choice.Index]; duplicate {
			return 0, errExternalImportChoice
		}
		seen[choice.Index] = struct{}{}
	}
	if err := pending.checkSource(); err != nil {
		return 0, err
	}
	if err := pending.target.check(false); err != nil {
		a.logoutLocked()
		return 0, err
	}
	next := cloneVault(a.vault)
	defer func() { wipeVault(next) }()
	keys, ids := importExistingEntries(next.Accounts)
	for _, choice := range choices {
		account := pending.records[choice.Index]
		key := importKey(account)
		if _, exists := keys[key]; exists && !choice.Separate {
			continue
		}
		id, err := newChallengeToken()
		if err != nil {
			return 0, err
		}
		if _, exists := ids[id]; exists {
			return 0, errors.New("не удалось выделить новый идентификатор записи")
		}
		ids[id], keys[key] = struct{}{}, struct{}{}
		account.ID = id
		next.Accounts = append(next.Accounts, account)
	}
	imported := len(next.Accounts) - len(a.vault.Accounts)
	if imported == 0 {
		return 0, nil
	}
	err := pending.session.saveChecked(next, func(backupWritten bool) error {
		if err := pending.target.check(backupWritten); err != nil {
			return err
		}
		if err := pending.checkSource(); err != nil {
			return err
		}
		if !backupWritten && !time.Now().Before(pending.expires) {
			return errExternalImportExpired
		}
		if !backupWritten && a.idleTimeout > 0 && time.Since(a.lastActivity) >= a.idleTimeout {
			return errExternalImportLocked
		}
		return nil
	})
	if err != nil {
		if pending.session.isClosed() || errors.Is(err, errVaultCommitUncertain) ||
			errors.Is(err, ErrVaultSessionChanged) || errors.Is(err, errExternalImportLocked) {
			a.logoutLocked()
		}
		return 0, err
	}
	wipeVault(a.vault)
	a.vault = next
	next = nil
	return imported, nil
}

func (a *App) CancelExternalV2Import(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if challengeMatches(a.pendingExternalImport.token, token) {
		a.clearExternalImportLocked()
	}
}

func (a *App) setExternalImportLocked(pending externalImportChallenge) (string, error) {
	token, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	pending.token = token
	pending.expires = time.Now().Add(challengeLifetime)
	pending.timer = time.AfterFunc(time.Until(pending.expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.pendingExternalImport.token, token) {
			a.clearExternalImportLocked()
		}
	})
	a.pendingExternalImport = pending
	return token, nil
}

func (a *App) clearExternalImportLocked() {
	if a.pendingExternalImport.timer != nil {
		a.pendingExternalImport.timer.Stop()
	}
	clear(a.pendingExternalImport.records)
	a.pendingExternalImport = externalImportChallenge{}
}

type accountImportKey struct{ title, login string }

func importKey(account Account) accountImportKey {
	title, _, _ := strings.Cut(account.Title, "|||")
	return accountImportKey{strings.ToLower(strings.TrimSpace(title)), strings.ToLower(strings.TrimSpace(account.Login))}
}

func importExistingEntries(accounts []Account) (map[accountImportKey]struct{}, map[string]struct{}) {
	keys := make(map[accountImportKey]struct{}, len(accounts))
	ids := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		keys[importKey(account)] = struct{}{}
		ids[account.ID] = struct{}{}
	}
	return keys, ids
}

func externalImportRows(current, source []Account) []ExternalImportRow {
	keys, _ := importExistingEntries(current)
	counts := make(map[accountImportKey]int, len(source))
	for _, account := range source {
		counts[importKey(account)]++
	}
	rows := make([]ExternalImportRow, 0, len(source))
	for i, account := range source {
		key := importKey(account)
		_, exists := keys[key]
		rows = append(rows, ExternalImportRow{Index: i, Title: account.Title, Login: account.Login, Conflict: exists || counts[key] > 1})
	}
	return rows
}

func externalImportPath(path, vaultDir string) (string, error) {
	path, err := externalBackupPath(path, vaultDir)
	if err != nil {
		return "", err
	}
	// Compare directory identity as well as spelling, to reject aliases of
	// the managed vault directory, e.g. NTFS short path names.
	vaultInfo, err := passwordChangeDirectoryInfo(vaultDir)
	if err != nil {
		return "", err
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return "", err
		}
		if os.SameFile(vaultInfo, info) {
			return "", errors.New("выберите файл вне папки активного хранилища")
		}
		if parent == filepath.Dir(parent) {
			return path, nil
		}
	}
}

func (p externalImportChallenge) checkSource() error {
	path, err := externalImportPath(p.path, p.target.directory)
	if err != nil {
		return errExternalImportChanged
	}
	data, info, err := readV2FileSnapshot(path)
	if err != nil || !os.SameFile(info, p.sourceInfo) || sha256.Sum256(data) != p.sourceHash {
		return errExternalImportChanged
	}
	return nil
}

// Resolve the current route without applying scaffold or permissions. Lock
// order is App → selector → v2 file, as elsewhere when the session is read.
func readExternalImportTarget(session *v2VaultSession) (externalImportTarget, error) {
	dir := filepath.Dir(session.path)
	route, err := discoverStorageRoute()
	if err != nil || route.State != storageRouteReady || !sameStoragePath(route.Location.Root, dir) {
		return externalImportTarget{}, errors.Join(ErrVaultSessionChanged, err)
	}
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	info, err := passwordChangeDirectoryInfo(dir)
	if err != nil {
		return externalImportTarget{}, err
	}
	paths := vaultPaths(dir)
	selector, err := readVaultSelector(paths.selector)
	if err != nil || validateVaultSelectorRecord(selector) != nil || selector.Mode != selectorActiveV2 {
		return externalImportTarget{}, ErrVaultSelectionAmbiguous
	}
	primary := passwordChangeRevision{present: true, digest: session.digest}
	if !primary.matches(paths.v2) {
		return externalImportTarget{}, ErrVaultSessionChanged
	}
	backup, err := readPasswordChangeRevision(paths.v2 + ".bak")
	if err != nil {
		return externalImportTarget{}, err
	}
	return externalImportTarget{directory: dir, info: info, selector: selector, primary: primary, backup: backup}, nil
}

func (target externalImportTarget) check(backupWritten bool) error {
	route, err := discoverStorageRoute()
	if err != nil || route.State != storageRouteReady || !sameStoragePath(route.Location.Root, target.directory) {
		return ErrVaultSessionChanged
	}
	info, err := passwordChangeDirectoryInfo(target.directory)
	if err != nil || !os.SameFile(target.info, info) {
		return ErrVaultSessionChanged
	}
	paths := vaultPaths(target.directory)
	selector, err := readVaultSelector(paths.selector)
	if err != nil || selector != target.selector {
		return ErrVaultSessionChanged
	}
	backup := target.backup
	if backupWritten {
		backup = target.primary
	}
	if !target.primary.matches(paths.v2) || !backup.matches(paths.v2+".bak") {
		return fmt.Errorf("%w: снимки основного файла или резервной копии изменились", ErrVaultSessionChanged)
	}
	return nil
}
