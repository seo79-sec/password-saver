package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
	"path/filepath"
	"sync"
	"time"

	"github.com/pquerna/otp/totp" // НОВОЕ
	"github.com/skip2/go-qrcode"  // НОВОЕ
)

// App struct управляет состоянием приложения и сессией в RAM
type App struct {
	mu               sync.RWMutex
	ctx              context.Context
	cm               *crypto.CryptoManager
	v2Session        *v2VaultSession
	v2Engine         *cryptov2.Engine
	v2Activation     *v2ActivationService
	vault            *Vault
	twoFAVerified    bool // НОВОЕ: Флаг успешного прохождения 2FA
	pendingReset     resetChallenge
	pendingRecover   recoveryChallenge
	idleTimer        *time.Timer
	idleTimeout      time.Duration
	lastActivity     time.Time
	totpFailures     int
	totpBlockedUntil time.Time
}

type resetChallenge struct {
	token   string
	expires time.Time
}
type recoveryChallenge struct {
	token   string
	expires time.Time
	cm      *crypto.CryptoManager
	timer   *time.Timer
}

const challengeLifetime = 2 * time.Minute

var recoveryChallengeLifetime = challengeLifetime

func NewApp() *App {
	return &App{idleTimeout: time.Minute, v2Activation: &v2ActivationService{}}
}

func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ctx = ctx
}

// 1. АВТОРИЗАЦИЯ И БЕЗОПАСНОСТЬ СЕССИИ

// Login проверяет мастер-пароль, верифицирует HMAC целостность и расшифровывает данные
// Вот тут мы явно указываем, что возвращаем ДВА значения: (bool, error)
func (a *App) Login(password string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().Before(a.totpBlockedUntil) {
		return false, errors.New("слишком много неверных кодов 2FA; попробуйте позже")
	}
	// A repeated login starts a fresh authentication flow, including after a
	// previous session had completed the second factor.
	a.logoutLocked()
	a.clearPendingChallengesLocked()
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	if selectionErr != nil {
		vaultActivationMu.Unlock()
		return false, selectionErr
	}
	if selection.ActiveV2 {
		vaultActivationMu.Unlock()
		return false, ErrVaultV2UIUnavailable
	}
	cm, err := crypto.NewCryptoManager(password)
	if err != nil {
		vaultActivationMu.Unlock()
		return false, err
	}

	v, err := LoadVault(cm)
	if err == nil && selection.NeedsV1Record {
		state := vaultSelectorRecord{Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV1}
		if stateErr := writeVaultSelector(vaultPaths(".").selector, state); stateErr != nil {
			wipeVault(v)
			cm.Wipe()
			vaultActivationMu.Unlock()
			return false, stateErr
		}
	}
	vaultActivationMu.Unlock()
	if err != nil {
		cm.Wipe()
		return false, errors.New("неверный мастер-пароль или файл поврежден")
	}

	a.cm = cm
	a.vault = v

	// Если 2FA НЕ включена, мы автоматически считаем её "пройденной"
	a.twoFAVerified = !v.TwoFAEnabled
	a.lastActivity = time.Now()
	a.armIdleTimerLocked()

	// Возвращаем флаг (нужна ли 2FA) и nil (ошибок нет)
	return v.TwoFAEnabled, nil
}

// Logout надежно блокирует хранилище, стирая конфиденциальные данные из RAM
func (a *App) Logout() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logoutLocked()
}

func (a *App) logoutLocked() {
	if a.idleTimer != nil {
		a.idleTimer.Stop()
		a.idleTimer = nil
	}
	// Исправлена опечатка: используем верное имя поля a.cm
	if a.cm != nil {
		a.cm.Wipe() // Принудительно забиваем нулями область RAM с паролем
		a.cm = nil  // Обнуляем указатель сессии
	}
	if a.v2Session != nil {
		a.v2Session.close()
		a.v2Session = nil
	}
	if a.v2Activation != nil {
		a.v2Activation.clearChallenges()
	}
	wipeVault(a.vault)
	a.vault = nil
	a.twoFAVerified = false // Сбрасываем статус 2FA
	a.clearPendingChallengesLocked()
	// Удаляем ссылку на открытые данные аккаунтов, отправляя их под сборщик мусора
}

const maxTOTPFailures = 5
const totpLockoutDuration = time.Minute

func (a *App) armIdleTimerLocked() {
	if a.idleTimer != nil {
		a.idleTimer.Stop()
	}
	if (a.cm == nil && a.v2Session == nil) || a.idleTimeout <= 0 {
		return
	}
	remaining := time.Until(a.lastActivity.Add(a.idleTimeout))
	if remaining < 0 {
		remaining = 0
	}
	a.idleTimer = time.AfterFunc(remaining, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.cm == nil && a.v2Session == nil {
			return
		}
		if time.Since(a.lastActivity) >= a.idleTimeout {
			a.logoutLocked()
			return
		}
		a.armIdleTimerLocked()
	})
}

// SetIdleTimeout accepts only the UI's supported timeout choices.
func (a *App) SetIdleTimeout(minutes int) error {
	if minutes != 1 && minutes != 5 && minutes != 10 && minutes != 15 {
		return errors.New("недопустимый тайм-аут блокировки")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.idleTimeout = time.Duration(minutes) * time.Minute
	if a.cm != nil || a.v2Session != nil {
		a.lastActivity = time.Now()
		a.armIdleTimerLocked()
	}
	return nil
}

// TouchActivity refreshes the backend lock timer; the UI timer is only a convenience.
func (a *App) TouchActivity() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cm != nil || a.v2Session != nil {
		a.lastActivity = time.Now()
		a.armIdleTimerLocked()
	}
}

// CheckInactivity enforces the backend deadline after window focus or resume,
// including cases where operating-system sleep paused frontend timers.
func (a *App) CheckInactivity() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if (a.cm != nil || a.v2Session != nil) && time.Since(a.lastActivity) >= a.idleTimeout {
		a.logoutLocked()
	}
	return a.isLockedLocked()
}

// IsLocked проверяет текущий статус блокировки хранилища
func (a *App) IsLocked() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isLockedLocked()
}

func (a *App) isLockedLocked() bool {
	return (a.cm == nil && a.v2Session == nil) || !a.twoFAVerified
}

// unlockActiveV2ForBackend is intentionally unexported and is not a Wails
// binding. It supports backend tests and future UI integration without
// exposing the DEK or retaining the master password.
func (a *App) unlockActiveV2ForBackend(password, totpCode string, engine *cryptov2.Engine) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().Before(a.totpBlockedUntil) {
		return errors.New("слишком много неверных кодов 2FA; попробуйте позже")
	}
	a.logoutLocked()
	path := filepath.Join(".", dataFileV2)
	session, vault, err := openActiveV2VaultSession(path, engine, password)
	if err != nil {
		return err
	}
	if vault.TwoFAEnabled && !totp.Validate(totpCode, vault.TwoFASecret) {
		session.close()
		wipeVault(vault)
		a.recordTOTPFailureLocked()
		return errors.New("неверный код 2FA")
	}
	a.cm = nil
	a.v2Session = session
	a.vault = vault
	a.twoFAVerified = true
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}
	a.lastActivity = time.Now()
	a.armIdleTimerLocked()
	return nil
}

// confirmV2Activation is an internal backend transition; it is deliberately
// not exported as a Wails method. Any previous v1 or v2 session is closed once
// durable selector state confirms v2, including an uncertain post-sync result.
func (a *App) confirmV2Activation(service *v2ActivationService, token, password, totpCode string, engine *cryptov2.Engine) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.confirmV2ActivationLocked(service, token, password, totpCode, engine)
}

func (a *App) confirmV2ActivationLocked(service *v2ActivationService, token, password, totpCode string, engine *cryptov2.Engine) error {
	err := service.Confirm(token, password, totpCode, engine)
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	vaultActivationMu.Unlock()
	if err == nil || (selectionErr == nil && selection.ActiveV2) {
		a.logoutLocked()
	}
	return err
}

// 2. УПРАВЛЕНИЕ ЗАПИСЯМИ ХРАНИЛИЩА

// GetAccounts возвращает расшифрованные записи для отображения во фронтенде
func (a *App) GetAccounts() ([]Account, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.isLockedLocked() {
		return nil, errors.New("хранилище заблокировано")
	}
	return append([]Account(nil), a.vault.Accounts...), nil
}

func (a *App) updateVault(change func(*Vault)) error {
	before := cloneVault(a.vault)
	change(a.vault)
	if a.v2Session != nil {
		if err := a.v2Session.save(a.vault); err != nil {
			if errors.Is(err, errVaultCommitUncertain) || errors.Is(err, ErrVaultSessionChanged) || errors.Is(err, ErrVaultSelectionAmbiguous) || errors.Is(err, ErrVaultV2NotActive) {
				wipeVault(before)
				a.logoutLocked()
				return err
			}
			wipeVault(a.vault)
			a.vault = before
			return err
		}
		wipeVault(before)
		return nil
	}
	if err := SaveVault(a.cm, a.vault); err != nil {
		if errors.Is(err, errVaultCommitUncertain) {
			return err
		}
		a.vault = before
		return err
	}
	return nil
}

func cloneVault(v *Vault) *Vault {
	if v == nil {
		return nil
	}
	copy := *v
	copy.Accounts = append([]Account(nil), v.Accounts...)
	return &copy
}

// AddAccount генерирует ID, добавляет новую запись и перезаписывает файл с новой HMAC подписью
func (a *App) AddAccount(title, login, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isLockedLocked() {
		return errors.New("хранилище заблокировано")
	}

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	id := hex.EncodeToString(idBytes)

	newAcc := Account{
		ID:        id,
		Title:     title,
		Login:     login,
		Password:  password,
		UpdatedAt: time.Now().Unix(), // Метка для отслеживания старых паролей (180 дней)
	}

	return a.updateVault(func(v *Vault) { v.Accounts = append(v.Accounts, newAcc) })
}

// DeleteAccount удаляет аккаунт по ID и обновляет файл на диске
func (a *App) DeleteAccount(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isLockedLocked() {
		return errors.New("хранилище заблокировано")
	}

	for i, acc := range a.vault.Accounts {
		if acc.ID == id {
			return a.updateVault(func(v *Vault) { v.Accounts = append(v.Accounts[:i], v.Accounts[i+1:]...) })
		}
	}
	return errors.New("запись не найдена")
}

// UpdateAccount изменяет поля существующей записи и перезаписывает защищенный контейнер
func (a *App) UpdateAccount(id string, title string, login string, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isLockedLocked() {
		return errors.New("хранилище заблокировано")
	}

	index := -1
	for i, acc := range a.vault.Accounts {
		if acc.ID == id {
			index = i
			break
		}
	}

	if index < 0 {
		return errors.New("запись не найдена")
	}
	return a.updateVault(func(v *Vault) {
		v.Accounts[index].Title = title
		v.Accounts[index].Login = login
		v.Accounts[index].Password = password
		v.Accounts[index].UpdatedAt = time.Now().Unix()
	})
}

// BeginVaultReset starts a short-lived reset challenge. It guards against an
// accidental reset, but is not an independent security boundary against code
// already running in the app process or a process with direct file access.
// Reset remains available while locked for forgotten passwords.
func (a *App) BeginVaultReset() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.isLockedLocked() {
		return "", errors.New("сначала заблокируйте хранилище")
	}
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	vaultActivationMu.Unlock()
	if selectionErr != nil {
		return "", selectionErr
	}
	if selection.ActiveV2 {
		return "", ErrVaultV2Protected
	}
	if selection.Prepared {
		return "", ErrVaultV2PreparationPending
	}
	token, err := newChallengeToken()
	if err != nil {
		return "", err
	}
	a.pendingReset = resetChallenge{token: token, expires: time.Now().Add(challengeLifetime)}
	return token, nil
}

func (a *App) CancelVaultReset(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if challengeMatches(a.pendingReset.token, token) {
		a.pendingReset = resetChallenge{}
	}
}

// ResetVault consumes the one-time challenge created before the UI asks the
// user to confirm. It does not protect files from another process with direct
// filesystem access.
func (a *App) ResetVault(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.isLockedLocked() {
		return errors.New("сначала заблокируйте хранилище")
	}
	if !challengeValid(a.pendingReset.token, a.pendingReset.expires, token) {
		return errors.New("подтверждение сброса отсутствует или истекло")
	}
	a.pendingReset = resetChallenge{}
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	if selectionErr != nil {
		vaultActivationMu.Unlock()
		return selectionErr
	}
	if selection.ActiveV2 || selection.Prepared {
		vaultActivationMu.Unlock()
		if selection.ActiveV2 {
			return ErrVaultV2Protected
		}
		return ErrVaultV2PreparationPending
	}
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	defer vaultActivationMu.Unlock()
	a.logoutLocked()
	for _, path := range []string{dataFile, dataFile + ".bak"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := syncVaultDirectory("."); err != nil {
		return fmt.Errorf("%w: reset removal durability uncertain: %v", errVaultCommitUncertain, err)
	}
	return nil
}

// PrepareVaultRecovery verifies that the main file is missing or damaged and
// that the backup passes both integrity and password checks. The returned
// short-lived token is consumed only after explicit UI confirmation.
func (a *App) PrepareVaultRecovery(password string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clearPendingRecoveryLocked()
	if !a.isLockedLocked() {
		return "", errors.New("восстановление доступно только на экране входа")
	}
	cm, err := crypto.NewCryptoManager(password)
	if err != nil {
		return "", err
	}
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	if selectionErr != nil {
		vaultActivationMu.Unlock()
		cm.Wipe()
		return "", selectionErr
	}
	if selection.ActiveV2 || selection.Prepared {
		vaultActivationMu.Unlock()
		cm.Wipe()
		if selection.ActiveV2 {
			return "", ErrVaultV2Protected
		}
		return "", ErrVaultV2PreparationPending
	}
	vaultFileMu.Lock()
	_, primaryErr := loadVaultFromPath(cm, dataFile)
	if primaryErr == nil || (!errors.Is(primaryErr, os.ErrNotExist) && !errors.Is(primaryErr, errVaultCorrupt)) {
		vaultFileMu.Unlock()
		vaultActivationMu.Unlock()
		cm.Wipe()
		return "", errors.New("основной файл нельзя безопасно восстановить")
	}
	_, backupErr := loadVaultFromPath(cm, dataFile+".bak")
	vaultFileMu.Unlock()
	vaultActivationMu.Unlock()
	if backupErr != nil {
		cm.Wipe()
		return "", errors.New("резервная копия не прошла проверку целостности или пароля")
	}
	token, err := newChallengeToken()
	if err != nil {
		cm.Wipe()
		return "", err
	}
	a.clearPendingRecoveryLocked()
	expires := time.Now().Add(recoveryChallengeLifetime)
	a.pendingRecover = recoveryChallenge{token: token, expires: expires, cm: cm}
	a.pendingRecover.timer = time.AfterFunc(time.Until(expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.pendingRecover.token, token) && !time.Now().Before(a.pendingRecover.expires) {
			a.clearPendingRecoveryLocked()
		}
	})
	return token, nil
}

func (a *App) CancelVaultRecovery(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if challengeMatches(a.pendingRecover.token, token) {
		a.clearPendingRecoveryLocked()
	}
}

// ConfirmVaultRecovery archives a damaged primary file and restores only the
// backup already validated by PrepareVaultRecovery.
func (a *App) ConfirmVaultRecovery(token string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := a.pendingRecover
	if !challengeValid(pending.token, pending.expires, token) || pending.cm == nil {
		a.clearPendingRecoveryLocked()
		return false, errors.New("подтверждение восстановления отсутствует или истекло")
	}
	transferred := false
	defer func() {
		if !transferred && challengeMatches(a.pendingRecover.token, pending.token) {
			a.clearPendingRecoveryLocked()
		}
	}()
	vaultActivationMu.Lock()
	selection, selectionErr := resolveVaultSelectionLocked(".")
	if selectionErr != nil || selection.ActiveV2 || selection.Prepared {
		vaultActivationMu.Unlock()
		if selectionErr != nil {
			return false, selectionErr
		}
		if selection.ActiveV2 {
			return false, ErrVaultV2Protected
		}
		return false, ErrVaultV2PreparationPending
	}
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	defer vaultActivationMu.Unlock()
	_, primaryErr := loadVaultFromPath(pending.cm, dataFile)
	if primaryErr == nil || (!errors.Is(primaryErr, os.ErrNotExist) && !errors.Is(primaryErr, errVaultCorrupt)) {
		a.clearPendingRecoveryLocked()
		return false, errors.New("основной файл изменился; повторите проверку восстановления")
	}
	backupData, err := recoveryBackupReader(dataFile + ".bak")
	if err != nil {
		return false, err
	}
	recovered, err := loadVaultData(pending.cm, backupData)
	if err != nil {
		return false, errors.New("резервная копия больше не прошла проверку")
	}
	archivePath := ""
	if !errors.Is(primaryErr, os.ErrNotExist) {
		archive, err := os.CreateTemp(".", "vault_data.enc.corrupt-*")
		if err != nil {
			return false, err
		}
		archivePath = archive.Name()
		if err := archive.Close(); err != nil {
			os.Remove(archivePath)
			return false, err
		}
		if err := os.Remove(archivePath); err != nil {
			return false, err
		}
		if err := os.Rename(dataFile, archivePath); err != nil {
			return false, err
		}
	}
	if err := writeFileAtomic(dataFile, backupData); err != nil {
		if errors.Is(err, errVaultCommitUncertain) {
			return false, fmt.Errorf("основной файл восстановлен, но синхронизация каталога не подтверждена: %w", err)
		}
		if archivePath != "" {
			if restoreErr := os.Rename(archivePath, dataFile); restoreErr != nil {
				return false, fmt.Errorf("restore failed (%v); diagnostic file retained at %s: %w", err, archivePath, restoreErr)
			}
		}
		return false, err
	}
	a.cm = pending.cm
	a.vault = recovered
	a.twoFAVerified = !recovered.TwoFAEnabled
	if a.pendingRecover.timer != nil {
		a.pendingRecover.timer.Stop()
	}
	a.pendingRecover = recoveryChallenge{}
	transferred = true
	return recovered.TwoFAEnabled, nil
}

func newChallengeToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func challengeMatches(expected, provided string) bool {
	return expected != "" && len(expected) == len(provided) && subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

func challengeValid(expected string, expires time.Time, provided string) bool {
	return time.Now().Before(expires) && challengeMatches(expected, provided)
}

func (a *App) clearPendingRecoveryLocked() {
	if a.pendingRecover.timer != nil {
		a.pendingRecover.timer.Stop()
	}
	if a.pendingRecover.cm != nil {
		a.pendingRecover.cm.Wipe()
	}
	a.pendingRecover = recoveryChallenge{}
}

func (a *App) clearPendingChallengesLocked() {
	a.pendingReset = resetChallenge{}
	a.clearPendingRecoveryLocked()
}

// --- ЛОГИКА ДВУХФАКТОРНОЙ АУТЕНТИФИКАЦИИ ---

// TOTPSetup содержит данные для отображения QR-кода во фронтенде
type TOTPSetup struct {
	Secret string `json:"secret"`
	QRCode string `json:"qrCode"`
}

// Generate2FA создает новый секретный ключ и рисует QR-код
func (a *App) Generate2FA() (*TOTPSetup, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isLockedLocked() {
		return nil, errors.New("хранилище заблокировано")
	}

	// Генерируем секрет специально для твоего приложения
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "PasswordSaver",
		AccountName: "MyVault",
	})
	if err != nil {
		return nil, err
	}

	// Создаем картинку QR-кода
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	// Кодируем картинку в Base64, чтобы передать в Svelte
	base64PNG := base64.StdEncoding.EncodeToString(png)

	return &TOTPSetup{
		Secret: key.Secret(),
		QRCode: "data:image/png;base64," + base64PNG,
	}, nil
}

// ConfirmAndEnable2FA проверяет первый код с телефона и навсегда включает 2FA
func (a *App) ConfirmAndEnable2FA(secret, code string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isLockedLocked() {
		return errors.New("хранилище заблокировано")
	}

	// Проверяем, правильный ли код ввел пользователь
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return err
	}
	valid := totp.Validate(code, secret)
	if !valid {
		a.recordTOTPFailureLocked()
		return errors.New("неверный код подтверждения")
	}
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}

	// Сохраняем настройки в хранилище
	return a.updateVault(func(v *Vault) {
		v.TwoFAEnabled = true
		v.TwoFASecret = secret
	})
}

// Verify2FA используется при логине для ввода кода с телефона
func (a *App) Verify2FA(code string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Either format can hold a pending password-authenticated session. The
	// second factor is always checked in Go before account methods unlock.
	if (a.cm == nil && a.v2Session == nil) || a.vault == nil {
		return errors.New("сначала введите мастер-пароль")
	}
	if a.twoFAVerified {
		return nil
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return err
	}

	if !a.vault.TwoFAEnabled {
		return nil // 2FA не включена, пропускаем
	}

	valid := totp.Validate(code, a.vault.TwoFASecret)
	if !valid {
		a.recordTOTPFailureLocked()
		return errors.New("неверный код 2FA")
	}

	// Код верный! Разблокируем полный доступ к функциям приложения
	a.twoFAVerified = true
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}
	a.lastActivity = time.Now()
	a.armIdleTimerLocked()
	return nil
}

func (a *App) checkTOTPAttemptsLocked() error {
	if time.Now().Before(a.totpBlockedUntil) {
		return errors.New("слишком много неверных кодов 2FA; попробуйте позже")
	}
	return nil
}

func (a *App) recordTOTPFailureLocked() {
	a.totpFailures++
	if a.totpFailures >= maxTOTPFailures {
		a.totpBlockedUntil = time.Now().Add(totpLockoutDuration)
		a.totpFailures = 0
	}
}
