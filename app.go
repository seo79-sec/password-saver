package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"password-saver/crypto"
	"time"

	"github.com/pquerna/otp/totp" // НОВОЕ
	"github.com/skip2/go-qrcode"  // НОВОЕ
)

// App struct управляет состоянием приложения и сессией в RAM
type App struct {
	ctx           context.Context
	cm            *crypto.CryptoManager
	vault         *Vault
	twoFAVerified bool // НОВОЕ: Флаг успешного прохождения 2FA
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// 1. АВТОРИЗАЦИЯ И БЕЗОПАСНОСТЬ СЕССИИ

// Login проверяет мастер-пароль, верифицирует HMAC целостность и расшифровывает данные
// Вот тут мы явно указываем, что возвращаем ДВА значения: (bool, error)
func (a *App) Login(password string) (bool, error) {
	// A repeated login starts a fresh authentication flow, including after a
	// previous session had completed the second factor.
	a.Logout()
	cm, err := crypto.NewCryptoManager(password)
	if err != nil {
		return false, err
	}

	v, err := LoadVault(cm)
	if err != nil {
		cm.Wipe()
		return false, errors.New("неверный мастер-пароль или файл поврежден")
	}

	a.cm = cm
	a.vault = v

	// Если 2FA НЕ включена, мы автоматически считаем её "пройденной"
	a.twoFAVerified = !v.TwoFAEnabled

	// Возвращаем флаг (нужна ли 2FA) и nil (ошибок нет)
	return v.TwoFAEnabled, nil
}

// Logout надежно блокирует хранилище, стирая конфиденциальные данные из RAM
func (a *App) Logout() {
	// Исправлена опечатка: используем верное имя поля a.cm
	if a.cm != nil {
		a.cm.Wipe() // Принудительно забиваем нулями область RAM с паролем
		a.cm = nil  // Обнуляем указатель сессии
	}
	a.vault = nil
	a.twoFAVerified = false // Сбрасываем статус 2FA
	// Удаляем ссылку на открытые данные аккаунтов, отправляя их под сборщик мусора
}

// IsLocked проверяет текущий статус блокировки хранилища
func (a *App) IsLocked() bool {
	return a.cm == nil || !a.twoFAVerified
}

// 2. УПРАВЛЕНИЕ ЗАПИСЯМИ ХРАНИЛИЩА

// GetAccounts возвращает расшифрованные записи для отображения во фронтенде
func (a *App) GetAccounts() ([]Account, error) {
	if a.IsLocked() {
		return nil, errors.New("хранилище заблокировано")
	}
	return append([]Account(nil), a.vault.Accounts...), nil
}

func (a *App) updateVault(change func(*Vault)) error {
	before := cloneVault(a.vault)
	change(a.vault)
	if err := SaveVault(a.cm, a.vault); err != nil {
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
	if a.IsLocked() {
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
	if a.IsLocked() {
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
	if a.IsLocked() {
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

// ResetVault выполняет экстренный сброс: затирает RAM и удаляет физический файл с диска
func (a *App) ResetVault() error {
	a.Logout()
	// Reset remains available while locked so a forgotten master password can
	// still reset the vault. The UI asks for explicit confirmation.
	for _, path := range []string{dataFile, dataFile + ".bak"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// --- ЛОГИКА ДВУХФАКТОРНОЙ АУТЕНТИФИКАЦИИ ---

// TOTPSetup содержит данные для отображения QR-кода во фронтенде
type TOTPSetup struct {
	Secret string `json:"secret"`
	QRCode string `json:"qrCode"`
}

// Generate2FA создает новый секретный ключ и рисует QR-код
func (a *App) Generate2FA() (*TOTPSetup, error) {
	if a.IsLocked() {
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
	if a.IsLocked() {
		return errors.New("хранилище заблокировано")
	}

	// Проверяем, правильный ли код ввел пользователь
	valid := totp.Validate(code, secret)
	if !valid {
		return errors.New("неверный код подтверждения")
	}

	// Сохраняем настройки в хранилище
	return a.updateVault(func(v *Vault) {
		v.TwoFAEnabled = true
		v.TwoFASecret = secret
	})
}

// Verify2FA используется при логине для ввода кода с телефона
func (a *App) Verify2FA(code string) error {
	// Если нет крипто-менеджера, значит мастер-пароль еще не вводили
	if a.cm == nil || a.vault == nil {
		return errors.New("сначала введите мастер-пароль")
	}
	if a.twoFAVerified {
		return nil
	}

	if !a.vault.TwoFAEnabled {
		return nil // 2FA не включена, пропускаем
	}

	valid := totp.Validate(code, a.vault.TwoFASecret)
	if !valid {
		return errors.New("неверный код 2FA")
	}

	// Код верный! Разблокируем полный доступ к функциям приложения
	a.twoFAVerified = true
	return nil
}
