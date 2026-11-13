package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"password-saver/crypto"
	"path/filepath"
)

// Account — это структура одной записи (одного сохраненного пароля)
type Account struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Login     string `json:"login"`
	Password  string `json:"password"`
	UpdatedAt int64  `json:"updatedAt"`
}

// Vault — это наше хранилище, массив аккаунтов
type Vault struct {
	Accounts     []Account `json:"accounts"`
	TwoFAEnabled bool      `json:"twoFAEnabled"` // НОВОЕ: Включена ли 2FA
	TwoFASecret  string    `json:"twoFASecret"`  // НОВОЕ: Секретный ключ (будет лежать в зашифрованном виде!)
}

const dataFile = "vault_data.enc" // Имя файла, где всё будет храниться
const maxVaultFileSize = crypto.CiphertextLimit*4/3 + (1 << 20)

var renameVaultFile = os.Rename

// Секретный ключ приложения для подписи файла (HMAC)
// Защищает файл от подмены или изменения сторонними программами
var hmacSecret = []byte("PasswordSaver_MTUSI_SecureKey_2026")

// SaveVault шифрует данные и заменяет контейнер атомарно. Перед заменой сохраняется
// предыдущий зашифрованный контейнер в vault_data.enc.bak.
func SaveVault(cm *crypto.CryptoManager, v *Vault) error {
	return saveVaultToPath(dataFile, cm, v)
}

func saveVaultToPath(path string, cm *crypto.CryptoManager, v *Vault) error {
	// 1. Превращаем структуру Vault в текст (JSON)
	jsonData, err := json.Marshal(v)
	if err != nil {
		return err
	}

	// 2. Шифруем этот JSON
	encryptedData, err := cm.Encrypt(string(jsonData))
	if err != nil {
		return err
	}

	// 3. Превращаем зашифрованные данные снова в JSON
	filePayload, err := json.Marshal(encryptedData)
	if err != nil {
		return err
	}

	// 4. Генерируем HMAC-подпись от зашифрованного payload
	h := hmac.New(sha256.New, hmacSecret)
	h.Write(filePayload)
	signature := h.Sum(nil) // Получаем ровно 32 байта подписи

	// 5. Склеиваем: [JSON зашифрованных данных] + [32 байта подписи]
	finalData := append(filePayload, signature...)

	// Backup только шифротекста; plaintext в резервную копию не попадает.
	previousInfo, err := os.Stat(path)
	if err == nil && previousInfo.Size() > maxVaultFileSize {
		return errors.New("текущий файл хранилища превышает допустимый размер")
	}
	previous, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(previous) > 0 {
		if err := writeFileAtomic(path+".bak", previous); err != nil {
			return fmt.Errorf("не удалось сохранить резервную копию: %w", err)
		}
	}
	return writeFileAtomic(path, finalData)
}

// writeFileAtomic writes in the destination directory, syncs the data, and
// replaces the destination. The fallback preserves and restores the old file
// on platforms where rename cannot replace an existing destination.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameVaultFile(tmpName, path); err == nil {
		return syncDirectory(dir)
	}

	// Windows and some filesystems reject rename over an existing file.
	rollback, err := os.CreateTemp(dir, ".vault-rollback-*")
	if err != nil {
		return err
	}
	rollbackName := rollback.Name()
	if err := rollback.Close(); err != nil {
		os.Remove(rollbackName)
		return err
	}
	if err := os.Remove(rollbackName); err != nil {
		return err
	}
	if err := renameVaultFile(path, rollbackName); err != nil {
		return err
	}
	if err := renameVaultFile(tmpName, path); err != nil {
		if restoreErr := renameVaultFile(rollbackName, path); restoreErr != nil {
			return fmt.Errorf("замена не удалась (%v), восстановление не удалось (%w)", err, restoreErr)
		}
		return err
	}
	if err := os.Remove(rollbackName); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	// Directory syncing is unsupported on some platforms (notably Windows).
	_ = f.Sync()
	return nil
}

// LoadVault читает файл, проверяет целостность по HMAC и расшифровывает пароли
func LoadVault(cm *crypto.CryptoManager) (*Vault, error) {
	// 1. Читаем файл с диска
	info, statErr := os.Stat(dataFile)
	if statErr == nil && info.Size() > maxVaultFileSize {
		return nil, errors.New("файл поврежден: превышен допустимый размер")
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	f, openErr := os.Open(dataFile)
	if openErr != nil && !errors.Is(openErr, os.ErrNotExist) {
		return nil, openErr
	}
	var fileData []byte
	var err error
	if openErr == nil {
		fileData, err = io.ReadAll(io.LimitReader(f, maxVaultFileSize+1))
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(fileData) > maxVaultFileSize {
			return nil, errors.New("файл поврежден: превышен допустимый размер")
		}
	} else {
		err = openErr
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Если файла еще нет (первый запуск), возвращаем пустое хранилище
			return &Vault{Accounts: []Account{}}, nil
		}
		return nil, err
	}

	sigLen := sha256.Size // Размер подписи SHA-256 всегда 32 байта
	if len(fileData) < sigLen {
		return nil, errors.New("файл поврежден: слишком маленький размер")
	}

	// 2. Разделяем данные и подпись
	payload := fileData[:len(fileData)-sigLen]
	receivedSignature := fileData[len(fileData)-sigLen:]

	// 3. Проверяем подлинность файла (HMAC)
	h := hmac.New(sha256.New, hmacSecret)
	h.Write(payload)
	expectedSignature := h.Sum(nil)

	// Безопасное побитовое сравнение подписей (защита от атак по времени)
	if !hmac.Equal(receivedSignature, expectedSignature) {
		return nil, errors.New("КРИТИЧЕСКАЯ ОШИБКА: Файл был изменен или поврежден!")
	}

	// 4. Распаковываем зашифрованную структуру (теперь мы точно знаем, что payload не изменен)
	var encryptedData crypto.EncryptedData
	if err := json.Unmarshal(payload, &encryptedData); err != nil {
		return nil, errors.New("файл поврежден: неверный формат JSON")
	}

	// 5. Расшифровываем
	decryptedJson, err := cm.Decrypt(&encryptedData)
	if err != nil {
		return nil, errors.New("неверный мастер-пароль") // Расшифровка не удалась
	}

	// 6. Превращаем расшифрованный JSON обратно в структуру Vault
	var v Vault
	if err := json.Unmarshal([]byte(decryptedJson), &v); err != nil {
		return nil, err
	}

	return &v, nil
}
