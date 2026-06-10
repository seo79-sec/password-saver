package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"password-saver/crypto"
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

// Секретный ключ приложения для подписи файла (HMAC)
// Защищает файл от подмены или изменения сторонними программами
var hmacSecret = []byte("PasswordSaver_MTUSI_SecureKey_2026")

// SaveVault шифрует и сохраняет все пароли в файл, добавляя проверку целостности (HMAC)
func SaveVault(cm *crypto.CryptoManager, v *Vault) error {
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

	// 6. Записываем в файл
	return os.WriteFile(dataFile, finalData, 0600)
}

// LoadVault читает файл, проверяет целостность по HMAC и расшифровывает пароли
func LoadVault(cm *crypto.CryptoManager) (*Vault, error) {
	// 1. Читаем файл с диска
	fileData, err := os.ReadFile(dataFile)
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
