package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

type CryptoManager struct {
	masterPassword []byte // Изменено со string на []byte для возможности затирания в RAM
}

type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
}

func NewCryptoManager(masterPassword string) (*CryptoManager, error) {
	if len(masterPassword) < 12 {
		return nil, errors.New("мастер-пароль должен быть не менее 12 символов")
	}

	return &CryptoManager{
		// Превращаем строку в байты. Оригинальная строка из Wails уничтожится стандартным путем,
		// но наша долгоживущая копия в структуре теперь под полным контролем.
		masterPassword: []byte(masterPassword),
	}, nil
}

// ZeroMemory принудительно заполняет переданную область памяти нулями.
// Это уничтожает реальные данные физически в RAM, не дожидаясь сборщика мусора.
func ZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// Wipe гарантированно уничтожает мастер-пароль внутри крипто-менеджера.
// Этот метод нужно обязательно вызывать при Logout или блокировке приложения.
func (cm *CryptoManager) Wipe() {
	if cm.masterPassword != nil {
		ZeroMemory(cm.masterPassword) // Затираем нулями ячейки памяти
		cm.masterPassword = nil       // Разрываем ссылку
	}
}

func (cm *CryptoManager) Encrypt(plaintext string) (*EncryptedData, error) {
	if cm.masterPassword == nil {
		return nil, errors.New("крипто-менеджер уничтожен или сессия закрыта")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Передаем cm.masterPassword напрямую. Больше никаких скрытых аллокаций.
	key := argon2.IDKey(cm.masterPassword, salt, 3, 128*1024, 4, 32)

	// Как только ключ создан и передан в AES, сам 256-битный ключ нам больше не нужен в RAM.
	// Используем defer, чтобы гарантированно стереть ключ при выходе из функции.
	defer ZeroMemory(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

func (cm *CryptoManager) Decrypt(ed *EncryptedData) (string, error) {
	if cm.masterPassword == nil {
		return "", errors.New("крипто-менеджер уничтожен или сессия закрыта")
	}

	salt, err := base64.StdEncoding.DecodeString(ed.Salt)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ed.Ciphertext)
	if err != nil {
		return "", err
	}

	nonce, err := base64.StdEncoding.DecodeString(ed.Nonce)
	if err != nil {
		return "", err
	}

	key := argon2.IDKey(cm.masterPassword, salt, 3, 128*1024, 4, 32)
	defer ZeroMemory(key) // Уничтожаем временный ключ сразу после создания блочного шифра AES

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("ошибка расшифровки: неверный пароль")
	}

	return string(plaintext), nil
}

// SignData создает HMAC-подпись для данных
func SignData(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifySignature проверяет подлинность данных
func VerifySignature(data []byte, signature []byte, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedSignature := h.Sum(nil)
	return hmac.Equal(signature, expectedSignature)
}
