package crypto

import (
	"encoding/base64"
	"strings"
	"sync"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cm, err := NewCryptoManager("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cm.Wipe)
	want := `{"password":"sensitive"}`
	ed, err := cm.Encrypt(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cm.Decrypt(ed)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Decrypt() = %q, want %q", got, want)
	}
}

func TestDecryptRejectsMalformedContainer(t *testing.T) {
	cm, err := NewCryptoManager("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cm.Wipe)
	valid, err := cm.Encrypt("value")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]*EncryptedData{
		"nil":                  nil,
		"short salt":           {Salt: base64.StdEncoding.EncodeToString([]byte("short")), Nonce: valid.Nonce, Ciphertext: valid.Ciphertext},
		"short nonce":          {Salt: valid.Salt, Nonce: base64.StdEncoding.EncodeToString([]byte("short")), Ciphertext: valid.Ciphertext},
		"short ciphertext":     {Salt: valid.Salt, Nonce: valid.Nonce, Ciphertext: base64.StdEncoding.EncodeToString([]byte("short"))},
		"oversized ciphertext": {Salt: valid.Salt, Nonce: valid.Nonce, Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, CiphertextLimit+1))},
	}
	for name, container := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := cm.Decrypt(container); err == nil {
				t.Fatal("Decrypt accepted malformed container")
			}
		})
	}
}

func TestDecryptRejectsWrongPasswordAndWipedManager(t *testing.T) {
	cm, _ := NewCryptoManager("correct horse battery staple")
	ed, err := cm.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := NewCryptoManager("different horse battery staple")
	defer wrong.Wipe()
	if _, err := wrong.Decrypt(ed); err == nil || !strings.Contains(err.Error(), "неверный пароль") {
		t.Fatalf("wrong password error = %v", err)
	}
	cm.Wipe()
	if _, err := cm.Decrypt(ed); err == nil {
		t.Fatal("wiped manager decrypted data")
	}
}

func TestCryptoManagerConcurrentUseAndWipe(t *testing.T) {
	cm, err := NewCryptoManager("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ed, err := cm.Encrypt("shared fixture")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				if encrypted, err := cm.Encrypt("parallel"); err == nil {
					_, _ = cm.Decrypt(encrypted)
				}
				_, _ = cm.Decrypt(ed)
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); cm.Wipe() }()
	wg.Wait()
	cm.Wipe()
}
