package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"password-saver/crypto"
)

func withVaultDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

func TestSaveLoadBackupAndWrongPassword(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	first := &Vault{Accounts: []Account{{ID: "one", Password: "secret"}}}
	if err := SaveVault(cm, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveVault(cm, &Vault{Accounts: []Account{{ID: "two", Password: "new"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dataFile + ".bak"); err != nil {
		t.Fatalf("encrypted backup missing: %v", err)
	}
	loaded, err := LoadVault(cm)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Accounts) != 1 || loaded.Accounts[0].ID != "two" {
		t.Fatalf("unexpected loaded vault: %#v", loaded)
	}
	wrong, _ := crypto.NewCryptoManager("incorrect horse battery staple")
	defer wrong.Wipe()
	if _, err := LoadVault(wrong); err == nil {
		t.Fatal("wrong master password accepted")
	}
}

func TestLoadVaultRejectsDamagedAndOversizedFiles(t *testing.T) {
	withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	for _, data := range [][]byte{[]byte("not a valid signed vault"), bytes.Repeat([]byte("x"), maxVaultFileSize+1)} {
		if err := os.WriteFile(dataFile, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVault(cm); err == nil {
			t.Fatal("LoadVault accepted damaged or oversized file")
		}
	}
}

func TestSaveVaultWriteFailurePreservesPreviousFile(t *testing.T) {
	dir := withVaultDir(t)
	cm, _ := crypto.NewCryptoManager("correct horse battery staple")
	defer cm.Wipe()
	oldVault := &Vault{Accounts: []Account{{ID: "original"}}}
	path := filepath.Join(dir, dataFile)
	if err := saveVaultToPath(path, cm, oldVault); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldRename := renameVaultFile
	defer func() { renameVaultFile = oldRename }()
	failed := false
	renameVaultFile = func(src, dst string) error {
		if strings.HasPrefix(filepath.Base(src), ".vault-write-") && dst == path {
			failed = true
			return os.ErrPermission
		}
		return os.Rename(src, dst)
	}
	if err := saveVaultToPath(path, cm, &Vault{Accounts: []Account{{ID: "replacement"}}}); err == nil {
		t.Fatal("expected injected replacement failure")
	}
	if !failed {
		t.Fatal("write failure injection was not reached")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed save changed the previous container")
	}
}
