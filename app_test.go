package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"password-saver/crypto"
)

func TestAppAuthorizationAndSessionReset(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	if _, err := a.GetAccounts(); err == nil {
		t.Fatal("unauthenticated GetAccounts succeeded")
	}
	if err := a.AddAccount("title", "login", "password"); err == nil {
		t.Fatal("unauthenticated AddAccount succeeded")
	}
	if err := a.UpdateAccount("id", "title", "login", "password"); err == nil {
		t.Fatal("unauthenticated UpdateAccount succeeded")
	}
	if err := a.DeleteAccount("id"); err == nil {
		t.Fatal("unauthenticated DeleteAccount succeeded")
	}
	if err := a.Verify2FA("123456"); err == nil {
		t.Fatal("unauthenticated Verify2FA succeeded")
	}

	if _, err := a.Login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddAccount("title", "login", "password"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login("incorrect horse battery staple"); err == nil {
		t.Fatal("wrong password succeeded")
	}
	if !a.IsLocked() || a.vault != nil || a.cm != nil {
		t.Fatal("failed repeated login left prior session active")
	}
}

func TestMutationFailureRollsBackMemory(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	if _, err := a.Login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddAccount("title", "login", "original"); err != nil {
		t.Fatal(err)
	}
	original := cloneVault(a.vault)
	oldRename := replaceVaultFile
	t.Cleanup(func() { replaceVaultFile = oldRename })
	failed := false
	replaceVaultFile = func(src, dst string) error {
		if strings.HasPrefix(filepath.Base(src), ".vault-write-") && dst == dataFile {
			failed = true
			return os.ErrPermission
		}
		return os.Rename(src, dst)
	}
	if err := a.UpdateAccount(original.Accounts[0].ID, "changed", "changed", "changed"); err == nil {
		t.Fatal("expected update persistence failure")
	}
	if !failed {
		t.Fatal("write failure injection was not reached")
	}
	if a.vault.TwoFAEnabled != original.TwoFAEnabled || len(a.vault.Accounts) != len(original.Accounts) || a.vault.Accounts[0] != original.Accounts[0] {
		t.Fatalf("vault memory changed after failed save: %#v", a.vault)
	}
}

func TestResetVaultAvailableWhenMasterPasswordForgotten(t *testing.T) {
	withVaultDir(t)
	if err := os.WriteFile(dataFile, []byte("encrypted fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile+".bak", []byte("encrypted backup fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if err := app.ResetVault("forged-token"); err == nil {
		t.Fatal("reset without challenge succeeded")
	}
	if _, err := os.Stat(dataFile); err != nil {
		t.Fatalf("unconfirmed reset removed the vault: %v", err)
	}
	token, err := app.BeginVaultReset()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ResetVault("wrong-token"); err == nil {
		t.Fatal("reset with wrong token succeeded")
	}
	if _, err := os.Stat(dataFile); err != nil {
		t.Fatalf("wrong token removed vault: %v", err)
	}
	app.CancelVaultReset(token)
	if err := app.ResetVault(token); err == nil {
		t.Fatal("cancelled token remained usable")
	}
	token, err = app.BeginVaultReset()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ResetVault(token); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataFile, dataFile + ".bak"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s remains after explicit reset", path)
		}
	}
}

func TestResetChallengeExpiresAndActiveSessionCannotStartReset(t *testing.T) {
	withVaultDir(t)
	cm, err := crypto.NewCryptoManager("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Wipe()
	if err := SaveVault(cm, &Vault{Accounts: []Account{}}); err != nil {
		t.Fatal(err)
	}
	app := NewApp()
	if _, err := app.Login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.BeginVaultReset(); err == nil {
		t.Fatal("active session was allowed to begin reset")
	}
	app.Logout()
	token, err := app.BeginVaultReset()
	if err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	app.pendingReset.expires = time.Now().Add(-time.Second)
	app.mu.Unlock()
	if err := app.ResetVault(token); err == nil {
		t.Fatal("expired reset challenge was accepted")
	}
	if _, err := os.Stat(dataFile); err != nil {
		t.Fatalf("expired challenge removed the vault: %v", err)
	}
}

func TestRepeatedLoginRequiresSecondFactorAgain(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	password := "correct horse battery staple"
	if _, err := a.Login(password); err != nil {
		t.Fatal(err)
	}
	setup, err := a.Generate2FA()
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmAndEnable2FA(setup.Secret, code); err != nil {
		t.Fatal(err)
	}
	a.Logout()
	requires2FA, err := a.Login(password)
	if err != nil || !requires2FA {
		t.Fatalf("Login() = (%v, %v), want 2FA required", requires2FA, err)
	}
	code, err = totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify2FA(code); err != nil {
		t.Fatal(err)
	}
	if a.IsLocked() {
		t.Fatal("valid second factor did not unlock the vault")
	}
	requires2FA, err = a.Login(password)
	if err != nil || !requires2FA {
		t.Fatalf("repeated Login() = (%v, %v), want fresh 2FA", requires2FA, err)
	}
	if !a.IsLocked() {
		t.Fatal("repeated login retained previous 2FA authorization")
	}
}

func TestConcurrentAppCallsAndLogoutAreSynchronized(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	if _, err := a.Login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			<-start
			for i := 0; i < 12; i++ {
				_ = a.AddAccount("title", "login", "password")
				_, _ = a.GetAccounts()
				_ = a.IsLocked()
			}
		}(worker)
	}
	go func() { <-start; a.Logout() }()
	close(start)
	wg.Wait()
	if !a.IsLocked() {
		t.Fatal("concurrent logout did not lock the app")
	}
}

func TestMutationKeepsMemoryAlignedAfterDirectorySyncFailure(t *testing.T) {
	withVaultDir(t)
	a := NewApp()
	if _, err := a.Login("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddAccount("title", "login", "old"); err != nil {
		t.Fatal(err)
	}
	oldSync := syncVaultDirectory
	t.Cleanup(func() { syncVaultDirectory = oldSync })
	calls := 0
	syncVaultDirectory = func(path string) error {
		calls++
		if calls == 2 {
			return errors.New("injected directory sync failure")
		}
		return oldSync(path)
	}
	err := a.UpdateAccount(a.vault.Accounts[0].ID, "title", "login", "new")
	if !errors.Is(err, errVaultCommitUncertain) {
		t.Fatalf("UpdateAccount error = %v, want uncertain commit", err)
	}
	if a.vault.Accounts[0].Password != "new" {
		t.Fatal("RAM reverted although replacement was already visible")
	}
	syncVaultDirectory = oldSync
	disk, err := LoadVault(a.cm)
	if err != nil || disk.Accounts[0].Password != "new" {
		t.Fatalf("disk and memory diverged after uncertain commit: %v", err)
	}
}
