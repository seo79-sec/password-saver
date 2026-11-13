package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
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
	if err := app.ResetVault(false); err == nil {
		t.Fatal("reset without explicit confirmation succeeded")
	}
	if _, err := os.Stat(dataFile); err != nil {
		t.Fatalf("unconfirmed reset removed the vault: %v", err)
	}
	if err := app.ResetVault(true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataFile, dataFile + ".bak"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s remains after explicit reset", path)
		}
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
