package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

//go:embed v3_release_uia.ps1
var v3ReleaseUIAScript []byte

func checkV3RollbackReleasedEXE(t *testing.T, snapshot string, _ *Vault) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	const releaseURL = "https://github.com/seo79-sec/password-saver/releases/download/v2.5.0/PasswordSaver-Standard-2.5.0-Windows-x64.zip"
	const releaseSHA = "a6de6c1e84099bb315d1642c7b2a57bfc7cbb3e1d3df0747920e7f7120f9e940"
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Get(releaseURL)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(archive)) != releaseSHA {
		t.Fatalf("release download failed verification (HTTP %d): %v", response.StatusCode, err)
	}
	zipped, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	file, err := zipped.Open("PasswordSaver/password-saver.exe")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := io.ReadAll(io.LimitReader(file, 32<<20))
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	exe := filepath.Join(root, "password-saver.exe")
	if err := os.WriteFile(exe, executable, 0700); err != nil {
		t.Fatal(err)
	}
	localAppData := filepath.Join(root, "Local")
	profile := filepath.Join(localAppData, "PasswordSaver", "vaults", "default")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	if err := secureStorageDirectory(profile); err != nil {
		t.Fatal(err)
	}
	for name, original := range map[string]string{dataFileV2: snapshot, vaultSelectorFile: vaultSelectorFile} {
		if err := writeFileAtomic(filepath.Join(profile, name), readPasswordChangeTestFile(t, original)); err != nil {
			t.Fatal(err)
		}
	}

	script := filepath.Join(root, "check-release.ps1")
	if err := os.WriteFile(script, v3ReleaseUIAScript, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-STA", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script)
	child.Dir = root
	child.Env = append(os.Environ(), "PS_V3_RELEASE_EXE="+exe, "PS_V3_RELEASE_PROFILE="+root)
	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("released v2.5.0 EXE native verification: %v: %s", err, out)
	}
	t.Log(string(out))
}
