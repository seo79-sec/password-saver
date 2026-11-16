//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsManualLegacySelectionOnAnotherDrive(t *testing.T) {
	f := manualStorageFixture(t, "v2")
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	letter := byte('Z')
	for ; letter >= 'D'; letter-- {
		if drives&(1<<(letter-'A')) == 0 {
			break
		}
	}
	if letter < 'D' {
		t.Skip("no unused drive letter for isolated synthetic test")
	}
	device, err := windows.UTF16PtrFromString(fmt.Sprintf("%c:", letter))
	if err != nil {
		t.Fatal(err)
	}
	target, err := windows.UTF16PtrFromString(`\??\` + f.source)
	if err != nil {
		t.Fatal(err)
	}
	// Only map an unused letter to the synthetic temp directory. Remove this
	// exact mapping on cleanup; no real volume is mounted or overwritten.
	if err := windows.DefineDosDevice(windows.DDD_RAW_TARGET_PATH|windows.DDD_NO_BROADCAST_SYSTEM, device, target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.DefineDosDevice(windows.DDD_RAW_TARGET_PATH|windows.DDD_NO_BROADCAST_SYSTEM|windows.DDD_REMOVE_DEFINITION|windows.DDD_EXACT_MATCH_ON_REMOVE, device, target); err != nil {
			t.Error(err)
		}
	})
	choice := fmt.Sprintf("%c:\\", letter)
	chooseLegacyStorageDirectory = func(context.Context) (string, error) { return choice, nil }
	selected, err := f.app.SelectLegacyStorageDirectory()
	if err != nil || selected.Path != choice {
		t.Fatalf("other-drive choice = %+v, %v", selected, err)
	}
	token, err := f.app.PrepareSelectedStorageLocationMigration(selected.Token, f.password, currentCode(t, f.vault.TwoFASecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.app.ConfirmStorageLocationMigration(token); err != nil {
		t.Fatal(err)
	}
	assertSnapshotEqual(t, f.source, f.files)
	assertSnapshotEqual(t, f.target, f.files)
}

func TestWindowsStorageRejectsDirectoryJunction(t *testing.T) {
	root, target := t.TempDir(), t.TempDir()
	junction := filepath.Join(root, "selected-folder")
	// Junctions do not require the symlink privilege. All paths are test-owned;
	// cmd's shell metacharacters are not accepted as test fixture paths.
	if strings.ContainsAny(junction+target, "%!^&|<>\r\n\"") {
		t.Skip("temp directory contains cmd metacharacters")
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("create synthetic junction: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	if _, err := scanVaultDirectory(junction, legacyVaultDirectory); !errors.Is(err, ErrVaultStorageUnsafe) {
		t.Fatalf("junction source accepted: %v", err)
	}
	if _, err := scanVaultDirectory(junction, managedVaultDirectory); !errors.Is(err, ErrVaultStorageUnsafe) {
		t.Fatalf("junction target accepted: %v", err)
	}
	knownPath := filepath.Join(root, dataFileV2)
	if err := os.Rename(junction, knownPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(knownPath) })
	if _, err := scanVaultDirectory(root, legacyVaultDirectory); !errors.Is(err, ErrVaultStorageUnsafe) {
		t.Fatalf("known vault filename as junction accepted: %v", err)
	}
}
