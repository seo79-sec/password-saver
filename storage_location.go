package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The default storage root is intentionally independent of the executable
// location and current working directory. Do not use this helper to switch
// active storage without a separate, reviewed migration.
var ErrVaultDataLocation = errors.New("cannot determine a safe vault data directory")

// defaultVaultDataDirectory is the planned v2.5 location for a single local
// vault. Existing releases still use their historical directory until the
// separate opt-in migration flow and path-based storage APIs are implemented.
func defaultVaultDataDirectory() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if strings.TrimSpace(base) == "" {
			var err error
			base, err = os.UserCacheDir() // Windows: %LocalAppData%
			if err != nil {
				return "", fmt.Errorf("%w: local Windows app data unavailable", ErrVaultDataLocation)
			}
		}
		return vaultDirectoryFromBase(base)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: OS config directory unavailable", ErrVaultDataLocation)
	}
	return vaultDirectoryFromBase(base)
}

// vaultDirectoryFromBase deliberately rejects relative or missing base paths;
// silently using "." here would put secrets next to the executable again.
func vaultDirectoryFromBase(base string) (string, error) {
	if strings.TrimSpace(base) == "" || !filepath.IsAbs(base) {
		return "", ErrVaultDataLocation
	}
	return filepath.Join(filepath.Clean(base), "PasswordSaver", "vaults", "default"), nil
}

// vaultFileInventory is a read-only view used to plan safe migration.
// It does not authenticate vaults, move files, select an active format,
// or grant permission to delete old data.
type vaultFileInventory struct {
	HasVaultFiles bool
}

// inspectVaultFiles refuses non-regular entries (including symlinks) rather
// than following them while examining a migration source or destination.
func inspectVaultFiles(directory string) (vaultFileInventory, error) {
	var out vaultFileInventory
	if strings.TrimSpace(directory) == "" || !filepath.IsAbs(directory) {
		return out, ErrVaultDataLocation
	}
	for _, filename := range []string{
		dataFile, dataFile + ".bak", dataFileV2, dataFileV2 + ".bak", vaultSelectorFile,
	} {
		path := filepath.Join(directory, filename)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return vaultFileInventory{}, fmt.Errorf("%w: cannot inspect vault directory", ErrVaultDataLocation)
		}
		if !info.Mode().IsRegular() {
			return vaultFileInventory{}, fmt.Errorf("%w: unsafe vault file entry", ErrVaultDataLocation)
		}
		out.HasVaultFiles = true
	}
	return out, nil
}

// This is a migration decision aid, NOT an automatic move. Both locations
// containing files requires an explicit resolution; there is no silent choice.
type vaultLocationPlan struct {
	HasLegacyVault  bool
	HasTargetVault  bool
	NeedsMigration  bool
	HasConflict     bool
}

func inspectVaultLocationPlan(legacyDir, targetDir string) (vaultLocationPlan, error) {
	if !filepath.IsAbs(legacyDir) || !filepath.IsAbs(targetDir) {
		return vaultLocationPlan{}, ErrVaultDataLocation
	}
	// A same-directory candidate must not be mistaken for two vaults.
	if filepath.Clean(legacyDir) == filepath.Clean(targetDir) {
		current, err := inspectVaultFiles(targetDir)
		return vaultLocationPlan{HasTargetVault: current.HasVaultFiles}, err
	}
	legacy, err := inspectVaultFiles(legacyDir)
	if err != nil {
		return vaultLocationPlan{}, err
	}
	target, err := inspectVaultFiles(targetDir)
	if err != nil {
		return vaultLocationPlan{}, err
	}
	return vaultLocationPlan{
		HasLegacyVault: legacy.HasVaultFiles,
		HasTargetVault: target.HasVaultFiles,
		NeedsMigration: legacy.HasVaultFiles && !target.HasVaultFiles,
		HasConflict: legacy.HasVaultFiles && target.HasVaultFiles,
	}, nil
}
