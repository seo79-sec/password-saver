package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// LegacyStorageSelection exposes only the native-dialog choice, never file
// contents. The token is valid only in this App instance for a limited time.
type LegacyStorageSelection struct {
	Token      string `json:"token"`
	Path       string `json:"path"`
	TargetPath string `json:"targetPath"`
}

type legacyStorageSelection struct {
	token   string
	path    string
	expires time.Time
	timer   *time.Timer
}

var chooseLegacyStorageDirectory = func(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", ErrVaultDataLocation
	}
	return wailsruntime.OpenDirectoryDialog(ctx, wailsruntime.OpenDialogOptions{
		Title:                "Выберите папку существующего хранилища PasswordSaver",
		CanCreateDirectories: false,
	})
}

func (a *App) storageMigrationSessionLocked() bool {
	return a.cm != nil || a.v2Session != nil || a.vault != nil || a.twoFAVerified ||
		a.pendingRecover.cm != nil || a.pendingV2Recover.session != nil
}

// SelectLegacyStorageDirectory accepts no frontend path. Only the native user
// selection can issue a capability for the limited, read-only verification
// followed by a separately confirmed copy to the fixed AppData destination.
func (a *App) SelectLegacyStorageDirectory() (LegacyStorageSelection, error) {
	a.mu.Lock()
	if a.storageMigrationSessionLocked() || a.pendingStorageMigration.token != "" || a.storageSelectionDialogOpen {
		a.mu.Unlock()
		return LegacyStorageSelection{}, ErrVaultStorageMigrationBusy
	}
	a.clearLegacyStorageSelectionLocked()
	generation, ctx := a.storageSelectionGeneration, a.ctx
	a.storageSelectionDialogOpen = true
	a.mu.Unlock()

	// A native dialog must not hold App.mu: Logout can invalidate its result.
	path, err := chooseLegacyStorageDirectory(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.storageSelectionGeneration {
		return LegacyStorageSelection{}, ErrVaultStorageMigrationExpired
	}
	a.storageSelectionDialogOpen = false
	if err != nil || path == "" {
		return LegacyStorageSelection{}, err // cancellation has no side effects
	}
	if a.storageMigrationSessionLocked() || a.pendingStorageMigration.token != "" {
		return LegacyStorageSelection{}, ErrVaultStorageMigrationBusy
	}
	if !filepath.IsAbs(path) {
		return LegacyStorageSelection{}, ErrVaultDataLocation
	}
	path = filepath.Clean(path)
	route, err := validateExplicitStorageSource(path)
	if err != nil {
		return LegacyStorageSelection{}, err
	}
	token, err := newChallengeToken()
	if err != nil {
		return LegacyStorageSelection{}, err
	}
	expires := time.Now().Add(storageMigrationChallengeLifetime)
	a.selectedLegacyStorage = legacyStorageSelection{token: token, path: path, expires: expires}
	a.selectedLegacyStorage.timer = time.AfterFunc(time.Until(expires), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if challengeMatches(a.selectedLegacyStorage.token, token) && !time.Now().Before(a.selectedLegacyStorage.expires) {
			a.clearLegacyStorageSelectionLocked()
		}
	})
	return LegacyStorageSelection{Token: token, Path: path, TargetPath: route.Location.Root}, nil
}

func validateExplicitStorageSource(path string) (storageRoute, error) {
	if !filepath.IsAbs(path) {
		return storageRoute{}, ErrVaultDataLocation
	}
	files, err := scanVaultDirectory(path, legacyVaultDirectory)
	if err != nil {
		return storageRoute{}, err
	}
	if len(files) == 0 {
		return storageRoute{}, errors.New("selected directory contains no vault files")
	}
	if files[vaultSelectorFile] != nil {
		data, err := readStorageFile(filepath.Join(path, vaultSelectorFile), 4096)
		if err != nil {
			return storageRoute{}, err
		}
		if _, err := parseVaultSelectorBytes(data); err != nil {
			return storageRoute{}, err
		}
	} else if files[dataFileV2] != nil || files[dataFileV2+".bak"] != nil {
		return storageRoute{}, ErrVaultSelectionAmbiguous
	}
	route, err := discoverStorageRouteWithSource(path)
	if err != nil {
		return storageRoute{}, err
	}
	if route.State != storageRouteNeedsMigration || !sameStoragePath(route.SourceDir, path) {
		return storageRoute{}, ErrVaultStorageConflict
	}
	return route, nil
}

func (a *App) PrepareSelectedStorageLocationMigration(selectionToken, password, totpCode string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.storageMigrationSessionLocked() {
		return "", ErrVaultStorageMigrationBusy
	}
	selected := a.selectedLegacyStorage
	if selected.token != "" && !time.Now().Before(selected.expires) {
		a.clearLegacyStorageSelectionLocked()
		return "", ErrVaultStorageMigrationExpired
	}
	if !challengeValid(selected.token, selected.expires, selectionToken) {
		return "", ErrVaultStorageMigrationExpired
	}
	if _, err := validateExplicitStorageSource(selected.path); err != nil {
		return "", err
	}
	token, err := a.prepareStorageLocationMigrationLocked(password, totpCode, selected.path)
	if err == nil {
		a.clearLegacyStorageSelectionLocked() // the copy challenge now owns the choice
	}
	return token, err
}

func (a *App) CancelLegacyStorageSelection(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.selectedLegacyStorage.token == "" || !challengeMatches(a.selectedLegacyStorage.token, token) {
		return ErrVaultStorageMigrationExpired
	}
	a.clearLegacyStorageSelectionLocked()
	return nil
}

func (a *App) clearLegacyStorageSelectionLocked() {
	if a.selectedLegacyStorage.timer != nil {
		a.selectedLegacyStorage.timer.Stop()
	}
	a.selectedLegacyStorage = legacyStorageSelection{}
	a.storageSelectionGeneration++
	a.storageSelectionDialogOpen = false
}
