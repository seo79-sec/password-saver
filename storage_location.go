package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	cryptov2 "password-saver/crypto/v2"
)

var (
	ErrVaultDataLocation            = errors.New("cannot determine a safe vault data directory")
	ErrVaultStorageMigration        = errors.New("an existing vault must be explicitly moved to the standard data directory")
	ErrVaultStorageConflict         = errors.New("different vault files exist in both locations")
	ErrVaultStorageUnsafe           = errors.New("vault storage path contains an unsafe filesystem entry")
	ErrVaultStorageMigrationBusy    = errors.New("a storage migration is already pending")
	ErrVaultStorageMigrationExpired = errors.New("storage migration confirmation expired or changed")
	ErrVaultStorageCommitUncertain  = errors.New("storage copy completed but directory synchronization was not confirmed")
	ErrVaultStorageIncomplete       = errors.New("unfinished vault write requires manual inspection before initialization")
)

type storageLocation struct {
	BaseDir string
	Root    string
	Backups string
	Config  string
	Vaults  string
}

type storageRouteState uint8

const (
	storageRouteReady storageRouteState = iota
	storageRouteNeedsMigration
	storageRouteConflict
	storageRouteIncomplete
)

const storageMigrationReceiptFile = "storage.migration.json"
const storageReceiptLimit = 16 * 1024

type storageMigrationReceipt struct {
	Format      string            `json:"format"`
	Version     uint16            `json:"version"`
	Source      string            `json:"source"`
	SourceFiles map[string]string `json:"sourceFiles"`
}

type storageRoute struct {
	Location       storageLocation
	State          storageRouteState
	LegacyDirs     []string
	SourceDir      string
	TemporaryFiles int
}

type StorageLocationStatus struct {
	State            string   `json:"state"`
	Path             string   `json:"path"`
	LegacyPaths      []string `json:"legacyPaths"`
	Format           string   `json:"format"`
	Algorithm        string   `json:"algorithm"`
	BackupPresent    bool     `json:"backupPresent"`
	MigrationPending bool     `json:"migrationPending"`
	TemporaryFiles   int      `json:"temporaryFiles"`
	Diagnostic       string   `json:"diagnostic"`
}

// The override is only used by tests. Production callers always resolve the
// OS-standard per-user directory and never switch the process working folder.
var storageOverrideMu sync.RWMutex
var storageDirectoryOverride string
var legacyDirectoryProvider = discoverLegacyVaultDirectories
var storageExecutablePath = os.Executable

func setStorageDirectoryOverrideForTest(path string) func() {
	storageOverrideMu.Lock()
	previous := storageDirectoryOverride
	storageDirectoryOverride = path
	storageOverrideMu.Unlock()
	return func() {
		storageOverrideMu.Lock()
		storageDirectoryOverride = previous
		storageOverrideMu.Unlock()
	}
}

func configuredVaultDataDirectory() (string, error) {
	storageOverrideMu.RLock()
	override := storageDirectoryOverride
	storageOverrideMu.RUnlock()
	if override != "" {
		if !filepath.IsAbs(override) {
			return "", ErrVaultDataLocation
		}
		return filepath.Clean(override), nil
	}
	return defaultVaultDataDirectory()
}

// defaultVaultDataDirectory is independent of the executable and current
// working directories. On Windows, UserCacheDir is Go's LOCALAPPDATA fallback.
func defaultVaultDataDirectory() (string, error) {
	cacheDir, cacheErr := os.UserCacheDir()
	configDir, configErr := os.UserConfigDir()
	if runtime.GOOS == "windows" && cacheErr != nil {
		return "", fmt.Errorf("%w: local Windows app data unavailable", ErrVaultDataLocation)
	}
	if runtime.GOOS != "windows" && configErr != nil {
		return "", fmt.Errorf("%w: OS config directory unavailable", ErrVaultDataLocation)
	}
	return vaultDirectoryForOS(runtime.GOOS, os.Getenv("LOCALAPPDATA"), cacheDir, configDir)
}

func vaultDirectoryForOS(goos, localAppData, cacheDir, configDir string) (string, error) {
	if goos == "windows" {
		base := localAppData
		if strings.TrimSpace(base) == "" {
			base = cacheDir
		}
		return vaultDirectoryFromBase(base)
	}
	return vaultDirectoryFromBase(configDir)
}

func vaultDirectoryFromBase(base string) (string, error) {
	if strings.TrimSpace(base) == "" || !filepath.IsAbs(base) {
		return "", ErrVaultDataLocation
	}
	return filepath.Join(filepath.Clean(base), "PasswordSaver", "vaults", "default"), nil
}

func newStorageLocation(root string) (storageLocation, error) {
	if strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
		return storageLocation{}, ErrVaultDataLocation
	}
	root = filepath.Clean(root)
	vaults := filepath.Dir(root)
	product := filepath.Dir(vaults)
	base := filepath.Dir(product)
	if filepath.Base(root) != "default" || filepath.Base(vaults) != "vaults" || filepath.Base(product) != "PasswordSaver" {
		return storageLocation{}, ErrVaultDataLocation
	}
	return storageLocation{
		BaseDir: base,
		Root:    root,
		Vaults:  vaults,
		Backups: filepath.Join(product, "backups"),
		Config:  filepath.Join(product, "config"),
	}, nil
}

// vaultFileInventory contains only encrypted vault bytes and the non-secret
// selector. It is read-only and never authenticates, selects, or deletes data.
type vaultFileInventory struct {
	HasVaultFiles bool
	Files         map[string][]byte
}

func isVaultDiagnosticArchive(name string) bool {
	return strings.HasPrefix(name, dataFile+".corrupt-") || strings.HasPrefix(name, dataFileV2+".corrupt-") ||
		strings.HasPrefix(name, dataFileV2+".pre-restore-") || strings.HasPrefix(name, dataFileV2+".bak.pre-restore-")
}

func v2ContainerFileLimit() int64 { return cryptov2.MaxContainerSize }

func readLimited(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrVaultDataLocation
	}
	return data, nil
}

func inspectVaultLocationPlan(legacyDir, targetDir string) (vaultLocationPlan, error) {
	if !filepath.IsAbs(legacyDir) || !filepath.IsAbs(targetDir) {
		return vaultLocationPlan{}, ErrVaultDataLocation
	}
	legacyDir = filepath.Clean(legacyDir)
	targetDir = filepath.Clean(targetDir)
	if sameStoragePath(legacyDir, targetDir) {
		current, err := inspectVaultFiles(targetDir)
		return vaultLocationPlan{HasTargetVault: current.HasVaultFiles}, err
	}
	legacy, err := inspectLegacyVaultFiles(legacyDir)
	if err != nil {
		return vaultLocationPlan{}, err
	}
	target, err := inspectVaultFiles(targetDir)
	if err != nil {
		return vaultLocationPlan{}, err
	}
	equivalent := legacy.HasVaultFiles && target.HasVaultFiles && sameInventory(legacy, target)
	return vaultLocationPlan{
		HasLegacyVault: legacy.HasVaultFiles,
		HasTargetVault: target.HasVaultFiles,
		NeedsMigration: legacy.HasVaultFiles && !target.HasVaultFiles,
		HasConflict:    legacy.HasVaultFiles && target.HasVaultFiles && !equivalent,
	}, nil
}

type vaultLocationPlan struct {
	HasLegacyVault bool
	HasTargetVault bool
	NeedsMigration bool
	HasConflict    bool
}

func sameInventory(left, right vaultFileInventory) bool {
	if len(left.Files) != len(right.Files) {
		return false
	}
	for name, expected := range left.Files {
		actual, ok := right.Files[name]
		if !ok || !bytes.Equal(expected, actual) {
			return false
		}
	}
	return true
}

func sameStoragePath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func inventoryHashes(inventory vaultFileInventory) map[string]string {
	hashes := make(map[string]string, len(inventory.Files))
	for name, data := range inventory.Files {
		digest := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(digest[:])
	}
	return hashes
}

func validStorageMigrationReceipt(directory, source string, sourceInventory vaultFileInventory) bool {
	if !sourceInventory.HasVaultFiles || !filepath.IsAbs(source) {
		return false
	}
	path := filepath.Join(directory, storageMigrationReceiptFile)
	data, err := readStorageFile(path, storageReceiptLimit)
	if err != nil {
		return false
	}
	var receipt storageMigrationReceipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil {
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || receipt.Format != "passwordsaver-storage-migration" || receipt.Version != 1 || !sameStoragePath(receipt.Source, source) {
		return false
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, data) || len(receipt.SourceFiles) != len(sourceInventory.Files) {
		return false
	}
	for name, digest := range inventoryHashes(sourceInventory) {
		if receipt.SourceFiles[name] != digest {
			return false
		}
	}
	return true
}

func configuredStorageLocation() (storageLocation, error) {
	root, err := configuredVaultDataDirectory()
	if err != nil {
		return storageLocation{}, err
	}
	return newStorageLocation(root)
}

// Routine route resolution reads filesystem metadata, not the active payload.
// If both locations contain files, the receipt requires a full source hash
// check. Do not cache that decision by path, size or mtime: a different vault
// could have the same metadata. The target is authenticated by login/recovery
// and its live revision is checked by the existing session save machinery.
func discoverStorageRoute() (storageRoute, error) {
	return discoverStorageRouteWithSource("")
}

func discoverStorageRouteWithSource(explicitSource string) (storageRoute, error) {
	location, err := configuredStorageLocation()
	if err != nil {
		return storageRoute{}, err
	}
	targetScan, err := scanVaultDirectoryDetails(location.Root, managedVaultDirectory)
	if err != nil {
		return storageRoute{}, err
	}
	target := targetScan.Files
	legacyCandidates, err := legacyDirectoryProvider(location.Root)
	if err != nil {
		return storageRoute{}, err
	}
	if explicitSource != "" {
		legacyCandidates = append(legacyCandidates, explicitSource)
	}
	legacyWithFiles := make([]string, 0, len(legacyCandidates))
	for _, candidate := range legacyCandidates {
		if sameStoragePath(candidate, location.Root) {
			continue
		}
		duplicate := false
		for _, previous := range legacyWithFiles {
			if sameStoragePath(candidate, previous) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		files, err := scanVaultDirectory(candidate, legacyVaultDirectory)
		if err != nil {
			return storageRoute{}, err
		}
		if len(files) > 0 {
			legacyWithFiles = append(legacyWithFiles, candidate)
		}
	}
	route := storageRoute{Location: location, LegacyDirs: legacyWithFiles, TemporaryFiles: targetScan.TemporaryFiles}
	// Residue is not a container, and must not make a partially completed
	// first write look like a clean installation. A selector alone is also
	// insufficient. Keep real backup recovery available when a backup exists.
	if targetScan.TemporaryFiles > 0 && target[dataFile] == nil && target[dataFile+".bak"] == nil && target[dataFileV2] == nil && target[dataFileV2+".bak"] == nil {
		route.State = storageRouteIncomplete
		return route, nil
	}
	if len(legacyWithFiles) > 1 {
		route.State = storageRouteConflict
		return route, nil
	}
	if len(target) > 0 && len(legacyWithFiles) > 0 {
		route.State = storageRouteConflict
		// A manual import must never reuse/overwrite an existing target, even
		// if a receipt identifies an earlier copy of the same source.
		if _, receiptErr := statStorageFile(filepath.Join(location.Root, storageMigrationReceiptFile), storageReceiptLimit); explicitSource == "" && receiptErr == nil {
			legacy, err := inspectLegacyVaultFiles(legacyWithFiles[0])
			if err != nil {
				return storageRoute{}, err
			}
			if validStorageMigrationReceipt(location.Root, legacyWithFiles[0], legacy) {
				route.State = storageRouteReady
			}
		}
		return route, nil
	}
	if len(legacyWithFiles) > 0 {
		if err := requireEmptyDirectoryIfPresent(location.Root); err != nil {
			route.State = storageRouteConflict
			return route, nil
		}
		route.State, route.SourceDir = storageRouteNeedsMigration, legacyWithFiles[0]
		return route, nil
	}
	return route, nil
}

func discoverLegacyVaultDirectories(target string) ([]string, error) {
	var candidates []string
	executable, err := storageExecutablePath()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot determine executable directory", ErrVaultDataLocation)
	}
	executableDir, err := filepath.Abs(filepath.Dir(executable))
	if err != nil {
		return nil, ErrVaultDataLocation
	}
	// Do not scan the process working directory: a launcher may start the app
	// from an unrelated path containing files with the same names. Only the
	// executable directory is detected automatically. Other v2.0.0 working
	// directories require the native, explicitly confirmed import flow.
	for _, candidate := range []string{executableDir} {
		candidate = filepath.Clean(candidate)
		if sameStoragePath(candidate, target) {
			continue
		}
		alreadyAdded := false
		for _, previous := range candidates {
			if sameStoragePath(candidate, previous) {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			candidates = append(candidates, candidate)
		}
	}
	sort.Strings(candidates)
	return candidates, nil
}

func ensureStorageScaffold(location storageLocation, createVaultRoot bool) error {
	product := filepath.Dir(location.Vaults)
	directories := []string{
		location.BaseDir,
		product,
		location.Vaults,
		location.Backups,
		location.Config,
	}
	if createVaultRoot {
		directories = append(directories, location.Root)
	}
	for _, directory := range directories {
		if err := ensureSafeDirectoryChain(directory, true); err != nil {
			return err
		}
		if !sameStoragePath(directory, location.BaseDir) {
			if err := secureStorageDirectory(directory); err != nil {
				return fmt.Errorf("%w: cannot secure storage directory", ErrVaultDataLocation)
			}
		}
	}
	if createVaultRoot {
		if err := ensureSafeDirectoryChain(location.Root, true); err != nil {
			return err
		}
		entries, err := os.ReadDir(location.Root)
		if err != nil {
			return fmt.Errorf("%w: cannot inspect storage files", ErrVaultDataLocation)
		}
		for _, entry := range entries {
			path := filepath.Join(location.Root, entry.Name())
			if isVaultWriteTemporary(entry.Name()) {
				// Do not chmod, open, delete or otherwise operate on residue.
				// In particular it may have been unlinked by a concurrent writer.
				if _, err := statStorageFile(path, vaultWriteTemporaryLimit()); err != nil && !errors.Is(err, os.ErrNotExist) {
					return ErrVaultStorageUnsafe
				}
				continue
			}
			if _, known := knownVaultFileLimits()[entry.Name()]; !known && entry.Name() != storageMigrationReceiptFile && !isVaultDiagnosticArchive(entry.Name()) {
				return ErrVaultStorageUnsafe
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return ErrVaultStorageUnsafe
			}
			if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
				return ErrVaultStorageUnsafe
			}
			if err := secureStorageFile(path); err != nil {
				return fmt.Errorf("%w: cannot secure stored vault file", ErrVaultDataLocation)
			}
		}
	}
	return nil
}

func ensureSafeDirectoryChain(path string, create bool) error {
	if !filepath.IsAbs(path) {
		return ErrVaultDataLocation
	}
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(path, root)
	if volume != "" {
		remainder = strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	}
	current := root
	for _, part := range strings.Split(remainder, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%w: cannot create storage directory", ErrVaultDataLocation)
			}
			info, err = os.Lstat(current)
		}
		if errors.Is(err, os.ErrNotExist) && !create {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: cannot inspect storage directory", ErrVaultDataLocation)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrVaultStorageUnsafe
		}
		if reparse, err := storagePathIsReparsePoint(current); err != nil || reparse {
			return ErrVaultStorageUnsafe
		}
	}
	return nil
}

func checkExistingPathComponents(path string) error {
	if !filepath.IsAbs(path) {
		return ErrVaultDataLocation
	}
	return ensureSafeDirectoryChain(path, false)
}

func activeVaultStorageDirectory() (string, error) {
	route, err := discoverStorageRoute()
	if err != nil {
		return "", err
	}
	switch route.State {
	case storageRouteNeedsMigration:
		return "", ErrVaultStorageMigration
	case storageRouteConflict:
		return "", ErrVaultStorageConflict
	case storageRouteIncomplete:
		return "", ErrVaultStorageIncomplete
	}
	if err := ensureStorageScaffold(route.Location, true); err != nil {
		return "", err
	}
	return route.Location.Root, nil
}

func storageLocationStatus() StorageLocationStatus {
	route, err := discoverStorageRoute()
	if err != nil {
		diagnostic := "unavailable"
		if errors.Is(err, ErrVaultStorageUnsafe) {
			diagnostic = "unsafe-entry"
		}
		return StorageLocationStatus{State: "error", Diagnostic: diagnostic}
	}
	status := StorageLocationStatus{Path: route.Location.Root, TemporaryFiles: route.TemporaryFiles}
	if route.TemporaryFiles > 0 {
		status.Diagnostic = "write-residue"
	}
	switch route.State {
	case storageRouteIncomplete:
		status.State, status.Diagnostic = "incomplete-write", "incomplete-write"
		return status
	case storageRouteNeedsMigration:
		status.State = "migration-required"
		status.MigrationPending = true
		status.LegacyPaths = append([]string(nil), route.LegacyDirs...)
		if files, sourceErr := scanVaultDirectory(route.SourceDir, legacyVaultDirectory); sourceErr == nil {
			// Only the small selector is needed for display. Vault bytes stay on disk.
			source := vaultFileInventory{Files: make(map[string][]byte)}
			for name := range files {
				source.Files[name] = nil
			}
			if _, exists := files[vaultSelectorFile]; exists {
				source.Files[vaultSelectorFile], _ = readStorageFile(filepath.Join(route.SourceDir, vaultSelectorFile), 4096)
			}
			status.Format = storageFormatFromInventory(source)
			status.BackupPresent = files[dataFile+".bak"] != nil || files[dataFileV2+".bak"] != nil
			if status.Format == "v2" {
				status.Algorithm = "AES-256-GCM"
			}
		}
		if scaffoldErr := ensureStorageScaffold(route.Location, false); scaffoldErr != nil {
			status.State = "error"
		}
		return status
	case storageRouteConflict:
		status.State = "conflict"
		status.LegacyPaths = append([]string(nil), route.LegacyDirs...)
		return status
	default:
		status.State = "ready"
	}
	if err := ensureStorageScaffold(route.Location, true); err != nil {
		status.State = "error"
		return status
	}
	paths := vaultPaths(route.Location.Root)
	record, selectorErr := readVaultSelector(paths.selector)
	if selectorErr == nil && validateVaultSelectorRecord(record) == nil {
		switch record.Mode {
		case selectorActiveV2:
			status.Format = "v2"
			status.Algorithm = "AES-256-GCM"
			status.BackupPresent, _ = pathExists(paths.v2 + ".bak")
		case selectorActiveV1, selectorPreparedV2:
			status.Format = "v1 (legacy)"
			status.BackupPresent, _ = pathExists(paths.v1 + ".bak")
		}
	} else {
		v1, _ := pathExists(paths.v1)
		v1Backup, _ := pathExists(paths.v1 + ".bak")
		if v1 || v1Backup {
			status.Format = "v1 (legacy)"
			status.BackupPresent = v1Backup
		} else {
			status.Format = "not initialized"
		}
	}
	return status
}

func storageFormatFromInventory(inventory vaultFileInventory) string {
	if selectorData, ok := inventory.Files[vaultSelectorFile]; ok {
		if selector, err := parseVaultSelectorBytes(selectorData); err == nil {
			switch selector.Mode {
			case selectorActiveV2:
				return "v2"
			case selectorActiveV1:
				return "v1 (legacy)"
			case selectorPreparedV2:
				return "v1 (v2 prepared)"
			}
		}
	}
	_, hasV2 := inventory.Files[dataFileV2]
	_, hasV2Backup := inventory.Files[dataFileV2+".bak"]
	if hasV2 || hasV2Backup {
		return "unknown v2 candidate"
	}
	_, hasV1 := inventory.Files[dataFile]
	_, hasV1Backup := inventory.Files[dataFile+".bak"]
	if hasV1 || hasV1Backup {
		return "v1 (legacy)"
	}
	return "not initialized"
}
