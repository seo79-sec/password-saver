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
)

const storageMigrationReceiptFile = "storage.migration.json"

type storageMigrationReceipt struct {
	Format      string            `json:"format"`
	Version     uint16            `json:"version"`
	Source      string            `json:"source"`
	SourceFiles map[string]string `json:"sourceFiles"`
}

type storageRoute struct {
	Location   storageLocation
	State      storageRouteState
	LegacyDirs []string
	SourceDir  string
}

type StorageLocationStatus struct {
	State            string   `json:"state"`
	Path             string   `json:"path"`
	LegacyPaths      []string `json:"legacyPaths"`
	Format           string   `json:"format"`
	Algorithm        string   `json:"algorithm"`
	BackupPresent    bool     `json:"backupPresent"`
	MigrationPending bool     `json:"migrationPending"`
}

// The override is only used by tests. Production callers always resolve the
// OS-standard per-user directory and never switch the process working folder.
var storageOverrideMu sync.RWMutex
var storageDirectoryOverride string
var legacyDirectoryProvider = discoverLegacyVaultDirectories

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

func inspectVaultFiles(directory string) (vaultFileInventory, error) {
	var out = vaultFileInventory{Files: make(map[string][]byte)}
	if strings.TrimSpace(directory) == "" || !filepath.IsAbs(directory) {
		return out, ErrVaultDataLocation
	}
	if err := checkExistingPathComponents(directory); err != nil {
		return vaultFileInventory{}, err
	}
	dirInfo, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return vaultFileInventory{}, fmt.Errorf("%w: cannot inspect vault directory", ErrVaultDataLocation)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return vaultFileInventory{}, ErrVaultStorageUnsafe
	}
	if reparse, err := storagePathIsReparsePoint(directory); err != nil || reparse {
		return vaultFileInventory{}, ErrVaultStorageUnsafe
	}
	limits := map[string]int64{
		dataFile:            maxVaultFileSize,
		dataFile + ".bak":   maxVaultFileSize,
		dataFileV2:          v2ContainerFileLimit(),
		dataFileV2 + ".bak": v2ContainerFileLimit(),
		vaultSelectorFile:   4096,
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return vaultFileInventory{}, fmt.Errorf("%w: cannot inspect vault directory entries", ErrVaultDataLocation)
	}
	for _, entry := range entries {
		if _, known := limits[entry.Name()]; !known && entry.Name() != storageMigrationReceiptFile && !isVaultDiagnosticArchive(entry.Name()) {
			return vaultFileInventory{}, ErrVaultStorageUnsafe
		}
	}
	for _, entry := range entries {
		if entry.Name() == storageMigrationReceiptFile || isVaultDiagnosticArchive(entry.Name()) {
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxVaultFileSize {
				return vaultFileInventory{}, ErrVaultStorageUnsafe
			}
			if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
				return vaultFileInventory{}, ErrVaultStorageUnsafe
			}
		}
	}
	for filename, limit := range limits {
		path := filepath.Join(directory, filename)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return vaultFileInventory{}, fmt.Errorf("%w: cannot inspect vault file", ErrVaultDataLocation)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return vaultFileInventory{}, ErrVaultStorageUnsafe
		}
		if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
			return vaultFileInventory{}, ErrVaultStorageUnsafe
		}
		if info.Size() < 0 || info.Size() > limit {
			return vaultFileInventory{}, fmt.Errorf("%w: a vault file exceeds its size limit", ErrVaultDataLocation)
		}
		file, err := os.Open(path)
		if err != nil {
			return vaultFileInventory{}, fmt.Errorf("%w: cannot read vault file", ErrVaultDataLocation)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
			_ = file.Close()
			return vaultFileInventory{}, ErrVaultStorageUnsafe
		}
		data, readErr := readLimited(file, limit)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return vaultFileInventory{}, fmt.Errorf("%w: cannot read vault file", ErrVaultDataLocation)
		}
		out.Files[filename] = data
		out.HasVaultFiles = true
	}
	return out, nil
}

func isVaultDiagnosticArchive(name string) bool {
	return strings.HasPrefix(name, dataFile+".corrupt-") || strings.HasPrefix(name, dataFileV2+".corrupt-")
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
	legacy, err := inspectVaultFiles(legacyDir)
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

func validStorageMigrationReceipt(directory, source string, sourceInventory, targetInventory vaultFileInventory) bool {
	if !sourceInventory.HasVaultFiles || !targetInventory.HasVaultFiles || !filepath.IsAbs(source) {
		return false
	}
	path := filepath.Join(directory, storageMigrationReceiptFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16*1024 {
		return false
	}
	if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
		return false
	}
	data, err := os.ReadFile(path)
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

func discoverStorageRoute() (storageRoute, error) {
	location, err := configuredStorageLocation()
	if err != nil {
		return storageRoute{}, err
	}
	target, err := inspectVaultFiles(location.Root)
	if err != nil {
		return storageRoute{}, err
	}
	legacyCandidates, err := legacyDirectoryProvider(location.Root)
	if err != nil {
		return storageRoute{}, err
	}
	legacyWithFiles := make([]string, 0, len(legacyCandidates))
	legacyInventories := make([]vaultFileInventory, 0, len(legacyCandidates))
	for _, candidate := range legacyCandidates {
		inventory, err := inspectVaultFiles(candidate)
		if err != nil {
			return storageRoute{}, err
		}
		if inventory.HasVaultFiles {
			legacyWithFiles = append(legacyWithFiles, candidate)
			legacyInventories = append(legacyInventories, inventory)
		}
	}
	if len(legacyWithFiles) > 1 {
		return storageRoute{Location: location, State: storageRouteConflict, LegacyDirs: legacyWithFiles}, nil
	}
	if target.HasVaultFiles && len(legacyWithFiles) > 0 {
		if len(legacyWithFiles) == 1 {
			legacy := legacyInventories[0]
			if validStorageMigrationReceipt(location.Root, legacyWithFiles[0], legacy, target) {
				return storageRoute{Location: location, State: storageRouteReady, LegacyDirs: legacyWithFiles}, nil
			}
		}
		return storageRoute{Location: location, State: storageRouteConflict, LegacyDirs: legacyWithFiles}, nil
	}
	if len(legacyWithFiles) > 0 {
		if err := requireEmptyDirectoryIfPresent(location.Root); err != nil {
			return storageRoute{Location: location, State: storageRouteConflict, LegacyDirs: legacyWithFiles}, nil
		}
		return storageRoute{Location: location, State: storageRouteNeedsMigration, LegacyDirs: legacyWithFiles, SourceDir: legacyWithFiles[0]}, nil
	}
	return storageRoute{Location: location, State: storageRouteReady}, nil
}

func discoverLegacyVaultDirectories(target string) ([]string, error) {
	var candidates []string
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot determine executable directory", ErrVaultDataLocation)
	}
	executableDir, err := filepath.Abs(filepath.Dir(executable))
	if err != nil {
		return nil, ErrVaultDataLocation
	}
	// Do not scan the process working directory: a launcher may start the app
	// from an unrelated path containing files with the same names. Only the
	// executable's former data directory is a supported legacy location.
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
	}
	if err := ensureStorageScaffold(route.Location, true); err != nil {
		return "", err
	}
	return route.Location.Root, nil
}

func storageLocationStatus() StorageLocationStatus {
	route, err := discoverStorageRoute()
	if err != nil {
		return StorageLocationStatus{State: "error"}
	}
	status := StorageLocationStatus{Path: route.Location.Root}
	switch route.State {
	case storageRouteNeedsMigration:
		status.State = "migration-required"
		status.MigrationPending = true
		status.LegacyPaths = append([]string(nil), route.LegacyDirs...)
		if source, sourceErr := inspectVaultFiles(route.SourceDir); sourceErr == nil {
			status.Format = storageFormatFromInventory(source)
			status.BackupPresent = len(source.Files[dataFile+".bak"]) > 0 || len(source.Files[dataFileV2+".bak"]) > 0
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
	if len(inventory.Files[dataFileV2]) > 0 || len(inventory.Files[dataFileV2+".bak"]) > 0 {
		return "unknown v2 candidate"
	}
	if len(inventory.Files[dataFile]) > 0 || len(inventory.Files[dataFile+".bak"]) > 0 {
		return "v1 (legacy)"
	}
	return "not initialized"
}
