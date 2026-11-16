package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type storageDirectoryKind uint8

const (
	managedVaultDirectory storageDirectoryKind = iota
	legacyVaultDirectory
)

type vaultDirectoryScan struct {
	Files          map[string]os.FileInfo
	TemporaryFiles int
}

// Go's CreateTemp currently appends a decimal uint32. Limit the allowlist to
// that exact spelling; a prefix alone is never sufficient. The contents stay
// untrusted and are never read, selected, copied or used as a backup.
func isVaultWriteTemporary(name string) bool {
	for _, prefix := range []string{".vault-write-", ".vault-v2-stage-"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		value, err := strconv.ParseUint(suffix, 10, 32)
		return err == nil && strconv.FormatUint(value, 10) == suffix
	}
	return false
}

func vaultWriteTemporaryLimit() int64 {
	return max(int64(maxVaultFileSize), v2ContainerFileLimit())
}

func knownVaultFileLimits() map[string]int64 {
	return map[string]int64{
		dataFile: maxVaultFileSize, dataFile + ".bak": maxVaultFileSize,
		dataFileV2: v2ContainerFileLimit(), dataFileV2 + ".bak": v2ContainerFileLimit(),
		vaultSelectorFile: 4096,
	}
}

// scanVaultDirectory checks metadata only, including for empty/corrupt vaults.
// Legacy directories can also contain the EXE, checksums and unrelated user
// files. Never open or enumerate those files for the purpose of migration.
// Managed directories retain the strict allowlist, including in staging.
func scanVaultDirectory(directory string, kind storageDirectoryKind) (map[string]os.FileInfo, error) {
	scan, err := scanVaultDirectoryDetails(directory, kind)
	return scan.Files, err
}

func scanVaultDirectoryDetails(directory string, kind storageDirectoryKind) (vaultDirectoryScan, error) {
	out := vaultDirectoryScan{Files: make(map[string]os.FileInfo)}
	if strings.TrimSpace(directory) == "" || !filepath.IsAbs(directory) {
		return out, ErrVaultDataLocation
	}
	if err := checkExistingPathComponents(directory); err != nil {
		return out, err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("%w: cannot inspect vault directory", ErrVaultDataLocation)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return out, ErrVaultStorageUnsafe
	}
	if reparse, err := storagePathIsReparsePoint(directory); err != nil || reparse {
		return out, ErrVaultStorageUnsafe
	}
	limits := knownVaultFileLimits()
	if kind == managedVaultDirectory {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return out, err
		}
		for _, entry := range entries {
			if _, known := limits[entry.Name()]; known {
				continue
			}
			if isVaultWriteTemporary(entry.Name()) {
				// A live writer may remove its temporary between ReadDir and
				// Lstat. Do not open it or act on a stale path after this check.
				_, err := statStorageFile(filepath.Join(directory, entry.Name()), vaultWriteTemporaryLimit())
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return out, ErrVaultStorageUnsafe
				}
				out.TemporaryFiles++
				continue
			}
			limit := int64(maxVaultFileSize)
			if entry.Name() == storageMigrationReceiptFile {
				limit = storageReceiptLimit
			} else if !isVaultDiagnosticArchive(entry.Name()) {
				return out, ErrVaultStorageUnsafe
			}
			if _, err := statStorageFile(filepath.Join(directory, entry.Name()), limit); err != nil {
				return out, err
			}
		}
	} else if kind != legacyVaultDirectory {
		return out, ErrVaultStorageUnsafe
	}
	for name, limit := range limits {
		info, err := statStorageFile(filepath.Join(directory, name), limit)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		out.Files[name] = info
	}
	return out, nil
}

func statStorageFile(path string, limit int64) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrVaultStorageUnsafe
	}
	if reparse, err := storagePathIsReparsePoint(path); err != nil || reparse {
		return nil, ErrVaultStorageUnsafe
	}
	if info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("%w: a vault file exceeds its size limit", ErrVaultDataLocation)
	}
	return info, nil
}

// This hook also lets tests count payload reads in location-only operations.
var readStorageInventoryFile = readStorageFile

func readStorageFile(path string, limit int64) ([]byte, error) {
	info, err := statStorageFile(path, limit)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrVaultStorageUnsafe
	}
	data, readErr := readLimited(file, limit)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func inspectVaultFiles(directory string) (vaultFileInventory, error) {
	return readVaultInventory(directory, managedVaultDirectory)
}

func inspectLegacyVaultFiles(directory string) (vaultFileInventory, error) {
	return readVaultInventory(directory, legacyVaultDirectory)
}

func readVaultInventory(directory string, kind storageDirectoryKind) (vaultFileInventory, error) {
	out := vaultFileInventory{Files: make(map[string][]byte)}
	files, err := scanVaultDirectory(directory, kind)
	if err != nil {
		return out, err
	}
	limits := knownVaultFileLimits()
	for name := range files {
		data, err := readStorageInventoryFile(filepath.Join(directory, name), limits[name])
		if err != nil {
			return vaultFileInventory{}, err
		}
		out.Files[name] = data
	}
	out.HasVaultFiles = len(out.Files) > 0
	return out, nil
}
