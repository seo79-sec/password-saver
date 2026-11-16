package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type storageDirectoryKind uint8

const (
	managedVaultDirectory storageDirectoryKind = iota
	legacyVaultDirectory
)

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
	files := make(map[string]os.FileInfo)
	if strings.TrimSpace(directory) == "" || !filepath.IsAbs(directory) {
		return nil, ErrVaultDataLocation
	}
	if err := checkExistingPathComponents(directory); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return files, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: cannot inspect vault directory", ErrVaultDataLocation)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrVaultStorageUnsafe
	}
	if reparse, err := storagePathIsReparsePoint(directory); err != nil || reparse {
		return nil, ErrVaultStorageUnsafe
	}
	limits := knownVaultFileLimits()
	if kind == managedVaultDirectory {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if _, known := limits[entry.Name()]; known {
				continue
			}
			limit := int64(maxVaultFileSize)
			if entry.Name() == storageMigrationReceiptFile {
				limit = storageReceiptLimit
			} else if !isVaultDiagnosticArchive(entry.Name()) {
				return nil, ErrVaultStorageUnsafe
			}
			if _, err := statStorageFile(filepath.Join(directory, entry.Name()), limit); err != nil {
				return nil, err
			}
		}
	} else if kind != legacyVaultDirectory {
		return nil, ErrVaultStorageUnsafe
	}
	for name, limit := range limits {
		info, err := statStorageFile(filepath.Join(directory, name), limit)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files[name] = info
	}
	return files, nil
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
