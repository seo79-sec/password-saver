package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

const dataFileV2 = "vault_data.v2.enc"

var (
	ErrVaultV2Corrupt              = errors.New("v2 vault file is damaged or invalid")
	ErrVaultV2Authentication       = errors.New("v2 vault authentication failed; password may be incorrect or authenticated data may be damaged")
	ErrVaultUnsupportedFormat      = errors.New("unsupported vault format")
	ErrVaultV2TargetExists         = errors.New("v2 target file already exists")
	ErrVaultV2SourceChanged        = errors.New("v2 file changed while being updated")
	ErrVaultMigrationSourceChanged = errors.New("v1 source changed during migration")
	ErrVaultMigrationMismatch      = errors.New("v2 migration verification failed")
	errVaultFormatUnknown          = errors.New("unknown vault file format")
	errVaultMigrationWrongPass     = errors.New("incorrect v1 master password")
)

type VaultFormat uint8

const (
	VaultFormatUnknown VaultFormat = iota
	VaultFormatV1
	VaultFormatV2
)

var (
	v2VaultFileMu            sync.Mutex
	createVaultFileNoReplace = replaceFileNoReplace
)

// DetectVaultFormat classifies a file's serialization shape only. It does not
// verify the v1 HMAC, decrypt data, or authenticate a v2 AEAD tag.
func DetectVaultFormat(data []byte) (VaultFormat, error) {
	if len(data) == 0 || len(data) > maxVaultFileSize {
		return VaultFormatUnknown, errVaultFormatUnknown
	}
	trimmed := bytes.TrimSpace(data)
	var object map[string]json.RawMessage
	if json.Unmarshal(trimmed, &object) == nil {
		if _, exists := object["format"]; exists {
			return VaultFormatV2, nil
		}
	}
	// Canonical v2 begins with a top-level format member. Keep treating a
	// damaged value with that marker as a v2 candidate; never try it as v1.
	if bytes.HasPrefix(trimmed, []byte(`{"format"`)) || bytes.Contains(trimmed, []byte(`"format"`)) {
		return VaultFormatV2, nil
	}
	if len(data) > 32 {
		payload := data[:len(data)-32]
		var legacy map[string]json.RawMessage
		if json.Unmarshal(payload, &legacy) == nil {
			_, hasCiphertext := legacy["ciphertext"]
			_, hasSalt := legacy["salt"]
			_, hasNonce := legacy["nonce"]
			if hasCiphertext && hasSalt && hasNonce {
				return VaultFormatV1, nil
			}
		}
	}
	return VaultFormatUnknown, errVaultFormatUnknown
}

// ReadV2Vault reads and authenticates a staged v2 vault from an explicit path.
// It never consults v1 files or backups.
func ReadV2Vault(path string, engine *cryptov2.Engine, masterPassword string) (*Vault, error) {
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	return readV2VaultAt(path, engine, masterPassword)
}

func readV2VaultAt(path string, engine *cryptov2.Engine, masterPassword string) (*Vault, error) {
	data, err := readV2File(path)
	if err != nil {
		return nil, err
	}
	return decryptV2VaultData(data, engine, masterPassword)
}

func decryptV2VaultData(data []byte, engine *cryptov2.Engine, masterPassword string) (*Vault, error) {
	format, err := DetectVaultFormat(data)
	if err != nil {
		return nil, ErrVaultUnsupportedFormat
	}
	if format != VaultFormatV2 {
		return nil, ErrVaultUnsupportedFormat
	}
	if engine == nil {
		return nil, errors.New("v2 crypto engine is unavailable")
	}
	plaintext, err := engine.Decrypt(masterPassword, data)
	if err != nil {
		switch {
		case errors.Is(err, cryptov2.ErrAuthentication):
			return nil, ErrVaultV2Authentication
		case errors.Is(err, cryptov2.ErrUnsupportedFormat), errors.Is(err, cryptov2.ErrUnsupportedAlgorithm):
			return nil, ErrVaultUnsupportedFormat
		case errors.Is(err, cryptov2.ErrInvalidContainer), errors.Is(err, cryptov2.ErrInputTooLarge):
			return nil, ErrVaultV2Corrupt
		default:
			return nil, err
		}
	}
	defer wipeBytes(plaintext)
	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, ErrVaultV2Corrupt
	}
	return &vault, nil
}

// SaveV2Vault persists a v2 vault at an explicit, non-active path. Existing
// containers must authenticate before being backed up or replaced. The backup
// contains only the previous encrypted container bytes.
func SaveV2Vault(path string, engine *cryptov2.Engine, masterPassword string, vault *Vault) error {
	if engine == nil || vault == nil {
		return errors.New("v2 crypto engine and vault are required")
	}
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	serializedVault, err := json.Marshal(vault)
	if err != nil {
		return err
	}
	container, err := engine.Encrypt(masterPassword, serializedVault)
	wipeBytes(serializedVault)
	if err != nil {
		return err
	}
	previous, err := readV2File(path)
	if errors.Is(err, os.ErrNotExist) {
		return writeFileAtomicNoReplace(path, container)
	}
	if err != nil {
		return err
	}
	verified, err := decryptV2VaultData(previous, engine, masterPassword)
	if err != nil {
		return fmt.Errorf("existing v2 vault was not replaced: %w", err)
	}
	wipeVault(verified)
	if err := ensureV2FileUnchanged(path, previous); err != nil {
		return err
	}
	if err := writeFileAtomic(path+".bak", previous); err != nil {
		return fmt.Errorf("encrypted backup was not confirmed; primary v2 vault was not changed: %w", err)
	}
	if err := ensureV2FileUnchanged(path, previous); err != nil {
		return err
	}
	return writeFileAtomic(path, container)
}

// MigrateV1VaultToV2 prepares vault_data.v2.enc while leaving vault_data.enc
// and its .bak untouched. The v1 file remains the active application vault.
func MigrateV1VaultToV2(masterPassword string, engine *cryptov2.Engine) error {
	return migrateV1ToV2Paths(dataFile, dataFileV2, masterPassword, engine)
}

func migrateV1ToV2Paths(sourcePath, targetPath, masterPassword string, engine *cryptov2.Engine) error {
	if engine == nil {
		return errors.New("v2 crypto engine is unavailable")
	}
	sourceAbs, err := filepath.Abs(sourcePath)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	if filepath.Clean(sourceAbs) == filepath.Clean(targetAbs) || filepath.Clean(sourceAbs+".bak") == filepath.Clean(targetAbs) {
		return errors.New("migration target must be separate from v1 primary and backup")
	}

	// SaveVault and migration share this lock, preventing in-process writes while
	// a stable source snapshot is verified. The v2 lock serializes staged writes.
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	if err := ensurePathAbsent(targetPath); err != nil {
		return err
	}
	sourceBytes, err := readVaultFile(sourcePath)
	if err != nil {
		return err
	}
	format, err := DetectVaultFormat(sourceBytes)
	if format == VaultFormatV2 {
		return ErrVaultUnsupportedFormat
	}
	if err != nil || format != VaultFormatV1 {
		return errVaultCorrupt
	}
	cm, err := crypto.NewCryptoManager(masterPassword)
	if err != nil {
		return err
	}
	defer cm.Wipe()
	vault, err := loadVaultData(cm, sourceBytes)
	if err != nil {
		if errors.Is(err, errVaultWrongPassword) {
			return errVaultMigrationWrongPass
		}
		return fmt.Errorf("v1 source could not be authenticated: %w", errVaultCorrupt)
	}
	defer wipeVault(vault)

	serializedVault, err := json.Marshal(vault)
	if err != nil {
		return err
	}
	container, err := engine.Encrypt(masterPassword, serializedVault)
	wipeBytes(serializedVault)
	if err != nil {
		return err
	}
	if err := ensureSourceUnchanged(sourcePath, sourceBytes); err != nil {
		return err
	}
	if err := writeFileAtomicNoReplace(targetPath, container); err != nil {
		return err
	}
	createdTarget := true
	cleanupTarget := func() {
		if !createdTarget {
			return
		}
		current, readErr := readV2File(targetPath)
		if readErr == nil && bytes.Equal(current, container) {
			if removeErr := os.Remove(targetPath); removeErr == nil {
				_ = syncVaultDirectory(filepath.Dir(targetPath))
			}
		}
	}
	verified, err := readV2VaultAt(targetPath, engine, masterPassword)
	if err != nil {
		cleanupTarget()
		return fmt.Errorf("%w: staged v2 container did not reopen: %v", ErrVaultMigrationMismatch, err)
	}
	if !reflect.DeepEqual(vault, verified) {
		wipeVault(verified)
		cleanupTarget()
		return ErrVaultMigrationMismatch
	}
	wipeVault(verified)
	if err := ensureSourceUnchanged(sourcePath, sourceBytes); err != nil {
		// Do not remove the verified candidate if source changed externally. It is
		// clearly a staged snapshot, never an automatic replacement of the source.
		createdTarget = false
		return err
	}
	createdTarget = false
	return nil
}

func ensureSourceUnchanged(path string, original []byte) error {
	current, err := readVaultFile(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVaultMigrationSourceChanged, err)
	}
	if !bytes.Equal(current, original) {
		return ErrVaultMigrationSourceChanged
	}
	return nil
}

func ensureV2FileUnchanged(path string, original []byte) error {
	current, err := readV2File(path)
	if err != nil || !bytes.Equal(current, original) {
		return ErrVaultV2SourceChanged
	}
	return nil
}

func ensurePathAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return ErrVaultV2TargetExists
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readV2File(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > cryptov2.MaxContainerSize {
		return nil, ErrVaultV2Corrupt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, cryptov2.MaxContainerSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > cryptov2.MaxContainerSize {
		return nil, ErrVaultV2Corrupt
	}
	return data, nil
}

func writeFileAtomicNoReplace(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := ensurePathAbsent(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".vault-v2-stage-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := syncVaultTempFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := createVaultFileNoReplace(tmpName, path); err != nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			return ErrVaultV2TargetExists
		}
		return err
	}
	if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: target created but temporary link cleanup failed: %v", errVaultCommitUncertain, err)
	}
	if err := syncVaultDirectory(dir); err != nil {
		return fmt.Errorf("%w: %v", errVaultCommitUncertain, err)
	}
	return nil
}

func wipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func wipeVault(vault *Vault) {
	if vault == nil {
		return
	}
	for i := range vault.Accounts {
		vault.Accounts[i].ID = ""
		vault.Accounts[i].Title = ""
		vault.Accounts[i].Login = ""
		vault.Accounts[i].Password = ""
		vault.Accounts[i].UpdatedAt = 0
	}
	vault.Accounts = nil
	vault.TwoFASecret = ""
	vault.TwoFAEnabled = false
}
