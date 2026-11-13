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
	"reflect"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"password-saver/crypto"
	cryptov2 "password-saver/crypto/v2"
)

const vaultSelectorFile = "vault_format.state"

var (
	ErrVaultSelectionAmbiguous   = errors.New("active vault format is ambiguous or selector state is damaged")
	ErrVaultV2NotActive          = errors.New("v2 vault is not the confirmed active format")
	ErrVaultV2UIUnavailable      = errors.New("v2 storage is active but no user-interface login flow is connected")
	ErrVaultV2Protected          = errors.New("v1 reset and recovery cannot modify storage while v2 is selected")
	ErrVaultV2PreparationPending = errors.New("v1 reset and recovery are blocked while a v2 activation is prepared")
	ErrVaultV2StalePreparation   = errors.New("prepared v2 vault no longer matches the current v1 vault")
	ErrVaultV2CancelDenied       = errors.New("v2 preparation cancellation is not confirmed or no longer current")
	ErrVaultActivationDenied     = errors.New("explicit v2 activation confirmation is required")
	ErrVaultSessionClosed        = errors.New("v2 vault session is closed")
	ErrVaultSessionChanged       = errors.New("active v2 vault changed outside this session")
	ErrVaultSessionUncertain     = errors.New("v2 vault commit is uncertain; session was closed")
	vaultActivationMu            sync.Mutex
)

type vaultSelectorMode string

const (
	selectorActiveV1   vaultSelectorMode = "v1-only"
	selectorPreparedV2 vaultSelectorMode = "v1-prepared"
	selectorActiveV2   vaultSelectorMode = "v2-active"
)

type vaultSelectorRecord struct {
	Format            string            `json:"format"`
	Version           uint16            `json:"version"`
	Mode              vaultSelectorMode `json:"mode"`
	SourceV1SHA256    string            `json:"sourceV1Sha256,omitempty"`
	PreparedV2SHA256  string            `json:"preparedV2Sha256,omitempty"`
	ActivatedV2SHA256 string            `json:"activatedV2Sha256,omitempty"`
}

type vaultSelection struct {
	ActiveV2      bool
	Prepared      bool
	Fresh         bool
	NeedsV1Record bool
}

// validateVaultSelectorRecord enforces one consistent schema for every
// selector consumer. Fields from one state may never be carried into another.
func validateVaultSelectorRecord(record vaultSelectorRecord) error {
	if record.Format != "passwordsaver-vault-selector" || record.Version != 1 {
		return ErrVaultSelectionAmbiguous
	}
	switch record.Mode {
	case selectorActiveV1:
		if record.SourceV1SHA256 != "" || record.PreparedV2SHA256 != "" || record.ActivatedV2SHA256 != "" {
			return ErrVaultSelectionAmbiguous
		}
	case selectorPreparedV2:
		if !validSHA256Hex(record.SourceV1SHA256) || !validSHA256Hex(record.PreparedV2SHA256) || record.ActivatedV2SHA256 != "" {
			return ErrVaultSelectionAmbiguous
		}
	case selectorActiveV2:
		if !validSHA256Hex(record.SourceV1SHA256) || record.PreparedV2SHA256 != "" || !validSHA256Hex(record.ActivatedV2SHA256) {
			return ErrVaultSelectionAmbiguous
		}
	default:
		return ErrVaultSelectionAmbiguous
	}
	return nil
}

// ResolveVaultSelection returns only an unambiguous selection. Missing state
// is accepted as legacy v1 only when no v2 file exists; it can never silently
// downgrade a directory that contains a v2 container.
func ResolveVaultSelection(directory string) (vaultSelection, error) {
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	return resolveVaultSelectionLocked(directory)
}

func resolveVaultSelectionLocked(directory string) (vaultSelection, error) {
	paths := vaultPaths(directory)
	record, err := readVaultSelector(paths.selector)
	if errors.Is(err, os.ErrNotExist) {
		v2Exists, statErr := pathExists(paths.v2)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return vaultSelection{}, ErrVaultSelectionAmbiguous
		}
		if v2Exists {
			return vaultSelection{}, ErrVaultSelectionAmbiguous
		}
		return vaultSelection{Fresh: true, NeedsV1Record: true}, nil
	}
	if err != nil {
		return vaultSelection{}, ErrVaultSelectionAmbiguous
	}
	if err := validateVaultSelectorRecord(record); err != nil {
		return vaultSelection{}, err
	}
	switch record.Mode {
	case selectorActiveV1:
		return vaultSelection{Fresh: true}, nil
	case selectorPreparedV2:
		v1Exists, v1StatErr := pathExists(paths.v1)
		v2Exists, v2StatErr := pathExists(paths.v2)
		if v1StatErr != nil || v2StatErr != nil || !v1Exists || !v2Exists {
			return vaultSelection{}, ErrVaultSelectionAmbiguous
		}
		source, sourceErr := readVaultFile(paths.v1)
		candidate, candidateErr := readV2File(paths.v2)
		fresh := sourceErr == nil && candidateErr == nil && digestHex(source) == record.SourceV1SHA256 && digestHex(candidate) == record.PreparedV2SHA256
		return vaultSelection{Prepared: true, Fresh: fresh}, nil
	case selectorActiveV2:
		v2Exists, statErr := pathExists(paths.v2)
		if statErr != nil || !v2Exists {
			return vaultSelection{}, ErrVaultSelectionAmbiguous
		}
		return vaultSelection{ActiveV2: true, Fresh: true}, nil
	default:
		return vaultSelection{}, ErrVaultSelectionAmbiguous
	}
}

type activationPaths struct{ v1, v2, selector string }

func vaultPaths(directory string) activationPaths {
	return activationPaths{
		v1:       filepath.Join(directory, dataFile),
		v2:       filepath.Join(directory, dataFileV2),
		selector: filepath.Join(directory, vaultSelectorFile),
	}
}

func readVaultSelector(path string) (vaultSelectorRecord, error) {
	var record vaultSelectorRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return record, ErrVaultSelectionAmbiguous
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if err != nil {
		return record, err
	}
	if closeErr != nil {
		return record, closeErr
	}
	if len(data) > 4096 {
		return record, ErrVaultSelectionAmbiguous
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return vaultSelectorRecord{}, ErrVaultSelectionAmbiguous
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return vaultSelectorRecord{}, ErrVaultSelectionAmbiguous
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, data) || record.Format != "passwordsaver-vault-selector" || record.Version != 1 {
		return vaultSelectorRecord{}, ErrVaultSelectionAmbiguous
	}
	return record, nil
}

func writeVaultSelector(path string, record vaultSelectorRecord) error {
	if err := validateVaultSelectorRecord(record); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type activationChallenge struct {
	token    string
	expires  time.Time
	paths    activationPaths
	sourceID string
	v2ID     string
}

type cancelPreparationChallenge struct {
	token   string
	expires time.Time
	paths   activationPaths
	record  string
}

// v2ActivationService is intentionally unexported and is not bound through
// Wails. Confirm is a separate explicit second call using a one-time token.
type v2ActivationService struct {
	mu            sync.Mutex
	pending       *activationChallenge
	pendingCancel *cancelPreparationChallenge
}

func (s *v2ActivationService) clearChallenges() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.pending = nil
	s.pendingCancel = nil
	s.mu.Unlock()
}

const activationChallengeLifetime = 2 * time.Minute

var activationChallengeToken = newChallengeToken

func (s *v2ActivationService) Prepare(directory, masterPassword, totpCode string, engine *cryptov2.Engine) (string, error) {
	return s.prepare(directory, masterPassword, totpCode, engine, nil)
}

// prepareForSession adds a check against the Vault already open in the
// authenticated App session. The public internal preparation path still
// authenticates both files itself; this extra comparison binds UI migration
// to the exact data the user currently unlocked.
func (s *v2ActivationService) prepareForSession(directory, masterPassword, totpCode string, engine *cryptov2.Engine, expected *Vault) (string, error) {
	return s.prepare(directory, masterPassword, totpCode, engine, expected)
}

func (s *v2ActivationService) prepare(directory, masterPassword, totpCode string, engine *cryptov2.Engine, expected *Vault) (string, error) {
	if s == nil || engine == nil {
		return "", ErrVaultSelectionAmbiguous
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	selectorWasMissing := false
	if record, err := readVaultSelector(paths.selector); err == nil {
		if err := validateVaultSelectorRecord(record); err != nil {
			return "", err
		}
		switch record.Mode {
		case selectorActiveV2:
			return "", ErrVaultV2NotActive
		case selectorActiveV1:
			// The caller explicitly revalidates the candidate below.
		case selectorPreparedV2:
			// Revalidation below decides whether this prepared snapshot is fresh.
		default:
			return "", ErrVaultSelectionAmbiguous
		}
	} else if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", ErrVaultSelectionAmbiguous
		}
		selectorWasMissing = true
	}
	v1Bytes, err := readVaultFile(paths.v1)
	if err != nil {
		return "", errVaultCorrupt
	}
	v2Bytes, err := readV2File(paths.v2)
	if err != nil {
		return "", ErrVaultV2Corrupt
	}
	if format, _ := DetectVaultFormat(v1Bytes); format != VaultFormatV1 {
		return "", ErrVaultUnsupportedFormat
	}
	v1Vault, err := decryptV1MigrationData(v1Bytes, masterPassword)
	if err != nil {
		return "", err
	}
	defer wipeVault(v1Vault)
	v2Vault, err := decryptV2VaultData(v2Bytes, engine, masterPassword)
	if err != nil {
		return "", err
	}
	defer wipeVault(v2Vault)
	if !reflect.DeepEqual(v1Vault, v2Vault) {
		return "", ErrVaultV2StalePreparation
	}
	if expected != nil && !reflect.DeepEqual(v1Vault, expected) {
		return "", ErrVaultMigrationSourceChanged
	}
	if err := validateActivationTOTP(v1Vault, totpCode); err != nil {
		return "", err
	}
	if err := ensureSourceUnchanged(paths.v1, v1Bytes); err != nil {
		return "", err
	}
	if err := ensureV2FileUnchanged(paths.v2, v2Bytes); err != nil {
		return "", err
	}
	record := vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorPreparedV2,
		SourceV1SHA256: digestHex(v1Bytes), PreparedV2SHA256: digestHex(v2Bytes),
	}
	// Generate the token before persisting v1-prepared. If secure randomness
	// fails, the active v1 selector remains available for ordinary recovery.
	token, err := activationChallengeToken()
	if err != nil {
		if selectorWasMissing {
			// Once both files have been explicitly authenticated and compared,
			// persist the already-active v1 choice if confirmation-token
			// generation fails. This restores v1 recovery without selecting or
			// deleting the unactivated candidate.
			v1Only := vaultSelectorRecord{Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV1}
			if stateErr := writeVaultSelector(paths.selector, v1Only); stateErr != nil {
				return "", errors.Join(err, stateErr)
			}
		}
		return "", err
	}
	if err := writeVaultSelector(paths.selector, record); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.pending = &activationChallenge{token: token, expires: time.Now().Add(activationChallengeLifetime), paths: paths, sourceID: record.SourceV1SHA256, v2ID: record.PreparedV2SHA256}
	s.mu.Unlock()
	return token, nil
}

// BeginCancelV2Preparation starts an explicit, short-lived cancellation
// confirmation. It reads only the selector so cancellation remains available
// if the candidate was removed or the app restarted after Prepare.
func (s *v2ActivationService) BeginCancelV2Preparation(directory string) (string, error) {
	if s == nil {
		return "", ErrVaultV2CancelDenied
	}
	paths := vaultPaths(directory)
	vaultActivationMu.Lock()
	record, err := readVaultSelector(paths.selector)
	if err != nil {
		vaultActivationMu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrVaultV2CancelDenied
		}
		return "", ErrVaultSelectionAmbiguous
	}
	if err := validateVaultSelectorRecord(record); err != nil {
		vaultActivationMu.Unlock()
		return "", err
	}
	if record.Mode == selectorActiveV2 {
		vaultActivationMu.Unlock()
		return "", ErrVaultV2Protected
	}
	if record.Mode != selectorPreparedV2 {
		vaultActivationMu.Unlock()
		return "", ErrVaultV2CancelDenied
	}
	token, err := activationChallengeToken()
	if err == nil {
		s.mu.Lock()
		s.pendingCancel = &cancelPreparationChallenge{
			token: token, expires: time.Now().Add(activationChallengeLifetime),
			paths: paths, record: preparedSelectorIdentity(record),
		}
		s.mu.Unlock()
	}
	vaultActivationMu.Unlock()
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConfirmCancelV2Preparation consumes the explicit confirmation and atomically
// selects v1-only. It deliberately leaves both v1 files and the v2 candidate
// untouched. A v2-active, damaged, unknown, or changed selector is never
// rewritten as v1.
func (s *v2ActivationService) ConfirmCancelV2Preparation(token string) error {
	if s == nil {
		return ErrVaultV2CancelDenied
	}
	s.mu.Lock()
	pending := s.pendingCancel
	if pending == nil || !challengeValid(pending.token, pending.expires, token) {
		s.pendingCancel = nil
		s.mu.Unlock()
		return ErrVaultV2CancelDenied
	}
	s.pendingCancel = nil
	s.mu.Unlock()

	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	record, err := readVaultSelector(pending.paths.selector)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrVaultV2CancelDenied
		}
		return ErrVaultSelectionAmbiguous
	}
	if err := validateVaultSelectorRecord(record); err != nil {
		return err
	}
	if record.Mode == selectorActiveV2 {
		return ErrVaultV2Protected
	}
	if record.Mode != selectorPreparedV2 || preparedSelectorIdentity(record) != pending.record {
		return ErrVaultV2StalePreparation
	}
	v1Only := vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV1,
	}
	return writeVaultSelector(pending.paths.selector, v1Only)
}

func preparedSelectorIdentity(record vaultSelectorRecord) string {
	data, _ := json.Marshal(record) // The record has already passed strict JSON validation.
	return digestHex(data)
}

func decryptV1MigrationData(data []byte, masterPassword string) (*Vault, error) {
	cm, err := crypto.NewCryptoManager(masterPassword)
	if err != nil {
		return nil, err
	}
	defer cm.Wipe()
	vault, err := loadVaultData(cm, data)
	if errors.Is(err, errVaultWrongPassword) {
		return nil, errVaultMigrationWrongPass
	}
	if err != nil {
		return nil, errVaultCorrupt
	}
	return vault, nil
}

func validateActivationTOTP(vault *Vault, code string) error {
	if vault != nil && vault.TwoFAEnabled && !totp.Validate(code, vault.TwoFASecret) {
		return errors.New("2FA verification failed")
	}
	return nil
}

func (s *v2ActivationService) Confirm(token, masterPassword, totpCode string, engine *cryptov2.Engine) error {
	if s == nil || engine == nil {
		return ErrVaultActivationDenied
	}
	s.mu.Lock()
	pending := s.pending
	if pending == nil || !challengeValid(pending.token, pending.expires, token) {
		s.pending = nil
		s.mu.Unlock()
		return ErrVaultActivationDenied
	}
	s.pending = nil
	s.mu.Unlock()

	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	vaultFileMu.Lock()
	defer vaultFileMu.Unlock()
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()

	record, err := readVaultSelector(pending.paths.selector)
	if err != nil {
		if errors.Is(err, ErrVaultSelectionAmbiguous) {
			return ErrVaultSelectionAmbiguous
		}
		return ErrVaultV2StalePreparation
	}
	if err := validateVaultSelectorRecord(record); err != nil {
		return err
	}
	if record.Mode != selectorPreparedV2 || record.SourceV1SHA256 != pending.sourceID || record.PreparedV2SHA256 != pending.v2ID {
		return ErrVaultV2StalePreparation
	}
	v1Bytes, err := readVaultFile(pending.paths.v1)
	if err != nil || digestHex(v1Bytes) != pending.sourceID {
		return ErrVaultV2StalePreparation
	}
	v2Bytes, err := readV2File(pending.paths.v2)
	if err != nil || digestHex(v2Bytes) != pending.v2ID {
		return ErrVaultV2StalePreparation
	}
	v1Vault, err := decryptV1MigrationData(v1Bytes, masterPassword)
	if err != nil {
		return err
	}
	defer wipeVault(v1Vault)
	v2Vault, err := decryptV2VaultData(v2Bytes, engine, masterPassword)
	if err != nil {
		return err
	}
	defer wipeVault(v2Vault)
	if !reflect.DeepEqual(v1Vault, v2Vault) {
		return ErrVaultV2StalePreparation
	}
	if err := validateActivationTOTP(v1Vault, totpCode); err != nil {
		return err
	}
	if err := ensureSourceUnchanged(pending.paths.v1, v1Bytes); err != nil {
		return err
	}
	if err := ensureV2FileUnchanged(pending.paths.v2, v2Bytes); err != nil {
		return err
	}
	if err := writeFileAtomic(pending.paths.v2+".bak", v2Bytes); err != nil {
		return fmt.Errorf("v2 backup was not confirmed; selector remains on v1: %w", err)
	}
	backupBytes, err := readV2File(pending.paths.v2 + ".bak")
	if err != nil || !bytes.Equal(backupBytes, v2Bytes) {
		return errors.New("v2 backup verification failed; selector remains on v1")
	}
	backupVault, err := decryptV2VaultData(backupBytes, engine, masterPassword)
	if err != nil || !reflect.DeepEqual(backupVault, v2Vault) {
		wipeVault(backupVault)
		return errors.New("v2 backup authentication failed; selector remains on v1")
	}
	wipeVault(backupVault)
	active := vaultSelectorRecord{
		Format: "passwordsaver-vault-selector", Version: 1, Mode: selectorActiveV2,
		SourceV1SHA256: pending.sourceID, ActivatedV2SHA256: pending.v2ID,
	}
	if err := writeVaultSelector(pending.paths.selector, active); err != nil {
		return err
	}
	return nil
}
