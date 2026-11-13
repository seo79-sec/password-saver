package main

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	cryptov2 "password-saver/crypto/v2"
)

const (
	VaultStateV1Active   = "v1-active"
	VaultStateV1Prepared = "v1-prepared"
	VaultStateV2Active   = "v2-active"
	VaultStateAmbiguous  = "ambiguous"
)

// VaultPublicStatus is the only format information exposed to Wails. It never
// contains container metadata, hashes, password data, TOTP secrets, or keys.
type VaultPublicStatus struct {
	State              string `json:"state"`
	V2ContainerPresent bool   `json:"v2ContainerPresent"`
	PreparationFresh   bool   `json:"preparationFresh"`
}

var (
	defaultV2EngineOnce sync.Once
	defaultV2Engine     *cryptov2.Engine
	defaultV2EngineErr  error
)

func createDefaultV2Engine() (*cryptov2.Engine, error) {
	defaultV2EngineOnce.Do(func() {
		defaultV2Engine, defaultV2EngineErr = cryptov2.NewEngine(cryptov2.Options{})
	})
	return defaultV2Engine, defaultV2EngineErr
}

func (a *App) v2EngineLocked() (*cryptov2.Engine, error) {
	if a.v2Engine != nil {
		return a.v2Engine, nil
	}
	engine, err := createDefaultV2Engine()
	if err != nil {
		return nil, err
	}
	a.v2Engine = engine
	return engine, nil
}

func (a *App) v2ActivationLocked() *v2ActivationService {
	if a.v2Activation == nil {
		a.v2Activation = &v2ActivationService{}
	}
	return a.v2Activation
}

// GetVaultStatus returns a small, nonsecret summary for the login and security
// screens. A valid active selector remains v2-active even if its file is
// missing, so the frontend cannot offer a v1 downgrade.
func (a *App) GetVaultStatus() VaultPublicStatus {
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	return vaultPublicStatusLocked(".")
}

func vaultPublicStatusLocked(directory string) VaultPublicStatus {
	paths := vaultPaths(directory)
	record, err := readVaultSelector(paths.selector)
	if errors.Is(err, os.ErrNotExist) {
		candidate, candidateErr := pathExists(paths.v2)
		if candidateErr != nil || candidate {
			return VaultPublicStatus{State: VaultStateAmbiguous}
		}
		return VaultPublicStatus{State: VaultStateV1Active}
	}
	if err != nil || validateVaultSelectorRecord(record) != nil {
		return VaultPublicStatus{State: VaultStateAmbiguous}
	}
	candidate, candidateErr := pathExists(paths.v2)
	if candidateErr != nil {
		candidate = false
	}
	switch record.Mode {
	case selectorActiveV1:
		return VaultPublicStatus{State: VaultStateV1Active, V2ContainerPresent: candidate}
	case selectorPreparedV2:
		fresh := false
		if selection, selectionErr := resolveVaultSelectionLocked(directory); selectionErr == nil {
			fresh = selection.Fresh
		}
		return VaultPublicStatus{State: VaultStateV1Prepared, V2ContainerPresent: candidate, PreparationFresh: fresh}
	case selectorActiveV2:
		return VaultPublicStatus{State: VaultStateV2Active, V2ContainerPresent: candidate}
	default:
		return VaultPublicStatus{State: VaultStateAmbiguous}
	}
}

// LoginV2 is the Wails entry point for active v2 storage. The master password
// is used only for this call; the opaque session retains a DEK, never the
// password. A pending session remains locked until Verify2FA succeeds.
func (a *App) LoginV2(password string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return false, err
	}
	a.logoutLocked()
	selection, err := ResolveVaultSelection(".")
	if err != nil {
		return false, err
	}
	if !selection.ActiveV2 {
		return false, ErrVaultV2NotActive
	}
	present, statErr := pathExists(dataFileV2)
	if statErr != nil || !present {
		return false, ErrVaultV2Corrupt
	}
	engine, err := a.v2EngineLocked()
	if err != nil {
		return false, err
	}
	session, vault, err := openActiveV2VaultSession(dataFileV2, engine, password)
	if err != nil {
		if errors.Is(err, cryptov2.ErrAuthentication) {
			return false, ErrVaultV2Authentication
		}
		if errors.Is(err, cryptov2.ErrInvalidContainer) || errors.Is(err, cryptov2.ErrInputTooLarge) {
			return false, ErrVaultV2Corrupt
		}
		if errors.Is(err, cryptov2.ErrUnsupportedFormat) || errors.Is(err, cryptov2.ErrUnsupportedAlgorithm) {
			return false, ErrVaultUnsupportedFormat
		}
		return false, err
	}
	a.cm = nil
	a.v2Session = session
	a.vault = vault
	needsTOTP := vault.TwoFAEnabled
	a.twoFAVerified = !needsTOTP
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}
	a.lastActivity = time.Now()
	a.armIdleTimerLocked()
	return needsTOTP, nil
}

// PrepareV2Migration requires a live, fully authenticated v1 session and
// reauthenticates the supplied password and TOTP before staging or preparing
// a candidate. It never activates v2; that requires ConfirmV2Migration.
func (a *App) PrepareV2Migration(password, totpCode string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cm == nil || a.v2Session != nil || a.vault == nil || a.isLockedLocked() {
		return "", errors.New("разблокируйте активное хранилище v1 перед подготовкой миграции")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return "", err
	}
	vaultActivationMu.Lock()
	status := vaultPublicStatusLocked(".")
	vaultActivationMu.Unlock()
	if status.State == VaultStateV2Active {
		return "", ErrVaultV2Protected
	}
	if status.State == VaultStateAmbiguous {
		return "", ErrVaultSelectionAmbiguous
	}
	if status.State == VaultStateV1Prepared && !status.V2ContainerPresent {
		return "", ErrVaultV2Corrupt
	}

	vaultFileMu.Lock()
	source, err := readVaultFile(dataFile)
	vaultFileMu.Unlock()
	if err != nil {
		return "", err
	}
	verified, err := decryptV1MigrationData(source, password)
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(verified, a.vault) {
		wipeVault(verified)
		return "", ErrVaultMigrationSourceChanged
	}
	defer wipeVault(verified)
	if verified.TwoFAEnabled && !totp.Validate(totpCode, verified.TwoFASecret) {
		a.recordTOTPFailureLocked()
		return "", errors.New("неверный код 2FA")
	}
	a.totpFailures = 0
	a.totpBlockedUntil = time.Time{}

	engine, err := a.v2EngineLocked()
	if err != nil {
		return "", err
	}
	service := a.v2ActivationLocked()
	if !status.V2ContainerPresent {
		if err := MigrateV1VaultToV2(password, engine); err != nil {
			return "", err
		}
	}
	return service.prepareForSession(".", password, totpCode, engine, a.vault)
}

// ConfirmV2Migration is the explicit second activation step. It verifies the
// active v1 session, current password, TOTP, and prepared file snapshots again
// before the selector is committed and the previous session is closed.
func (a *App) ConfirmV2Migration(token, password, totpCode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cm == nil || a.v2Session != nil || a.vault == nil || a.isLockedLocked() {
		return errors.New("для активации требуется открытая сессия v1")
	}
	if err := a.checkTOTPAttemptsLocked(); err != nil {
		return err
	}
	if a.vault.TwoFAEnabled && !totp.Validate(totpCode, a.vault.TwoFASecret) {
		a.recordTOTPFailureLocked()
		return errors.New("неверный код 2FA")
	}
	service := a.v2ActivationLocked()
	engine, err := a.v2EngineLocked()
	if err != nil {
		return err
	}
	err = a.confirmV2ActivationLocked(service, token, password, totpCode, engine)
	if err == nil {
		a.totpFailures = 0
		a.totpBlockedUntil = time.Time{}
	}
	return err
}

// BeginCancelV2Preparation and ConfirmCancelV2Preparation are explicit
// Wails-bound wrappers around the durable backend cancellation challenge.
func (a *App) BeginCancelV2Preparation() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v2ActivationLocked().BeginCancelV2Preparation(".")
}

func (a *App) ConfirmCancelV2Preparation(token string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v2ActivationLocked().ConfirmCancelV2Preparation(token)
}
