package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	cryptov2 "password-saver/crypto/v2"
	"password-saver/internal/replicastore"
)

const (
	v3MarkerFile   = "v3_activation.state"
	v3SourceFile   = "source.v2.enc"
	v3RollbackFile = "rollback.v2.enc"
)

type v3ActivationMarker struct {
	Version  uint8
	ID       [16]byte
	Source   [sha256.Size]byte
	KeyWrap  []byte
	Rollback [sha256.Size]byte // Zero selects SQLite, otherwise selects the verified v2 snapshot.
}

func (a *App) activateV3Copy(ctx context.Context, candidate v3MigrationCandidate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, err := a.replicaKeySessionLocked()
	if err != nil {
		return err
	}
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	if sameStoragePath(candidate.profile, filepath.Dir(a.v2Session.path)) {
		return ErrVaultStorageUnsafe
	}
	markerPath := filepath.Join(candidate.profile, v3MarkerFile)
	if err := ensurePathAbsent(markerPath); err != nil {
		return err
	}
	sourcePath := a.v2Session.path
	source, err := readV2File(sourcePath)
	if err != nil || a.v2Session.digest != candidate.sourceSHA256 || sha256.Sum256(source) != candidate.sourceSHA256 {
		return ErrVaultV2SourceChanged
	}
	accounts, err := readV3MigrationRecords(ctx, session, candidate)
	defer clear(accounts)
	expected := slices.Clone(a.vault.Accounts)
	defer clear(expected)
	slices.SortFunc(expected, func(a, b Account) int { return strings.Compare(a.ID, b.ID) })
	if err != nil || !slices.Equal(accounts, expected) {
		return errors.Join(ErrVaultMigrationMismatch, err)
	}
	if err := writeFileAtomic(filepath.Join(candidate.profile, v3SourceFile), source); err != nil {
		return err
	}
	marker := v3ActivationMarker{Version: 1, ID: candidate.id, Source: candidate.sourceSHA256, KeyWrap: candidate.wrappedKey}
	return writeFileAtomicNoReplaceChecked(markerPath, marker.encode(), func() error {
		return errors.Join(ctx.Err(), ensureV2FileUnchanged(sourcePath, source))
	})
}

func (m v3ActivationMarker) encode() []byte {
	body, _ := json.Marshal(m)
	digest := sha256.Sum256(body)
	return append(digest[:], body...)
}

type v3OpenedCopy struct {
	dir     string
	marker  v3ActivationMarker
	session *cryptov2.Session
	vault   *Vault
	replica *replicastore.Store
}

// The callback owns access to the copy under the write lock. The session and
// replica handle are closed before this call returns.
func withV3Copy(ctx context.Context, dir string, engine *cryptov2.Engine, password, code string, use func(*v3OpenedCopy) error) error {
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	data, err := readV2File(filepath.Join(dir, v3MarkerFile))
	if err != nil {
		return err
	}
	p := v3OpenedCopy{dir: dir}
	if len(data) <= sha256.Size || len(data) > 4096 || json.Unmarshal(data[sha256.Size:], &p.marker) != nil ||
		p.marker.Version != 1 || !bytes.Equal(p.marker.encode(), data) {
		return ErrVaultSelectionAmbiguous
	}
	name, digest := v3SourceFile, p.marker.Source
	if p.marker.Rollback != ([sha256.Size]byte{}) {
		name, digest = v3RollbackFile, p.marker.Rollback
	}
	container, err := readV2File(filepath.Join(dir, name))
	if err != nil || sha256.Sum256(container) != digest {
		return errors.Join(ErrVaultSelectionAmbiguous, err)
	}
	session, plain, err := engine.Unlock(password, container)
	if err != nil {
		return err
	}
	defer session.Close()
	defer wipeBytes(plain)
	p.session, p.vault = session, &Vault{}
	defer wipeVault(p.vault)
	if json.Unmarshal(plain, p.vault) != nil {
		return ErrVaultV2Corrupt
	}
	if err := validateActivationTOTP(p.vault, code); err != nil {
		return err
	}
	if name == v3SourceFile {
		key, err := session.OpenReplicaKey(p.marker.ID, p.marker.KeyWrap)
		defer clear(key[:])
		if err != nil {
			return err
		}
		candidate := v3MigrationCandidate{profile: dir}
		p.replica, err = replicastore.Open(ctx, candidate.replicaPath(), key)
		if err != nil {
			return err
		}
		defer p.replica.Close()
		if p.replica.Identity() != p.marker.ID {
			return replicastore.ErrAuthentication
		}
	}
	return use(&p)
}

// rollback is called only within withV3Copy, with exclusive access to writes.
func (p *v3OpenedCopy) rollback(ctx context.Context, engine *cryptov2.Engine, password string) error {
	if p.replica == nil {
		return ErrVaultActivationDenied
	}
	view, err := p.replica.Read(ctx)
	if err != nil {
		return err
	}
	accounts, err := v3AccountsFromRecords(view.Records)
	if err != nil {
		return err
	}
	vault := &Vault{Accounts: accounts, TwoFAEnabled: p.vault.TwoFAEnabled, TwoFASecret: p.vault.TwoFASecret}
	defer wipeVault(vault)
	plain, err := json.Marshal(vault)
	if err != nil {
		return err
	}
	defer wipeBytes(plain)
	container, err := p.session.Encrypt(plain)
	if err != nil {
		return err
	}
	path := filepath.Join(p.dir, v3RollbackFile)
	if err := writeFileAtomic(path, container); err != nil {
		return err
	}
	verified, err := readV2VaultAt(path, engine, password)
	defer wipeVault(verified)
	if err != nil || !reflect.DeepEqual(verified, vault) {
		return errors.Join(ErrVaultMigrationMismatch, err)
	}
	marker := p.marker
	marker.Rollback = sha256.Sum256(container)
	if err := p.replica.Close(); err != nil {
		return err
	}
	p.replica = nil
	return writeFileAtomicChecked(filepath.Join(p.dir, v3MarkerFile), marker.encode(), func() error {
		return errors.Join(ctx.Err(), ensureV2FileUnchanged(path, container))
	})
}
