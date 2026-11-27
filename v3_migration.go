package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cryptov2 "password-saver/crypto/v2"
	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
)

var (
	errV3MigrationRecordID = errors.New("v2 snapshot contains an empty or duplicate record ID")
	errV3MigrationConflict = errors.New("replica contains conflicting record versions")
)

type v3MigrationCandidate struct {
	id           [16]byte
	sourceSHA256 [sha256.Size]byte
	profile      string
	wrappedKey   []byte
}

func (c v3MigrationCandidate) replicaPath() string { return filepath.Join(c.profile, "replica.sqlite") }

// prepareV3Migration uses the authenticated in-memory v2 snapshot. The caller
// owns the returned temporary profile and its cleanup.
func (a *App) prepareV3Migration(ctx context.Context) (_ v3MigrationCandidate, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, err := a.replicaKeySessionLocked()
	if err != nil {
		return v3MigrationCandidate{}, err
	}
	source := a.v2Session.digest
	accounts := slices.Clone(a.vault.Accounts)
	defer clear(accounts)
	slices.SortFunc(accounts, func(a, b Account) int { return strings.Compare(a.ID, b.ID) })
	profile, err := os.MkdirTemp("", "passwordsaver-v3-")
	if err != nil {
		return v3MigrationCandidate{}, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(profile))
		}
	}()
	if err := secureStorageDirectory(profile); err != nil {
		return v3MigrationCandidate{}, err
	}
	var key [replicastore.KeySize]byte
	rand.Read(key[:])
	defer clear(key[:])
	candidate := v3MigrationCandidate{profile: profile, sourceSHA256: source}
	store, err := replicastore.Create(ctx, candidate.replicaPath(), key)
	if err != nil {
		return v3MigrationCandidate{}, err
	}
	candidate.id = store.Identity()
	if err := errors.Join(seedV3Migration(ctx, store, accounts), store.Close()); err != nil {
		return v3MigrationCandidate{}, err
	}
	candidate.wrappedKey, err = session.WrapReplicaKey(candidate.id, key)
	if err != nil {
		return v3MigrationCandidate{}, err
	}
	reopened, err := readV3MigrationRecords(ctx, session, candidate)
	defer clear(reopened)
	if err != nil {
		return v3MigrationCandidate{}, err
	}
	if !slices.Equal(accounts, reopened) {
		return v3MigrationCandidate{}, ErrVaultMigrationMismatch
	}
	if err := errors.Join(ctx.Err(), a.checkV3MigrationSourceLocked(source)); err != nil {
		return v3MigrationCandidate{}, err
	}
	return candidate, nil
}

func seedV3Migration(ctx context.Context, store *replicastore.Store, accounts []Account) error {
	id := store.Identity()
	author := hex.EncodeToString(id[:])
	for i, account := range accounts {
		if strings.TrimSpace(account.ID) == "" || (i > 0 && accounts[i-1].ID == account.ID) {
			return errV3MigrationRecordID
		}
		data, err := json.Marshal(account)
		if err != nil {
			return err
		}
		op := syncmerge.Operation{ID: fmt.Sprintf("%s:%d", author, i), AuthorID: author, RecordID: account.ID, Action: syncmerge.Put, Data: data}
		result, err := store.Apply(ctx, op, replicastore.Incoming)
		clear(data)
		if err != nil || result.Status != syncmerge.Applied {
			return errors.Join(ErrVaultMigrationMismatch, err, result.Err)
		}
	}
	return nil
}

func (a *App) exportV3Migration(ctx context.Context, candidate v3MigrationCandidate, password string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	session, err := a.replicaKeySessionLocked()
	if err != nil {
		return "", err
	}
	accounts, err := readV3MigrationRecords(ctx, session, candidate)
	if err != nil {
		return "", err
	}
	vault := &Vault{Accounts: accounts, TwoFAEnabled: a.vault.TwoFAEnabled, TwoFASecret: a.vault.TwoFASecret}
	defer wipeVault(vault)
	container, err := verifiedV3V2Export(a.v2Session.engine, session, password, vault)
	if err != nil {
		return "", err
	}
	path := filepath.Join(candidate.profile, "vault-export.v2.enc")
	if err := writeFileAtomicNoReplaceChecked(path, container, func() error {
		return errors.Join(ctx.Err(), a.checkV3MigrationSourceLocked(candidate.sourceSHA256))
	}); err != nil {
		return "", err
	}
	return path, nil
}

// exportV3DisconnectedCopy writes a verified v2 container from the local snapshot.
func exportV3DisconnectedCopy(ctx context.Context, dir string, engine *cryptov2.Engine, password, code string, confirmed replicastore.ExchangeContext) (string, error) {
	path := filepath.Join(dir, "vault-disconnected.v2.enc")
	err := withV3Copy(ctx, dir, engine, password, code, func(p *v3OpenedCopy) error {
		if p.replica == nil {
			return ErrVaultActivationDenied
		}
		view, err := p.replica.ReadExchange(ctx, confirmed)
		if err != nil {
			return err
		}
		if view.State == nil || !view.State.Disconnected {
			return ErrVaultActivationDenied
		}
		accounts, err := v3AccountsFromRecords(view.Snapshot)
		if err != nil {
			return err
		}
		vault := &Vault{Accounts: accounts, TwoFAEnabled: p.vault.TwoFAEnabled, TwoFASecret: p.vault.TwoFASecret}
		defer wipeVault(vault)
		container, err := verifiedV3V2Export(engine, p.session, password, vault)
		if err != nil {
			return err
		}
		return writeFileAtomicNoReplaceChecked(path, container, ctx.Err)
	})
	if err != nil {
		return "", err
	}
	return path, nil
}
func verifiedV3V2Export(engine *cryptov2.Engine, session *cryptov2.Session, password string, vault *Vault) ([]byte, error) {
	plain, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(plain)
	container, err := session.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	verified, reopened, err := engine.Unlock(password, container)
	verified.Close()
	defer wipeBytes(reopened)
	if err != nil || !bytes.Equal(plain, reopened) {
		return nil, errors.Join(ErrVaultMigrationMismatch, err)
	}
	return container, nil
}

func readV3MigrationRecords(ctx context.Context, session *cryptov2.Session, candidate v3MigrationCandidate) ([]Account, error) {
	key, err := session.OpenReplicaKey(candidate.id, candidate.wrappedKey)
	defer clear(key[:])
	if err != nil {
		return nil, err
	}
	store, err := replicastore.Open(ctx, candidate.replicaPath(), key)
	if err != nil {
		return nil, err
	}
	if store.Identity() != candidate.id {
		return nil, errors.Join(replicastore.ErrAuthentication, store.Close())
	}
	view, err := store.Read(ctx)
	if err := errors.Join(err, store.Close()); err != nil {
		return nil, err
	}
	return v3AccountsFromRecords(view.Records)
}

func v3AccountsFromRecords(records []syncmerge.Record) ([]Account, error) {
	accounts := make([]Account, 0, len(records))
	for _, record := range records {
		if len(record.Versions) != 1 {
			return nil, errV3MigrationConflict
		}
		version := record.Versions[0]
		if version.Action == syncmerge.Delete {
			continue
		}
		var account Account
		if json.Unmarshal(version.Data, &account) != nil || account.ID != record.ID {
			return nil, ErrVaultMigrationMismatch
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// Caller holds a.mu.
func (a *App) checkV3MigrationSourceLocked(digest [sha256.Size]byte) error {
	if _, err := a.replicaKeySessionLocked(); err != nil {
		return err
	}
	session := a.v2Session
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	data, err := readV2File(session.path)
	if err != nil || session.digest != digest || sha256.Sum256(data) != digest {
		return ErrVaultV2SourceChanged
	}
	return nil
}
