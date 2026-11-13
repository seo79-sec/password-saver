package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	cryptov2 "password-saver/crypto/v2"
)

// v2VaultSession joins an opaque crypto/v2 DEK session to a specific on-disk
// container revision. It never stores a master password or exposes the DEK.
type v2VaultSession struct {
	mu     sync.Mutex
	crypto *cryptov2.Session
	engine *cryptov2.Engine
	path   string
	digest [sha256.Size]byte
	closed bool
}

func openActiveV2VaultSession(path string, engine *cryptov2.Engine, masterPassword string) (*v2VaultSession, *Vault, error) {
	if engine == nil {
		return nil, nil, errors.New("v2 crypto engine is unavailable")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	dir := filepath.Dir(absPath)
	paths := vaultPaths(dir)
	if filepath.Clean(absPath) != filepath.Clean(paths.v2) {
		return nil, nil, errors.New("v2 session path must be the configured v2 vault path")
	}

	vaultActivationMu.Lock()
	v2VaultFileMu.Lock()
	selection, err := resolveVaultSelectionLocked(dir)
	if err != nil || !selection.ActiveV2 {
		v2VaultFileMu.Unlock()
		vaultActivationMu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrVaultV2NotActive
	}
	serialized, err := readV2File(absPath)
	if err != nil {
		v2VaultFileMu.Unlock()
		vaultActivationMu.Unlock()
		return nil, nil, err
	}
	cryptoSession, plaintext, err := engine.Unlock(masterPassword, serialized)
	v2VaultFileMu.Unlock()
	vaultActivationMu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	defer wipeBytes(plaintext)
	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		cryptoSession.Close()
		return nil, nil, ErrVaultV2Corrupt
	}
	if err := ensureV2FileUnchanged(absPath, serialized); err != nil {
		cryptoSession.Close()
		wipeVault(&vault)
		return nil, nil, err
	}
	digest := sha256.Sum256(serialized)
	return &v2VaultSession{crypto: cryptoSession, engine: engine, path: absPath, digest: digest}, &vault, nil
}

func (s *v2VaultSession) save(vault *Vault) error {
	if s == nil {
		return ErrVaultSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.crypto == nil || vault == nil {
		return ErrVaultSessionClosed
	}
	dir := filepath.Dir(s.path)
	vaultActivationMu.Lock()
	defer vaultActivationMu.Unlock()
	selection, err := resolveVaultSelectionLocked(dir)
	if err != nil || !selection.ActiveV2 {
		s.closeLocked()
		if err != nil {
			return err
		}
		return ErrVaultV2NotActive
	}
	v2VaultFileMu.Lock()
	defer v2VaultFileMu.Unlock()
	current, err := readV2File(s.path)
	if err != nil {
		s.closeLocked()
		return fmt.Errorf("%w: %v", ErrVaultSessionChanged, err)
	}
	if sha256.Sum256(current) != s.digest {
		s.closeLocked()
		return ErrVaultSessionChanged
	}
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return err
	}
	container, err := s.crypto.Encrypt(plaintext)
	wipeBytes(plaintext)
	if err != nil {
		return err
	}
	if err := ensureV2FileUnchanged(s.path, current); err != nil {
		s.closeLocked()
		return ErrVaultSessionChanged
	}
	if err := writeFileAtomic(s.path+".bak", current); err != nil {
		return fmt.Errorf("encrypted v2 backup was not confirmed; active file was not replaced: %w", err)
	}
	backup, err := readV2File(s.path + ".bak")
	if err != nil || !bytes.Equal(backup, current) {
		return errors.New("encrypted v2 backup verification failed; active file was not replaced")
	}
	if err := ensureV2FileUnchanged(s.path, current); err != nil {
		s.closeLocked()
		return ErrVaultSessionChanged
	}
	if err := writeFileAtomic(s.path, container); err != nil {
		if errors.Is(err, errVaultCommitUncertain) {
			s.closeLocked()
			return fmt.Errorf("%w: %v", errVaultCommitUncertain, err)
		}
		return err
	}
	s.digest = sha256.Sum256(container)
	return nil
}

func (s *v2VaultSession) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *v2VaultSession) closeLocked() {
	if s.closed {
		return
	}
	if s.crypto != nil {
		s.crypto.Close()
		s.crypto = nil
	}
	s.engine = nil
	s.digest = [sha256.Size]byte{}
	s.closed = true
}

func (s *v2VaultSession) isClosed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
