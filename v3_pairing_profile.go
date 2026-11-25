package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	cryptov2 "password-saver/crypto/v2"
)

const (
	v3PairingFile    = "v3_pairing.state.enc"
	v3PairingFormat  = "passwordsaver-v3-pairing-profile"
	v3PairingVersion = 1
)

var (
	errV3PairingState   = errors.New("invalid v3 pairing profile state")
	errV3PairingChanged = errors.New("v3 pairing profile revision changed")
	v3PairingFileMu     sync.Mutex
)

type v3PairingPrivateKeys struct {
	SigningSeed     []byte
	ExchangePrivate []byte
}

type v3PairingPending struct {
	Request []byte
	Keys    v3PairingPrivateKeys
}

type v3PairingAccepted struct {
	Membership []byte
	EpochKey   []byte
	Checkpoint []byte
	AnswerHash [sha256.Size]byte
	Keys       v3PairingPrivateKeys
}

type v3PairingState struct {
	RequestID    [16]byte
	Pending      *v3PairingPending  `json:",omitempty"`
	IssuedAnswer []byte             `json:",omitempty"`
	Accepted     *v3PairingAccepted `json:",omitempty"`
}

type v3PairingRecord struct {
	Format  string
	Version uint8
	State   v3PairingState
}

func (s v3PairingState) valid() bool {
	if s.RequestID == [16]byte{} {
		return false
	}
	switch {
	case s.Pending != nil:
		return s.Accepted == nil && s.IssuedAnswer == nil && len(s.Pending.Request) > 0 && s.Pending.Keys.valid()
	case s.Accepted != nil:
		a := s.Accepted
		return s.IssuedAnswer == nil && len(a.Membership) > 0 && len(a.EpochKey) == 32 && a.Checkpoint != nil &&
			a.AnswerHash != [sha256.Size]byte{} && a.Keys.valid()
	default:
		return len(s.IssuedAnswer) > 0
	}
}

func (k v3PairingPrivateKeys) valid() bool {
	return len(k.SigningSeed) == ed25519.SeedSize && len(k.ExchangePrivate) == 32
}

func (s v3PairingState) wipe() {
	if s.Pending != nil {
		clear(s.Pending.Keys.SigningSeed)
		clear(s.Pending.Keys.ExchangePrivate)
	}
	if s.Accepted != nil {
		clear(s.Accepted.Keys.SigningSeed)
		clear(s.Accepted.Keys.ExchangePrivate)
		clear(s.Accepted.EpochKey)
		clear(s.Accepted.Checkpoint)
	}
}

type v3PairingProfile struct {
	path    string
	dirInfo os.FileInfo
	engine  *cryptov2.Engine
}

// openV3PairingProfile takes an existing, caller-owned temporary profile copy.
func openV3PairingProfile(copyDir string, engine *cryptov2.Engine) (v3PairingProfile, error) {
	if !filepath.IsAbs(copyDir) || engine == nil {
		return v3PairingProfile{}, ErrVaultStorageUnsafe
	}
	info, err := passwordChangeDirectoryInfo(copyDir)
	if err != nil {
		return v3PairingProfile{}, err
	}
	return v3PairingProfile{path: filepath.Join(copyDir, v3PairingFile), dirInfo: info, engine: engine}, nil
}

func (p v3PairingProfile) checkDirectory() error {
	info, err := passwordChangeDirectoryInfo(filepath.Dir(p.path))
	if err != nil || !os.SameFile(p.dirInfo, info) {
		return ErrVaultStorageUnsafe
	}
	return nil
}

func (p v3PairingProfile) read(password string) (v3PairingState, [sha256.Size]byte, error) {
	if err := p.checkDirectory(); err != nil {
		return v3PairingState{}, [sha256.Size]byte{}, err
	}
	data, err := readV2File(p.path)
	if err != nil {
		return v3PairingState{}, [sha256.Size]byte{}, err
	}
	state, err := p.decrypt(password, data)
	if err != nil {
		return v3PairingState{}, [sha256.Size]byte{}, err
	}
	return state, sha256.Sum256(data), nil
}

func (p v3PairingProfile) decrypt(password string, data []byte) (v3PairingState, error) {
	plain, err := p.engine.Decrypt(password, data)
	if err != nil {
		return v3PairingState{}, err
	}
	defer clear(plain)
	var record v3PairingRecord
	if json.Unmarshal(plain, &record) != nil || record.Format != v3PairingFormat ||
		record.Version != v3PairingVersion || !record.State.valid() {
		record.State.wipe()
		return v3PairingState{}, errV3PairingState
	}
	return record.State, nil
}

// save uses the digest returned by read or save as the expected revision.
// A zero revision is reserved for creating a new file.
func (p v3PairingProfile) save(password string, expected [sha256.Size]byte, state v3PairingState, beforeReplace func() error) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if !state.valid() {
		return zero, errV3PairingState
	}
	v3PairingFileMu.Lock()
	defer v3PairingFileMu.Unlock()
	if err := p.checkDirectory(); err != nil {
		return zero, err
	}
	previous, err := readOptionalV2Revision(p.path)
	if err != nil {
		return zero, err
	}
	if revisionOf(previous).digest != expected {
		return zero, errV3PairingChanged
	}
	if previous != nil {
		prior, err := p.decrypt(password, previous)
		if err != nil {
			return zero, err
		}
		prior.wipe()
	}
	plain, err := json.Marshal(v3PairingRecord{Format: v3PairingFormat, Version: v3PairingVersion, State: state})
	if err != nil {
		return zero, err
	}
	sealed, err := p.engine.Encrypt(password, plain)
	clear(plain)
	if err != nil {
		return zero, err
	}
	check := func() error {
		if beforeReplace != nil {
			if err := beforeReplace(); err != nil {
				return err
			}
		}
		if err := p.checkDirectory(); err != nil {
			return err
		}
		if previous != nil && ensureV2FileUnchanged(p.path, previous) != nil {
			return errV3PairingChanged
		}
		return nil
	}
	write := writeFileAtomicChecked
	if previous == nil {
		write = writeFileAtomicNoReplaceChecked
	}
	if err := write(p.path, sealed, check); err != nil {
		if errors.Is(err, ErrVaultV2TargetExists) {
			return zero, errV3PairingChanged
		}
		return zero, err
	}
	return sha256.Sum256(sealed), nil
}
