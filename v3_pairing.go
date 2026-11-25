package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"time"

	"password-saver/internal/syncpair"
	"password-saver/internal/syncwire"
)

var (
	errV3PairingDestination = errors.New("pairing destination must be an empty profile")
	errV3PairingReplay      = errors.New("pairing profile already contains a different request or result")
	errV3PairingFingerprint = errors.New("pairing fingerprint mismatch")
)

func (p v3PairingProfile) checkPairingDestination() error {
	if err := p.checkDirectory(); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Dir(p.path))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != v3PairingFile {
			return errV3PairingDestination
		}
	}
	return nil
}

func (p v3PairingProfile) beginPairing(password string, controller [32]byte, now time.Time) ([]byte, [32]byte, error) {
	var zero [32]byte
	if err := p.checkPairingDestination(); err != nil {
		return nil, zero, err
	}
	wire, digest, keys, err := syncpair.NewRequest(controller, now)
	if err != nil {
		return nil, zero, err
	}
	request, _, err := syncpair.ParseRequest(wire, now)
	if err != nil {
		return nil, zero, err
	}
	seed, exchange := keys.PrivateBytes()
	state := v3PairingState{RequestID: request.Header.RequestID, Pending: &v3PairingPending{
		Request: wire, Keys: v3PairingPrivateKeys{SigningSeed: seed, ExchangePrivate: exchange}}}
	defer state.wipe()
	if err := p.checkPairingDestination(); err != nil {
		return nil, zero, err
	}
	if _, err := p.save(password, zero, state, nil); err != nil {
		return nil, zero, err
	}
	return wire, digest, nil
}

func (p v3PairingProfile) issuePairingAnswer(password string, keys *syncpair.SpaceKeys, initial, request []byte, confirmed [32]byte, source *syncwire.Receiver, now time.Time) ([]byte, error) {
	if sha256.Sum256(request) != confirmed {
		return nil, errV3PairingFingerprint
	}
	state, _, err := p.read(password)
	defer state.wipe()
	if err == nil {
		if syncpair.IssuedAnswerMatchesRequest(state.IssuedAnswer, confirmed) {
			return state.IssuedAnswer, nil
		}
		return nil, errV3PairingReplay
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if source == nil {
		return nil, errV3PairingState
	}
	parsed, _, err := syncpair.ParseRequest(request, now)
	if err != nil {
		return nil, err
	}
	var payload syncpair.AnswerPayload
	rand.Read(payload.EpochKey[:])
	defer clear(payload.EpochKey[:])
	payload.Checkpoint, err = source.MarshalCheckpoint()
	if err != nil {
		return nil, err
	}
	defer clear(payload.Checkpoint)
	wire, err := keys.IssueAnswer(initial, request, confirmed, payload, now)
	if err != nil {
		return nil, err
	}
	result := v3PairingState{RequestID: parsed.Header.RequestID, IssuedAnswer: wire}
	if _, err := p.save(password, [32]byte{}, result, nil); err != nil {
		return nil, err
	}
	return wire, nil
}

func (p v3PairingProfile) acceptPairingAnswer(password string, wire []byte, controller [32]byte, now time.Time) (*syncwire.Receiver, error) {
	if err := p.checkPairingDestination(); err != nil {
		return nil, err
	}
	state, revision, err := p.read(password)
	if err != nil {
		return nil, err
	}
	defer state.wipe()
	digest := sha256.Sum256(wire)
	if state.Accepted != nil {
		if digest != state.Accepted.AnswerHash {
			return nil, errV3PairingReplay
		}
		return restoreV3Pairing(state.Accepted, controller)
	}
	if state.Pending == nil {
		return nil, errV3PairingDestination
	}
	pending := state.Pending
	keys, err := syncpair.RestoreDeviceKeys(pending.Keys.SigningSeed, pending.Keys.ExchangePrivate)
	if err != nil {
		return nil, err
	}
	membership, payload, err := keys.OpenAnswer(wire, pending.Request, controller, now)
	if err != nil {
		return nil, err
	}
	defer clear(payload.Checkpoint)
	defer clear(payload.EpochKey[:])
	signed, err := membership.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	accepted := &v3PairingAccepted{Membership: signed, Checkpoint: payload.Checkpoint, EpochKey: payload.EpochKey[:],
		AnswerHash: digest, Keys: pending.Keys}
	receiver, err := restoreV3Pairing(accepted, controller)
	if err != nil {
		return nil, err
	}
	if err := p.checkPairingDestination(); err != nil {
		return nil, err
	}
	if _, err := p.save(password, revision, v3PairingState{RequestID: state.RequestID, Accepted: accepted}, nil); err != nil {
		return nil, err
	}
	return receiver, nil
}

func restoreV3Pairing(accepted *v3PairingAccepted, controller [32]byte) (*syncwire.Receiver, error) {
	membership, err := syncpair.VerifySignedMembership(accepted.Membership, controller)
	if err != nil {
		return nil, err
	}
	h := membership.Header
	signers := make(map[[16]byte]ed25519.PublicKey, len(h.Members))
	for _, member := range h.Members {
		signers[member.DeviceID] = ed25519.PublicKey(member.SigningPub[:])
	}
	return syncwire.RestoreCheckpoint(accepted.Checkpoint, h.SpaceID, h.Epoch, accepted.EpochKey, signers)
}
