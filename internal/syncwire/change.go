package syncwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"password-saver/internal/syncmerge"
)

const (
	changePut    = 1
	changeDelete = 2
)

// LocalOperation contains the record fields to put in a change envelope.
type LocalOperation struct {
	RecordID [16]byte
	Parents  [][32]byte
	Action   syncmerge.Action
	Data     []byte
}

// SealOperation uses the supplied header, including its sequence and previous
// hash, and returns the signed wire bytes and their SHA-256 digest.
func SealOperation(header Header, operation LocalOperation, epochKey []byte, signer ed25519.PrivateKey) ([]byte, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	payload := changePayload{RecordID: operation.RecordID, Parents: operation.Parents, Data: operation.Data}
	switch operation.Action {
	case syncmerge.Put:
		payload.Action = changePut
	case syncmerge.Delete:
		payload.Action = changeDelete
	default:
		return nil, zero, errors.New("unknown change action")
	}
	if payload.Parents == nil {
		payload.Parents = [][32]byte{}
	}
	if payload.Data == nil {
		payload.Data = []byte{}
	}
	if _, err := payload.validate(); err != nil {
		return nil, zero, err
	}
	if len(payload.Data) > maxPlaintextSize {
		return nil, zero, errors.New("change payload length is out of range")
	}
	plaintext, err := encMode.Marshal(payload)
	if err != nil {
		return nil, zero, err
	}
	defer clear(plaintext)
	envelope, err := Seal(header, plaintext, epochKey, signer)
	if err != nil {
		return nil, zero, err
	}
	wire, err := Marshal(envelope)
	if err != nil {
		return nil, zero, err
	}
	return wire, sha256.Sum256(wire), nil
}

// validate applies the same payload rules on the send and receive paths.
func (p changePayload) validate() (syncmerge.Action, error) {
	if p.RecordID == [16]byte{} || p.Parents == nil || p.Data == nil {
		return "", errors.New("invalid canonical change payload")
	}
	if len(p.Parents) > maxParents {
		return "", errors.New("too many change parents")
	}
	var action syncmerge.Action
	switch p.Action {
	case changePut:
		action = syncmerge.Put
	case changeDelete:
		if len(p.Data) != 0 {
			return "", errors.New("delete change payload contains data")
		}
		action = syncmerge.Delete
	default:
		return "", errors.New("unknown change action")
	}
	seen := make(map[[32]byte]struct{}, len(p.Parents))
	for _, parent := range p.Parents {
		if _, ok := seen[parent]; ok {
			return "", syncmerge.ErrInvalidParent
		}
		seen[parent] = struct{}{}
	}
	return action, nil
}
