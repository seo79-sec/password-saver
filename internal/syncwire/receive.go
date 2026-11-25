package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/syncmerge"
)

const maxParents = 32

// ErrChangeFork identifies different envelopes signed for one writer's sequence number.
var ErrChangeFork = errors.New("change writer sequence has conflicting envelopes")

type changePayload struct {
	_        struct{} `cbor:",toarray"`
	RecordID [16]byte
	Parents  [][32]byte
	Action   uint64
	Data     []byte
}

var payloadDecMode = func() cbor.DecMode {
	options := decMode.DecOptions()
	options.MaxArrayElements = maxParents
	mode, err := options.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

type writerChain struct {
	seq  uint64
	hash [32]byte
	seen map[uint64][32]byte // hashes of accepted envelopes and envelopes waiting for dependencies
}

// Receiver owns an in-memory replica and writer chains for one space and epoch.
// Callers must serialize access to a Receiver.
type Receiver struct {
	spaceID  [16]byte
	epoch    uint64
	epochKey []byte
	signers  map[[16]byte]ed25519.PublicKey
	chains   map[[16]byte]*writerChain
	accepted map[[32]byte]struct{}
	replica  *syncmerge.Replica
}

// NewReceiver starts an empty replica with a copy of the supplied keys.
func NewReceiver(spaceID [16]byte, epoch uint64, epochKey []byte, signers map[[16]byte]ed25519.PublicKey) *Receiver {
	trusted := make(map[[16]byte]ed25519.PublicKey, len(signers))
	for deviceID, key := range signers {
		trusted[deviceID] = bytes.Clone(key)
	}
	return &Receiver{
		spaceID: spaceID, epoch: epoch, epochKey: bytes.Clone(epochKey), signers: trusted,
		chains: make(map[[16]byte]*writerChain), accepted: make(map[[32]byte]struct{}),
		replica: syncmerge.New(0),
	}
}

// Snapshot returns a deep copy of the current record versions.
func (r *Receiver) Snapshot() []syncmerge.Record { return r.replica.Snapshot() }

// Receive verifies a wire envelope and applies it when its dependencies are present.
// On Waiting, the caller retains the wire bytes and retries after receiving dependencies.
func (r *Receiver) Receive(wire []byte) syncmerge.Outcome {
	envelope, err := Parse(wire)
	if err != nil {
		return syncmerge.Outcome{Status: syncmerge.Rejected, Err: err}
	}
	plaintext, err := Open(envelope, r.spaceID, r.epoch, r.epochKey, r.signers)
	if err != nil {
		return syncmerge.Outcome{Status: syncmerge.Rejected, Err: err}
	}
	digest := sha256.Sum256(wire)
	op, parents, err := decodeOperation(plaintext, envelope.Header.DeviceID, digest)
	clear(plaintext)
	if err != nil {
		return syncmerge.Outcome{Status: syncmerge.Rejected, Err: err}
	}
	header := envelope.Header
	chain := r.chains[header.DeviceID]
	if chain == nil {
		chain = &writerChain{seen: make(map[uint64][32]byte)}
		r.chains[header.DeviceID] = chain
	}
	if seen, ok := chain.seen[header.Seq]; ok && seen != digest {
		return syncmerge.Outcome{ID: op.ID, Status: syncmerge.Rejected, Err: ErrChangeFork}
	}
	if header.Seq <= chain.seq {
		return syncmerge.Outcome{ID: op.ID, Status: syncmerge.Applied}
	}
	ready := header.Seq == chain.seq+1
	if ready && header.PrevHash != chain.hash {
		return syncmerge.Outcome{ID: op.ID, Status: syncmerge.Rejected, Err: errors.New("change previous hash does not match writer chain")}
	}
	for _, parent := range parents {
		if _, ok := r.accepted[parent]; !ok {
			ready = false
			break
		}
	}
	if !ready {
		chain.seen[header.Seq] = digest
		return syncmerge.Outcome{ID: op.ID, Status: syncmerge.Waiting}
	}
	result := r.replica.Apply(op).Outcome
	if result.Status == syncmerge.Applied {
		chain.seq, chain.hash = header.Seq, digest
		chain.seen[header.Seq] = digest
		r.accepted[digest] = struct{}{}
	}
	return result
}

func decodeOperation(plaintext []byte, author [16]byte, digest [32]byte) (syncmerge.Operation, [][32]byte, error) {
	var payload changePayload
	if err := payloadDecMode.Unmarshal(plaintext, &payload); err != nil {
		return syncmerge.Operation{}, nil, fmt.Errorf("decode change payload: %w", err)
	}
	canonical, err := encMode.Marshal(payload)
	if err != nil {
		return syncmerge.Operation{}, nil, err
	}
	if !bytes.Equal(plaintext, canonical) || payload.RecordID == [16]byte{} || payload.Parents == nil || payload.Data == nil {
		return syncmerge.Operation{}, nil, errors.New("invalid canonical change payload")
	}
	op := syncmerge.Operation{
		ID: hex.EncodeToString(digest[:]), AuthorID: hex.EncodeToString(author[:]),
		RecordID: hex.EncodeToString(payload.RecordID[:]), Data: payload.Data,
	}
	switch payload.Action {
	case 1:
		op.Action = syncmerge.Put
	case 2:
		if len(payload.Data) != 0 {
			return syncmerge.Operation{}, nil, errors.New("delete change payload contains data")
		}
		op.Action = syncmerge.Delete
	default:
		return syncmerge.Operation{}, nil, errors.New("unknown change action")
	}
	seen := make(map[[32]byte]struct{}, len(payload.Parents))
	for _, parent := range payload.Parents {
		if _, ok := seen[parent]; ok || parent == digest {
			return syncmerge.Operation{}, nil, syncmerge.ErrInvalidParent
		}
		seen[parent] = struct{}{}
		op.Parents = append(op.Parents, hex.EncodeToString(parent[:]))
	}
	return op, payload.Parents, nil
}
