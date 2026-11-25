package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/syncmerge"
)

const (
	checkpointVersion = 1
	maxCheckpointOps  = 4096
	maxCheckpointSize = 8 << 20
)

type checkpointHead struct {
	_    struct{} `cbor:",toarray"`
	Seq  uint64
	Hash [32]byte
}

type checkpointOperation struct {
	_                      struct{} `cbor:",toarray"`
	ID, AuthorID, RecordID string
	Parents                []string
	Action                 syncmerge.Action
	Data                   []byte
}

type checkpoint struct {
	_           struct{} `cbor:",toarray"`
	Version     uint64
	SpaceID     [16]byte
	SourceEpoch uint64
	Heads       map[[16]byte]checkpointHead
	History     []checkpointOperation
}

var checkpointDecMode = func() cbor.DecMode {
	options := decMode.DecOptions()
	options.MaxArrayElements = maxCheckpointOps
	options.MaxMapPairs = maxCheckpointOps
	options.DupMapKey = cbor.DupMapKeyEnforcedAPF
	mode, err := options.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// MarshalCheckpoint encodes accepted history and the current epoch's writer heads.
func (r *Receiver) MarshalCheckpoint() ([]byte, error) {
	if r.spaceID == [16]byte{} || r.epoch == 0 || len(r.accepted) > maxCheckpointOps {
		return nil, errors.New("invalid checkpoint source or too many accepted operations")
	}
	snapshot := checkpoint{Version: checkpointVersion, SpaceID: r.spaceID, SourceEpoch: r.epoch,
		Heads: make(map[[16]byte]checkpointHead), History: make([]checkpointOperation, 0, len(r.accepted))}
	for writer, chain := range r.chains {
		if chain.seq != 0 {
			snapshot.Heads[writer] = checkpointHead{Seq: chain.seq, Hash: chain.hash}
		}
	}
	totalData := 0
	for _, op := range r.replica.History() {
		totalData += len(op.Data)
		if totalData > maxCheckpointSize {
			return nil, errors.New("checkpoint exceeds size limit")
		}
		if op.Data == nil {
			op.Data = []byte{}
		}
		if op.Parents == nil {
			op.Parents = []string{}
		}
		snapshot.History = append(snapshot.History, checkpointOperation{ID: op.ID, AuthorID: op.AuthorID,
			RecordID: op.RecordID, Parents: op.Parents, Action: op.Action, Data: op.Data})
	}
	wire, err := encMode.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxCheckpointSize {
		return nil, errors.New("checkpoint exceeds size limit")
	}
	return wire, nil
}

// RestoreCheckpoint replays an authenticated checkpoint into a fresh receiver.
// The caller supplies the expected space and the new epoch, one above the source epoch.
func RestoreCheckpoint(wire []byte, spaceID [16]byte, epoch uint64, epochKey []byte, signers map[[16]byte]ed25519.PublicKey) (*Receiver, error) {
	if len(wire) > maxCheckpointSize {
		return nil, errors.New("checkpoint exceeds size limit")
	}
	var snapshot checkpoint
	if err := checkpointDecMode.Unmarshal(wire, &snapshot); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}
	canonical, err := encMode.Marshal(snapshot)
	if err != nil || !bytes.Equal(wire, canonical) {
		return nil, errors.New("non-canonical checkpoint")
	}
	if snapshot.Version != checkpointVersion || spaceID == [16]byte{} || snapshot.SpaceID != spaceID ||
		epoch < 2 || snapshot.SourceEpoch != epoch-1 || snapshot.Heads == nil || snapshot.History == nil {
		return nil, errors.New("invalid checkpoint space, epoch or shape")
	}
	pending := make(map[string]checkpointOperation, len(snapshot.History))
	authorOps := make(map[string]uint64)
	for _, op := range snapshot.History {
		if _, duplicate := pending[op.ID]; duplicate {
			return nil, errors.New("duplicate checkpoint operation")
		}
		if !validCheckpointID(op.AuthorID) || !validCheckpointID(op.RecordID) ||
			op.Parents == nil || len(op.Parents) > maxParents || op.Data == nil || len(op.Data) > maxPlaintextSize {
			return nil, errors.New("invalid checkpoint operation")
		}
		pending[op.ID] = op
		authorOps[op.AuthorID]++
	}
	for writer, head := range snapshot.Heads {
		op, ok := pending[hex.EncodeToString(head.Hash[:])]
		if !ok || head.Seq == 0 || head.Seq > authorOps[op.AuthorID] || op.AuthorID != hex.EncodeToString(writer[:]) {
			return nil, errors.New("invalid checkpoint writer head")
		}
	}
	receiver := NewReceiver(spaceID, epoch, epochKey, signers)
	// History is ordered by ID on export. Walk parents first to replay in causal order.
	var apply func(string) error
	apply = func(id string) error {
		var hash [32]byte
		if len(id) != hex.EncodedLen(len(hash)) {
			return errors.New("invalid checkpoint operation hash length")
		}
		if _, err := hex.Decode(hash[:], []byte(id)); err != nil || hex.EncodeToString(hash[:]) != id {
			return errors.New("invalid checkpoint operation hash")
		}
		if _, applied := receiver.accepted[hash]; applied {
			return nil
		}
		op, ok := pending[id]
		if !ok {
			return errors.New("unknown or cyclic checkpoint parent")
		}
		delete(pending, id)
		for _, parent := range op.Parents {
			if err := apply(parent); err != nil {
				return err
			}
		}
		result := receiver.replica.Apply(syncmerge.Operation{ID: op.ID, AuthorID: op.AuthorID,
			RecordID: op.RecordID, Parents: op.Parents, Action: op.Action, Data: op.Data})
		if result.Status != syncmerge.Applied {
			return fmt.Errorf("apply checkpoint operation: %w", result.Err)
		}
		receiver.accepted[hash] = struct{}{}
		return nil
	}
	for _, op := range snapshot.History {
		if err := apply(op.ID); err != nil {
			return nil, err
		}
	}
	return receiver, nil
}

func validCheckpointID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && [16]byte(decoded) != [16]byte{} && hex.EncodeToString(decoded) == id
}
