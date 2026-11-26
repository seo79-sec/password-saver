package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncwire"
)

// ErrCommandConflict indicates that a command ID was already used for other content.
var ErrCommandConflict = errors.New("local command ID already used for different content")

// ExchangeStore provides snapshot reads and generation-checked journal commits.
type ExchangeStore interface {
	ReadExchange(context.Context, replicastore.ExchangeContext) (replicastore.ExchangeView, error)
	CommitExchange(context.Context, replicastore.ExchangeContext, int64, []replicastore.ExchangeEnvelope, uint64, uint64) error
}

// QueueLocal commits one local operation and returns the exact bytes recorded in
// the journal. Reusing the command ID with the same content reuses those bytes.
func QueueLocal(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, signer ed25519.PrivateKey, commandID string, operation syncwire.LocalOperation) ([]byte, error) {
	if commandID == "" {
		return nil, errors.New("local command ID is required")
	}
	// Parent order has no meaning in the merge model. Normalize it and encode
	// empty fields consistently for both the command hash and the envelope.
	operation.Parents = append([][32]byte{}, operation.Parents...)
	slices.SortFunc(operation.Parents, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	if operation.Data == nil {
		operation.Data = []byte{}
	}
	encoded, err := cbor.Marshal([]any{"PasswordSaver/sync/local-command/v1", operation.RecordID, operation.Parents, operation.Action, operation.Data})
	if err != nil {
		return nil, err
	}
	commandHash := sha256.Sum256(encoded)
	clear(encoded)
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return nil, err
	}
	if view.State == nil {
		return nil, replicastore.ErrExchangeMode
	}
	if wire, err := queuedCommand(view.State.Journal, commandID, commandHash); wire != nil || err != nil {
		return wire, err
	}
	binding := view.State.Binding
	head := view.Heads[binding.DeviceID]
	header := syncwire.Header{Type: 1, Version: 1, SpaceID: binding.SpaceID, Epoch: binding.Epoch,
		DeviceID: binding.DeviceID, Seq: head.Seq + 1, PrevHash: head.Hash}
	wire, _, err := syncwire.SealOperation(header, operation, confirmed.EpochKey, signer)
	if err != nil {
		return nil, err
	}
	entry := replicastore.ExchangeEnvelope{Wire: wire, CommandID: commandID, CommandHash: commandHash, Sequence: header.Seq}
	// The commit replays the journal at this generation and requires the local
	// writer to advance, so a waiting or rejected local change cannot commit.
	err = store.CommitExchange(ctx, confirmed, view.Generation, []replicastore.ExchangeEnvelope{entry}, view.State.SentSequence, view.State.Cursor)
	if err == nil {
		return wire, nil
	}
	if !errors.Is(err, replicastore.ErrCommitUnknown) && !errors.Is(err, replicastore.ErrGeneration) {
		return nil, err
	}
	current, readErr := store.ReadExchange(ctx, confirmed)
	if readErr != nil {
		return nil, errors.Join(err, readErr)
	}
	if current.State != nil {
		if saved, conflict := queuedCommand(current.State.Journal, commandID, commandHash); saved != nil || conflict != nil {
			return saved, conflict
		}
	}
	return nil, err
}

func queuedCommand(journal []replicastore.ExchangeEnvelope, commandID string, commandHash [32]byte) ([]byte, error) {
	for _, entry := range journal {
		if entry.CommandID == commandID {
			if entry.CommandHash != commandHash {
				return nil, ErrCommandConflict
			}
			return entry.Wire, nil
		}
	}
	return nil, nil
}
