package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncwire"
)

var (
	// ErrReconnectRequiresDisconnect indicates that the replica must be disconnected first.
	ErrReconnectRequiresDisconnect = errors.New("reconnect inspection requires a disconnected replica")
	// ErrReconnectNotReady indicates a mismatch or outstanding changes.
	ErrReconnectNotReady = errors.New("reconnect requires a matching checkpoint and no outstanding changes")
	// ErrReconnectCheckpoint indicates an invalid checkpoint or mismatched binding.
	ErrReconnectCheckpoint = errors.New("invalid reconnect checkpoint")
)

// ReconnectCheckpoint carries checkpoint bytes and metadata authenticated by the caller.
type ReconnectCheckpoint struct {
	SpaceID        [16]byte
	Epoch          uint64
	MembershipHash [32]byte
	CheckpointHash [32]byte
	Wire           []byte
}

// ReconnectComparison describes whether the local and supplied checkpoints agree.
type ReconnectComparison uint8

const (
	ReconnectMatch ReconnectComparison = iota + 1
	ReconnectMismatch
	ReconnectDeferred // Incoming envelopes still have unresolved dependencies.
)

// ReconnectInspection describes one generation without acknowledging any envelopes.
type ReconnectInspection struct {
	Generation int64
	Unsent     int
	Pending    int
	Comparison ReconnectComparison
}

type reconnectReader interface {
	ReadExchange(context.Context, replicastore.ExchangeContext) (replicastore.ExchangeView, error)
}

// InspectReconnect compares the supplied checkpoint against a disconnected replica.
func InspectReconnect(ctx context.Context, store reconnectReader, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint) (ReconnectInspection, error) {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return ReconnectInspection{}, err
	}
	inspection, _, err := inspectReconnectView(view, confirmed, remote)
	return inspection, err
}

func inspectReconnectView(view replicastore.ExchangeView, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint) (ReconnectInspection, *syncwire.Receiver, error) {
	state := view.State
	receiver, err := restoreReconnectCheckpoint(state, confirmed, remote)
	if err != nil {
		return ReconnectInspection{}, nil, err
	}

	result := ReconnectInspection{Generation: view.Generation, Pending: len(view.Pending), Comparison: ReconnectDeferred}
	for _, entry := range state.Journal {
		if entry.Sequence > state.SentSequence {
			result.Unsent++
		}
	}
	if result.Pending != 0 {
		return result, receiver, nil
	}
	local, err := replayRemovalCheckpoint(reconnectReplayContext(confirmed, state), state)
	if err != nil {
		return ReconnectInspection{}, nil, err
	}
	defer clear(local)
	result.Comparison = ReconnectMismatch
	if bytes.Equal(local, remote.Wire) {
		result.Comparison = ReconnectMatch
	}
	return result, receiver, nil
}

func restoreReconnectCheckpoint(state *replicastore.ExchangeState, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint) (*syncwire.Receiver, error) {
	if state == nil || !state.Disconnected {
		return nil, ErrReconnectRequiresDisconnect
	}
	binding := confirmed.Binding
	if state.Binding != binding || remote.SpaceID != binding.SpaceID || remote.Epoch != binding.Epoch ||
		remote.MembershipHash != binding.MembershipHash || remote.CheckpointHash != sha256.Sum256(remote.Wire) ||
		binding.Epoch == math.MaxUint64 {
		return nil, ErrReconnectCheckpoint
	}
	confirmed = reconnectReplayContext(confirmed, state)
	// RestoreCheckpoint expects the successor of the checkpoint's source epoch.
	receiver, err := syncwire.RestoreCheckpoint(remote.Wire, binding.SpaceID, binding.Epoch+1, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReconnectCheckpoint, err)
	}

	return receiver, nil
}

func reconnectReplayContext(confirmed replicastore.ExchangeContext, state *replicastore.ExchangeState) replicastore.ExchangeContext {
	if active := state.ActivatedRemoval; active != nil {
		confirmed.Signers = map[[16]byte]ed25519.PublicKey{confirmed.Binding.DeviceID: active.SigningPub[:]}
	}
	return confirmed
}

type reconnectConfirmer interface {
	reconnectReader
	ConfirmReconnect(context.Context, replicastore.ExchangeBinding, replicastore.ReconnectConfirmation) error
}

// ConfirmReconnect repeats the inspection and saves the owner's decision without enabling exchange.
func ConfirmReconnect(ctx context.Context, store reconnectConfirmer, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, owner replicastore.ReconnectConfirmation) error {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return err
	}
	inspection, _, err := inspectReconnectView(view, confirmed, remote)
	if err != nil {
		return err
	}
	if owner.CheckpointHash != remote.CheckpointHash {
		return replicastore.ErrReconnectConfirmation
	}
	if inspection.Comparison != ReconnectMatch || inspection.Unsent != 0 || inspection.Pending != 0 {
		return ErrReconnectNotReady
	}
	if owner.Generation != inspection.Generation {
		saved := view.State.ReconnectConfirmation
		if saved == nil || *saved != owner || owner.Generation != inspection.Generation-1 {
			return replicastore.ErrGeneration
		}
	}
	return store.ConfirmReconnect(ctx, confirmed.Binding, owner)
}
