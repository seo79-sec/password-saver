package syncsession

import (
	"bytes"
	"context"
	"slices"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

// ReconnectReconciliation authorizes catching up to the reviewed point and cursor.
type ReconnectReconciliation struct {
	Generation     int64
	CheckpointHash [32]byte
	Cursor         uint64
}

type reconnectSuffixStore interface {
	reconnectReader
	ApplyReconnectSuffix(context.Context, replicastore.ExchangeContext, int64, uint64, uint64, uint64, [][]byte) error
}

// ReconcileReconnect catches up a disconnected replica using a local log that
// the caller has associated with confirmed.Binding. It acknowledges queued
// local envelopes only if each exact envelope is present by the reviewed cursor.
func ReconcileReconnect(ctx context.Context, store reconnectSuffixStore, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, log *syncrelay.Log, owner ReconnectReconciliation) error {
	if owner.Generation < 1 || owner.CheckpointHash == [32]byte{} || owner.CheckpointHash != remote.CheckpointHash {
		return replicastore.ErrReconnectConfirmation
	}
	if log == nil {
		return ErrReconnectRelayLog
	}
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return err
	}
	inspection, _, err := inspectReconnectView(view, confirmed, remote)
	if err != nil {
		return err
	}
	state := view.State
	if state.Removal != nil {
		return ErrRemovalRelayPaused
	}
	if inspection.Pending != 0 {
		return ErrReconnectNotReady
	}
	// Recognize an exact retry after the catch-up commit response was lost.
	applied := view.Generation-1 == owner.Generation && owner.Cursor == state.Cursor &&
		state.ReconnectConfirmation == nil && inspection.Unsent == 0 && inspection.Comparison == ReconnectMatch
	if view.Generation != owner.Generation && !applied {
		return replicastore.ErrGeneration
	}
	advancesCheckpoint := inspection.Comparison == ReconnectMismatch && owner.Cursor > state.Cursor
	if !applied && (owner.Cursor < state.Cursor || (!advancesCheckpoint && inspection.Unsent == 0)) {
		return ErrReconnectNotReady
	}
	seen := make(map[string]struct{}, len(state.Journal))
	unseenLocal := make(map[string]struct{}, inspection.Unsent)
	journalBytes := 0
	for _, saved := range state.Journal {
		key := string(saved.Wire)
		seen[key] = struct{}{}
		if saved.Sequence > state.SentSequence {
			unseenLocal[key] = struct{}{}
		}
		journalBytes += len(saved.Wire)
	}
	if err := verifyReconnectRelayPrefix(ctx, log.List, state.Cursor, seen, unseenLocal); err != nil {
		return err
	}
	if applied {
		return nil
	}
	wires, err := readReconnectSuffix(ctx, log, state.Cursor, owner.Cursor, seen, unseenLocal, len(state.Journal), journalBytes)
	if err != nil {
		return err
	}
	if len(unseenLocal) != 0 {
		return ErrReconnectNotReady
	}
	draft := *state
	draft.Journal = slices.Clone(state.Journal)
	for _, wire := range wires {
		draft.Journal = append(draft.Journal, replicastore.ExchangeEnvelope{Wire: wire})
	}
	candidate, err := replayRemovalCheckpoint(reconnectReplayContext(confirmed, state), &draft)
	if err != nil {
		return err
	}
	defer clear(candidate)
	if !bytes.Equal(candidate, remote.Wire) {
		return ErrReconnectCheckpoint
	}
	sent := state.SentSequence + uint64(inspection.Unsent)
	return store.ApplyReconnectSuffix(ctx, confirmed, owner.Generation, state.Cursor, owner.Cursor, sent, wires)
}

func readReconnectSuffix(ctx context.Context, log *syncrelay.Log, after, through uint64, seen, unseenLocal map[string]struct{}, journalCount, journalBytes int) ([][]byte, error) {
	var wires [][]byte
	for after < through {
		page, err := readReconnectRelayPage(ctx, log.List, after, through)
		if err != nil {
			return nil, err
		}
		for _, entry := range page {
			if len(entry.Wire) == 0 {
				return nil, ErrInvalidPage
			}
			key := string(entry.Wire)
			if _, known := seen[key]; known {
				delete(unseenLocal, key)
				continue
			}
			if journalCount == replicastore.MaxExchangeEnvelopes || len(entry.Wire) > replicastore.MaxExchangeWireBytes-journalBytes {
				return nil, replicastore.ErrLimit
			}
			seen[key] = struct{}{}
			wires = append(wires, entry.Wire)
			journalCount++
			journalBytes += len(entry.Wire)
		}
		after = page[len(page)-1].Cursor
	}
	return wires, nil
}
