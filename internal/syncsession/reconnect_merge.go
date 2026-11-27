package syncsession

import (
	"bytes"
	"context"
	"fmt"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

// ReconnectMergeRecord describes a change from the local snapshot to the merged snapshot.
type ReconnectMergeRecord struct {
	ID            string
	Local, Merged ReconnectVersionCounts
}

// ReconnectMergePreview describes an in-memory merge at the reviewed relay cursor.
type ReconnectMergePreview struct {
	Generation     int64
	CheckpointHash [32]byte
	Cursor         uint64
	// Unsent counts unacknowledged local envelopes absent through Cursor.
	Unsent  int
	Records []ReconnectMergeRecord
}

// PreviewReconnectMerge verifies and previews merging a relay log already associated
// by the caller with confirmed.Binding into a disconnected replica with local sends queued.
func PreviewReconnectMerge(ctx context.Context, store reconnectReader, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, log *syncrelay.Log, through uint64) (ReconnectMergePreview, error) {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	state := view.State
	if _, err := restoreReconnectCheckpoint(state, confirmed, remote); err != nil {
		return ReconnectMergePreview{}, err
	}
	if log == nil || through < state.Cursor {
		return ReconnectMergePreview{}, ErrReconnectRelayLog
	}
	relay, merged, unsent, err := collectReconnectMerge(ctx, state, log, through)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	b := confirmed.Binding
	confirmed = reconnectReplayContext(confirmed, state)
	checkpoint, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, relay, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	defer clear(checkpoint)
	if !bytes.Equal(checkpoint, remote.Wire) {
		return ReconnectMergePreview{}, ErrReconnectCheckpoint
	}

	replayed, err := syncwire.Replay(confirmed.Checkpoint, merged, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	if len(replayed.Pending) != 0 {
		return ReconnectMergePreview{}, syncwire.ErrReplayPending
	}
	result := ReconnectMergePreview{Generation: view.Generation, CheckpointHash: remote.CheckpointHash, Cursor: through, Unsent: unsent}
	for _, change := range diffReconnectRecords(view.Snapshot, replayed.Snapshot) {
		result.Records = append(result.Records, ReconnectMergeRecord{ID: change.ID, Local: change.Local, Merged: change.Remote})
	}
	return result, nil
}

func collectReconnectMerge(ctx context.Context, state *replicastore.ExchangeState, log *syncrelay.Log, through uint64) (relay, merged [][]byte, unsent int, err error) {
	if through > replicastore.MaxExchangeEnvelopes {
		return nil, nil, 0, replicastore.ErrLimit
	}
	// The boolean tracks outstanding local envelopes until an exact echo is read.
	seen := make(map[string]bool, len(state.Journal))
	journalBytes := 0
	for _, saved := range state.Journal {
		key := string(saved.Wire)
		queued, known := seen[key]
		if !known {
			merged = append(merged, saved.Wire)
			journalBytes += len(saved.Wire)
		}
		if saved.Sequence > state.SentSequence && !queued {
			queued = true
			unsent++
		}
		seen[key] = queued
	}
	if unsent == 0 {
		return nil, nil, 0, ErrReconnectNotReady
	}
	for after := uint64(0); after < through; {
		page, err := readReconnectRelayPage(ctx, log.List, after, through)
		if err != nil {
			return nil, nil, 0, err
		}
		for _, entry := range page {
			if len(entry.Wire) == 0 {
				return nil, nil, 0, ErrInvalidPage
			}
			key := string(entry.Wire)
			queued, known := seen[key]
			if !known {
				if entry.Cursor <= state.Cursor {
					return nil, nil, 0, fmt.Errorf("%w: unexpected envelope at position %d", ErrReconnectRelayLog, entry.Cursor)
				}
				if len(merged) == replicastore.MaxExchangeEnvelopes || len(entry.Wire) > replicastore.MaxExchangeWireBytes-journalBytes {
					return nil, nil, 0, replicastore.ErrLimit
				}
				merged = append(merged, entry.Wire)
				journalBytes += len(entry.Wire)
			}
			if queued {
				unsent--
			}
			seen[key] = false
			relay = append(relay, entry.Wire)
			after = entry.Cursor
		}
	}
	return relay, merged, unsent, nil
}
