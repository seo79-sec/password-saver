package syncsession

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	MergeHash      [32]byte
	Cursor         uint64
	// Unsent counts unacknowledged local envelopes absent through Cursor.
	Unsent  int
	Records []ReconnectMergeRecord

	confirmation ReconnectMergeConfirmation
}

// ReconnectMergeConfirmation authorizes applying the exact reviewed merge.
type ReconnectMergeConfirmation struct {
	replicaID [16]byte
	binding   replicastore.ExchangeBinding
	receipt   replicastore.ReconnectMergeReceipt
}

// Confirmation records the preview the owner has chosen to apply.
func (p ReconnectMergePreview) Confirmation() ReconnectMergeConfirmation {
	return p.confirmation
}

type reconnectMergeReader interface {
	reconnectReader
	replicaIdentity
}

// PreviewReconnectMerge verifies and previews merging a relay log already associated
// by the caller with confirmed.Binding into a disconnected replica with local sends queued.
func PreviewReconnectMerge(ctx context.Context, store reconnectMergeReader, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, log *syncrelay.Log, through uint64) (ReconnectMergePreview, error) {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	plan, err := prepareReconnectMerge(ctx, view, confirmed, remote, log, through)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	defer clear(plan.checkpoint)
	if !plan.hasQueued {
		return ReconnectMergePreview{}, ErrReconnectNotReady
	}

	b := confirmed.Binding
	confirmed = reconnectReplayContext(confirmed, view.State)
	merged, err := syncwire.RestoreCheckpoint(plan.checkpoint, b.SpaceID, b.Epoch+1, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return ReconnectMergePreview{}, err
	}
	receipt := replicastore.ReconnectMergeReceipt{
		Generation: view.Generation, CheckpointHash: remote.CheckpointHash, MergeHash: plan.mergeHash, Cursor: through, RelayHash: plan.relayHash,
	}
	result := ReconnectMergePreview{
		Generation: receipt.Generation, CheckpointHash: receipt.CheckpointHash, MergeHash: receipt.MergeHash, Cursor: receipt.Cursor,
		Unsent:       plan.unsent,
		confirmation: ReconnectMergeConfirmation{replicaID: store.Identity(), binding: b, receipt: receipt},
	}
	for _, change := range diffReconnectRecords(view.Snapshot, merged.Snapshot()) {
		result.Records = append(result.Records, ReconnectMergeRecord{ID: change.ID, Local: change.Local, Merged: change.Remote})
	}
	return result, nil
}

type reconnectMergeStore interface {
	reconnectMergeReader
	ApplyReconnectMerge(context.Context, replicastore.ExchangeContext, replicastore.ReconnectMergeReceipt, uint64, uint64, [][]byte) error
}

// ApplyReconnectMerge verifies the approved merge again and records its new
// incoming envelopes and contiguous local acknowledgements without reconnecting.
func ApplyReconnectMerge(ctx context.Context, store reconnectMergeStore, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, log *syncrelay.Log, owner ReconnectMergeConfirmation) error {
	receipt := owner.receipt
	if owner.replicaID == [16]byte{} || owner.replicaID != store.Identity() || owner.binding != confirmed.Binding ||
		receipt.Generation < 1 || receipt.CheckpointHash != remote.CheckpointHash {
		return replicastore.ErrReconnectConfirmation
	}
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return err
	}
	state := view.State
	retry := state != nil && view.Generation-1 == receipt.Generation &&
		state.ReconnectMergeReceipt != nil && *state.ReconnectMergeReceipt == receipt
	if view.Generation != receipt.Generation && !retry {
		return replicastore.ErrGeneration
	}
	plan, err := prepareReconnectMerge(ctx, view, confirmed, remote, log, receipt.Cursor)
	if err != nil {
		return err
	}
	defer clear(plan.checkpoint)
	if plan.mergeHash != receipt.MergeHash || plan.relayHash != receipt.RelayHash {
		return replicastore.ErrReconnectConfirmation
	}
	if !retry && (!plan.hasQueued || len(plan.incoming) == 0) {
		return ErrReconnectNotReady
	}
	return store.ApplyReconnectMerge(ctx, confirmed, receipt, state.Cursor, plan.sent, plan.incoming)
}

type reconnectMergePlan struct {
	incoming   [][]byte
	checkpoint []byte
	mergeHash  [32]byte
	relayHash  [32]byte
	sent       uint64
	unsent     int
	hasQueued  bool
}

func prepareReconnectMerge(ctx context.Context, view replicastore.ExchangeView, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint, log *syncrelay.Log, through uint64) (reconnectMergePlan, error) {
	state := view.State
	if _, err := restoreReconnectCheckpoint(state, confirmed, remote); err != nil {
		return reconnectMergePlan{}, err
	}
	if state.Removal != nil {
		return reconnectMergePlan{}, ErrRemovalRelayPaused
	}
	if log == nil || through < state.Cursor {
		return reconnectMergePlan{}, ErrReconnectRelayLog
	}
	plan, relay, journal, err := collectReconnectMerge(ctx, state, log, through)
	if err != nil {
		return reconnectMergePlan{}, err
	}
	b := confirmed.Binding
	confirmed = reconnectReplayContext(confirmed, state)
	checkpoint, err := syncwire.ReplayCheckpoint(confirmed.Checkpoint, relay, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return reconnectMergePlan{}, err
	}
	defer clear(checkpoint)
	if !bytes.Equal(checkpoint, remote.Wire) {
		return reconnectMergePlan{}, ErrReconnectCheckpoint
	}
	plan.checkpoint, err = syncwire.ReplayCheckpoint(confirmed.Checkpoint, journal, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err != nil {
		return reconnectMergePlan{}, err
	}
	plan.mergeHash = sha256.Sum256(plan.checkpoint)
	return plan, nil
}

func collectReconnectMerge(ctx context.Context, state *replicastore.ExchangeState, log *syncrelay.Log, through uint64) (reconnectMergePlan, [][]byte, [][]byte, error) {
	if through > replicastore.MaxExchangeEnvelopes {
		return reconnectMergePlan{}, nil, nil, replicastore.ErrLimit
	}
	seen := make(map[string]struct{}, len(state.Journal))
	queued := make(map[string]uint64)
	journal := make([][]byte, 0, len(state.Journal))
	journalBytes := 0
	for _, saved := range state.Journal {
		key := string(saved.Wire)
		seen[key] = struct{}{}
		journal = append(journal, saved.Wire)
		journalBytes += len(saved.Wire)
		if saved.Sequence > state.SentSequence {
			queued[key] = saved.Sequence
		}
	}
	var relay [][]byte
	plan := reconnectMergePlan{sent: state.SentSequence, hasQueued: len(queued) != 0}
	echoes := make(map[uint64]bool)
	relayHash := sha256.New()
	for after := uint64(0); after < through; {
		page, err := readReconnectRelayPage(ctx, log.List, after, through)
		if err != nil {
			return reconnectMergePlan{}, nil, nil, err
		}
		for _, entry := range page {
			if len(entry.Wire) == 0 {
				return reconnectMergePlan{}, nil, nil, ErrInvalidPage
			}
			key := string(entry.Wire)
			if _, known := seen[key]; !known {
				if entry.Cursor <= state.Cursor {
					return reconnectMergePlan{}, nil, nil, fmt.Errorf("%w: unexpected envelope at position %d", ErrReconnectRelayLog, entry.Cursor)
				}
				if len(journal) == replicastore.MaxExchangeEnvelopes || len(entry.Wire) > replicastore.MaxExchangeWireBytes-journalBytes {
					return reconnectMergePlan{}, nil, nil, replicastore.ErrLimit
				}
				seen[key] = struct{}{}
				plan.incoming = append(plan.incoming, entry.Wire)
				journal = append(journal, entry.Wire)
				journalBytes += len(entry.Wire)
			}
			if sequence, ok := queued[key]; ok {
				echoes[sequence] = true
			}
			digest := sha256.Sum256(entry.Wire)
			relayHash.Write(digest[:])
			relay = append(relay, entry.Wire)
			after = entry.Cursor
		}
	}
	for echoes[plan.sent+1] {
		plan.sent++
	}
	plan.unsent = len(queued) - len(echoes)
	copy(plan.relayHash[:], relayHash.Sum(nil))
	return plan, relay, journal, nil
}
