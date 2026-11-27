package replicastore

import (
	"context"
	"math"
)

// ReconnectMergeReceipt identifies the exact owner-reviewed merge.
type ReconnectMergeReceipt struct {
	Generation                           int64
	Cursor                               uint64
	CheckpointHash, MergeHash, RelayHash [32]byte
}

// ApplyReconnectMerge stores a verified merge without reopening exchange.
func (s *Store) ApplyReconnectMerge(ctx context.Context, confirmed ExchangeContext, receipt ReconnectMergeReceipt, after, sent uint64, wires [][]byte) error {
	if receipt.Generation < 1 || receipt.CheckpointHash == [32]byte{} ||
		receipt.MergeHash == [32]byte{} || receipt.RelayHash == [32]byte{} {
		return ErrReconnectConfirmation
	}
	return s.applyReconnectSuffix(ctx, confirmed, receipt.Generation, after, receipt.Cursor, sent, wires, &receipt)
}

// ApplyReconnectSuffix records envelopes and local acknowledgements already
// verified against the reviewed relay log and checkpoint. The replica stays disconnected.
func (s *Store) ApplyReconnectSuffix(ctx context.Context, confirmed ExchangeContext, expected int64, after, through, sent uint64, wires [][]byte) error {
	return s.applyReconnectSuffix(ctx, confirmed, expected, after, through, sent, wires, nil)
}

func (s *Store) applyReconnectSuffix(ctx context.Context, confirmed ExchangeContext, expected int64, after, through, sent uint64, wires [][]byte, receipt *ReconnectMergeReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, _, err := s.load(ctx, tx)
	if err != nil {
		return storageError(err)
	}
	if identity != s.identity {
		return ErrAuthentication
	}
	e := data.Exchange
	if e == nil || !e.Disconnected || e.Binding != confirmed.Binding {
		return ErrExchange
	}
	// A lost commit response can be retried with the exact persisted receipt.
	if receipt != nil && e.Removal == nil && expected == generation-1 && through == e.Cursor &&
		e.ReconnectMergeReceipt != nil && *e.ReconnectMergeReceipt == *receipt {
		return nil
	}
	if e.Cursor != after || through < after || uint64(len(wires)) > through-after {
		return ErrExchange
	}
	if e.Removal != nil {
		return ErrRemovalStaged
	}
	if generation != expected {
		return ErrGeneration
	}
	if generation == math.MaxInt64 || len(wires) > MaxExchangeEnvelopes-len(e.Journal) {
		return ErrLimit
	}
	sequence, err := e.validate()
	if err != nil {
		return err
	}
	if sent < e.SentSequence || sent > sequence ||
		(receipt == nil && sent != sequence) ||
		(len(wires) == 0 && (receipt != nil || sent == e.SentSequence)) {
		return ErrExchange
	}
	for _, wire := range wires {
		e.Journal = append(e.Journal, ExchangeEnvelope{Wire: wire})
	}
	e.Cursor, e.SentSequence = through, sent
	e.ReconnectConfirmation = nil
	e.ReconnectMergeReceipt = receipt
	replayed, err := e.replay(confirmed)
	if err != nil {
		return err
	}
	if len(replayed.Pending) != 0 {
		return ErrExchange
	}
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return storageError(err)
	}
	return s.commit(tx)
}
