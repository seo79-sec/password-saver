package replicastore

import (
	"context"
	"math"
)

// ApplyReconnectSuffix records envelopes and local acknowledgements already
// verified against the reviewed relay log and checkpoint. The replica stays disconnected.
func (s *Store) ApplyReconnectSuffix(ctx context.Context, confirmed ExchangeContext, expected int64, after, through, sent uint64, wires [][]byte) error {
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
	if e == nil || !e.Disconnected || e.Binding != confirmed.Binding || e.Cursor != after ||
		through < after || uint64(len(wires)) > through-after {
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
	if sent != sequence || (len(wires) == 0 && sent == e.SentSequence) {
		return ErrExchange
	}
	for _, wire := range wires {
		e.Journal = append(e.Journal, ExchangeEnvelope{Wire: wire})
	}
	e.Cursor, e.SentSequence = through, sent
	e.ReconnectConfirmation = nil
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
