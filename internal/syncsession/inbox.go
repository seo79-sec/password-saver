package syncsession

import (
	"context"
	"errors"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

var (
	ErrPageCursor  = errors.New("relay page starts at a stale read cursor")
	ErrInvalidPage = errors.New("invalid relay page")
)

// AcceptPage commits a page fetched after the supplied cursor. It advances
// the read cursor across exact repeats, including echoes of local envelopes.
func AcceptPage(ctx context.Context, store ExchangeStore, confirmed replicastore.ExchangeContext, after uint64, entries []syncrelay.Entry, next uint64) error {
	if len(entries) > syncrelay.MaxPageSize {
		return ErrInvalidPage
	}
	last := after
	for _, entry := range entries {
		if entry.Cursor <= last || entry.Cursor-last != 1 || len(entry.Wire) == 0 || len(entry.Wire) > syncrelay.MaxEnvelopeSize {
			return ErrInvalidPage
		}
		last = entry.Cursor
	}
	if next != last {
		return ErrInvalidPage
	}
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return err
	}
	if view.State == nil {
		return replicastore.ErrExchangeMode
	}
	if after != view.State.Cursor {
		return ErrPageCursor
	}
	if len(entries) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(view.State.Journal)+len(entries))
	for _, saved := range view.State.Journal {
		seen[string(saved.Wire)] = struct{}{}
	}
	var incoming []replicastore.ExchangeEnvelope
	for _, entry := range entries {
		if _, repeat := seen[string(entry.Wire)]; repeat {
			continue
		}
		seen[string(entry.Wire)] = struct{}{}
		incoming = append(incoming, replicastore.ExchangeEnvelope{Wire: entry.Wire})
	}
	// The transaction replays the journal at the expected generation. Waiting
	// envelopes survive in the journal, while rejected ones abort the page.
	return store.CommitExchange(ctx, confirmed, view.Generation, incoming, view.State.SentSequence, next)
}
