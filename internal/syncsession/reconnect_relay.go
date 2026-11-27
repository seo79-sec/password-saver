package syncsession

import (
	"context"
	"errors"
	"fmt"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

// ErrReconnectRelayLog indicates that the relay prefix cannot be verified.
var ErrReconnectRelayLog = errors.New("relay log does not match the reconnect cursor")

type replicaIdentity interface {
	Identity() [16]byte
}

// ReconnectRelayVerification records the exact local state and relay log verified.
type ReconnectRelayVerification struct {
	replicaID    [16]byte
	log          *syncrelay.Log
	binding      replicastore.ExchangeBinding
	generation   int64
	cursor       uint64
	confirmation replicastore.ReconnectConfirmation
}

// VerifyReconnectRelayLog verifies a local log already associated by the caller
// with the confirmed binding. Entries after the saved cursor are left for Pull.
func VerifyReconnectRelayLog(ctx context.Context, store reconnectReader, confirmed replicastore.ExchangeContext, log *syncrelay.Log) (ReconnectRelayVerification, error) {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return ReconnectRelayVerification{}, err
	}
	state := view.State
	if state == nil || !state.Disconnected {
		return ReconnectRelayVerification{}, ErrReconnectRequiresDisconnect
	}
	if state.Binding != confirmed.Binding {
		return ReconnectRelayVerification{}, replicastore.ErrExchange
	}
	saved := state.ReconnectConfirmation
	if saved == nil || saved.Generation < 1 || view.Generation-1 != saved.Generation ||
		saved.CheckpointHash == [32]byte{} {
		return ReconnectRelayVerification{}, replicastore.ErrReconnectConfirmation
	}
	if len(view.Pending) != 0 {
		return ReconnectRelayVerification{}, ErrReconnectNotReady
	}
	seen := make(map[string]struct{}, len(state.Journal))
	for _, entry := range state.Journal {
		if entry.Sequence > state.SentSequence {
			return ReconnectRelayVerification{}, ErrReconnectNotReady
		}
		seen[string(entry.Wire)] = struct{}{}
	}
	if log == nil {
		return ReconnectRelayVerification{}, ErrReconnectRelayLog
	}
	if err := verifyReconnectRelayPrefix(ctx, log.List, state.Cursor, seen, nil); err != nil {
		return ReconnectRelayVerification{}, err
	}
	var replicaID [16]byte
	if replica, ok := store.(replicaIdentity); ok {
		replicaID = replica.Identity()
	}
	return ReconnectRelayVerification{replicaID: replicaID, log: log, binding: state.Binding, generation: view.Generation,
		cursor: state.Cursor, confirmation: *saved}, nil
}

func verifyReconnectRelayPrefix(ctx context.Context, list func(uint64, int) ([]syncrelay.Entry, error), cursor uint64, seen, unseenLocal map[string]struct{}) error {
	for after := uint64(0); after < cursor; {
		page, err := readReconnectRelayPage(ctx, list, after, cursor)
		if err != nil {
			return err
		}
		for _, entry := range page {
			key := string(entry.Wire)
			if _, known := seen[key]; !known {
				return fmt.Errorf("%w: unexpected envelope at position %d", ErrReconnectRelayLog, entry.Cursor)
			}
			delete(unseenLocal, key)
			after = entry.Cursor
		}
	}
	return nil
}

func readReconnectRelayPage(ctx context.Context, list func(uint64, int) ([]syncrelay.Entry, error), after, through uint64) ([]syncrelay.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit := int(min(through-after, uint64(syncrelay.MaxPageSize)))
	page, err := list(after, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReconnectRelayLog, err)
	}
	if len(page) != limit {
		return nil, fmt.Errorf("%w: incomplete page after %d", ErrReconnectRelayLog, after)
	}
	for index, entry := range page {
		if entry.Cursor != after+uint64(index)+1 {
			return nil, fmt.Errorf("%w: unexpected position %d", ErrReconnectRelayLog, entry.Cursor)
		}
	}
	return page, nil
}
