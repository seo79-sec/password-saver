package syncsession

import (
	"context"
	"errors"
	"sync"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

var (
	ErrSessionInactive = errors.New("exchange requires opt-in and full unlock")
	ErrSessionChanged  = errors.New("exchange session changed during the request")
	ErrRunInProgress   = errors.New("exchange run already in progress")
)

// Relay is the transport used by an explicit exchange run.
type Relay interface {
	Push(context.Context, []byte) (uint64, error)
	Pull(context.Context, uint64, int) ([]syncrelay.Entry, uint64, error)
}

// Session gates explicit exchange on a test replica.
type Session struct {
	mu         sync.Mutex
	enabled    bool
	unlocked   bool
	generation uint64
	cancel     context.CancelFunc
	store      ExchangeStore
	confirmed  replicastore.ExchangeContext
	relay      Relay
}

// NewSession starts a locked session with exchange disabled.
func NewSession(store ExchangeStore, confirmed replicastore.ExchangeContext, relay Relay) *Session {
	return &Session{store: store, confirmed: confirmed, relay: relay}
}

// SetAccess records opt-in and full unlock, including any required second factor.
// A change cancels the current run before returning.
func (s *Session) SetAccess(enabled, fullyUnlocked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled == enabled && s.unlocked == fullyUnlocked {
		return
	}
	s.enabled, s.unlocked = enabled, fullyUnlocked
	s.generation++
	if s.cancel != nil {
		s.cancel()
	}
}

// RunOnce sends at most one queued envelope and reads one page. A full relay
// still permits the pull and leaves ErrQuotaExceeded in the returned error.
func (s *Session) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	if !s.enabled || !s.unlocked {
		s.mu.Unlock()
		return ErrSessionInactive
	}
	if s.cancel != nil {
		s.mu.Unlock()
		return ErrRunInProgress
	}
	ctx, cancel := context.WithCancel(ctx)
	generation := s.generation
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.cancel = nil
		s.mu.Unlock()
	}()
	view, err := s.store.ReadExchange(ctx, s.confirmed)
	if err != nil {
		return err
	}
	if view.State == nil {
		return replicastore.ErrExchangeMode
	}
	var quotaErr error
	for _, entry := range view.State.Journal {
		if entry.Sequence <= view.State.SentSequence {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor, err := s.relay.Push(ctx, entry.Wire)
		if errors.Is(err, syncrelay.ErrQuotaExceeded) {
			quotaErr = err
			break
		}
		if err != nil {
			return err
		}
		if cursor == 0 {
			return syncrelay.ErrInvalidRelayResponse
		}
		if err := s.commitResult(ctx, generation, func() error {
			return s.store.CommitExchange(ctx, s.confirmed, view.Generation, nil, entry.Sequence, view.State.Cursor)
		}); err != nil {
			return err
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(quotaErr, err)
	}
	after := view.State.Cursor
	page, next, err := s.relay.Pull(ctx, after, syncrelay.MaxPageSize)
	if err != nil {
		return errors.Join(quotaErr, err)
	}
	return errors.Join(quotaErr, s.commitResult(ctx, generation, func() error {
		return AcceptPage(ctx, s.store, s.confirmed, after, page, next)
	}))
}

func (s *Session) commitResult(ctx context.Context, generation uint64, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return ErrSessionChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return write()
}
