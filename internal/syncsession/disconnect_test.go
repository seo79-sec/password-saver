package syncsession

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

func TestRunOnceRejectsDisconnectedExchange(t *testing.T) {
	store, _, confirmed, signer := queueFixture(t)
	queueForRun(t, store, confirmed, signer, "queued")
	before := readQueue(t, store, confirmed)
	if err := store.DisconnectExchange(t.Context(), confirmed.Binding, before.Generation); err != nil {
		t.Fatal(err)
	}
	disconnected := readQueue(t, store, confirmed)
	requests := 0
	session := NewSession(store, confirmed, runRelay{
		push: func(context.Context, []byte) (uint64, error) {
			requests++
			return 0, nil
		},
		pull: func(context.Context, uint64, int) ([]syncrelay.Entry, uint64, error) {
			requests++
			return nil, 0, nil
		},
	})
	session.SetAccess(true, true)
	if err := session.RunOnce(t.Context()); !errors.Is(err, replicastore.ErrExchangeDisconnected) || requests != 0 {
		t.Fatalf("disconnected run returned %v and issued %d requests", err, requests)
	}
	if !reflect.DeepEqual(readQueue(t, store, confirmed), disconnected) {
		t.Fatal("blocked run changed exchange state")
	}
}

func TestDisconnectDiscardsInFlightResponses(t *testing.T) {
	for _, call := range []string{"push", "pull"} {
		t.Run(call, func(t *testing.T) {
			ctx := t.Context()
			_, _, confirmed, signer := queueFixture(t)
			path, key := filepath.Join(t.TempDir(), "replica.sqlite"), [replicastore.KeySize]byte{1}
			store, err := replicastore.Create(ctx, path, key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			empty := readQueue(t, store, confirmed)
			if err := store.CommitExchange(ctx, confirmed, empty.Generation, nil, 0, 7); err != nil {
				t.Fatal(err)
			}
			wire := queueForRun(t, store, confirmed, signer, "first")
			queueForRun(t, store, confirmed, signer, "second")
			before := readQueue(t, store, confirmed)
			started, release, done := make(chan context.Context, 1), make(chan struct{}), make(chan error, 1)
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			session := NewSession(store, confirmed, runRelay{
				push: func(ctx context.Context, _ []byte) (uint64, error) {
					if call == "pull" {
						return 0, syncrelay.ErrQuotaExceeded
					}
					started <- ctx
					<-release
					return 8, nil
				},
				pull: func(ctx context.Context, _ uint64, _ int) ([]syncrelay.Entry, uint64, error) {
					if call == "pull" {
						started <- ctx
						<-release
					}
					return []syncrelay.Entry{{Cursor: 8, Wire: wire}}, 8, nil
				},
			})
			session.SetAccess(true, true)
			go func() { done <- session.RunOnce(ctx) }()
			var request context.Context
			select {
			case request = <-started:
			case err := <-done:
				t.Fatalf("run ended before %s: %v", call, err)
			}
			err = session.Disconnect(ctx)
			canceled := errors.Is(request.Err(), context.Canceled)
			unblock()
			runErr := <-done
			if err != nil || !canceled || !errors.Is(runErr, ErrSessionChanged) {
				t.Fatalf("disconnect did not cancel and discard %s: disconnect %v, canceled %v, run %v", call, err, canceled, runErr)
			}
			assertClosedDisconnectSession(t, session)
			expected := before
			expected.Generation++
			expected.State.Disconnected = true
			if got := readQueue(t, store, confirmed); !reflect.DeepEqual(got, expected) {
				t.Fatal("disconnect or late reply changed the snapshot, queue, acknowledgment or cursor")
			}

			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = replicastore.Open(ctx, path, key)
			if err != nil {
				t.Fatal(err)
			}
			reopened := NewSession(store, confirmed, nil)
			reopened.SetAccess(true, true)
			if err := reopened.RunOnce(ctx); !errors.Is(err, replicastore.ErrExchangeDisconnected) {
				t.Fatalf("reopened session: %v", err)
			}
			if got := readQueue(t, store, confirmed); !reflect.DeepEqual(got, expected) {
				t.Fatal("reopened replica lost its disconnected state or data")
			}
		})
	}
}

type disconnectTestStore struct {
	ExchangeStore
	write func(context.Context, replicastore.ExchangeBinding, int64) error
}

func (s disconnectTestStore) DisconnectExchange(ctx context.Context, binding replicastore.ExchangeBinding, generation int64) error {
	return s.write(ctx, binding, generation)
}

func TestDisconnectRetriesPersistenceWithoutReopeningSession(t *testing.T) {
	store, _, confirmed, signer := queueFixture(t)
	queueForRun(t, store, confirmed, signer, "first")
	before := readQueue(t, store, confirmed)
	injected := errors.New("injected disconnect write failure")
	writes := 0
	session := NewSession(disconnectTestStore{ExchangeStore: store, write: func(ctx context.Context, binding replicastore.ExchangeBinding, generation int64) error {
		writes++
		if writes == 1 {
			return injected
		}
		err := store.DisconnectExchange(ctx, binding, generation)
		if writes == 2 && err == nil {
			return errors.Join(replicastore.ErrCommitUnknown, injected)
		}
		return err
	}}, confirmed, nil)
	session.SetAccess(true, true)
	if err := session.Disconnect(t.Context()); !errors.Is(err, injected) {
		t.Fatalf("failed write: %v", err)
	}
	assertClosedDisconnectSession(t, session)
	if got := readQueue(t, store, confirmed); !reflect.DeepEqual(got, before) {
		t.Fatal("failed write changed the replica")
	}

	queueForRun(t, store, confirmed, signer, "added before retry")
	expected := readQueue(t, store, confirmed)
	if err := session.Disconnect(t.Context()); !errors.Is(err, replicastore.ErrCommitUnknown) {
		t.Fatalf("retry did not use the current generation: %v", err)
	}
	expected.Generation++
	expected.State.Disconnected = true
	if err := session.Disconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := readQueue(t, store, confirmed); !reflect.DeepEqual(got, expected) || writes != 3 {
		t.Fatal("retry after commit changed the generation, queue or progress")
	}
	assertClosedDisconnectSession(t, session)
}

func assertClosedDisconnectSession(t *testing.T, session *Session) {
	t.Helper()
	for _, paused := range []bool{true, false} {
		session.SetAccess(false, false)
		session.SetPaused(paused)
		session.SetAccess(true, true)
		if err := session.RunOnce(t.Context()); !errors.Is(err, replicastore.ErrExchangeDisconnected) {
			t.Fatalf("closed session returned %v after access or pause change", err)
		}
	}
}
