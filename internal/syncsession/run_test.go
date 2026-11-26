package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"reflect"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncrelay"
	"password-saver/internal/syncwire"
)

type runRelay struct {
	push func(context.Context, []byte) (uint64, error)
	pull func(context.Context, uint64, int) ([]syncrelay.Entry, uint64, error)
}

func (r runRelay) Push(ctx context.Context, wire []byte) (uint64, error) { return r.push(ctx, wire) }
func (r runRelay) Pull(ctx context.Context, after uint64, limit int) ([]syncrelay.Entry, uint64, error) {
	return r.pull(ctx, after, limit)
}

func queueForRun(t *testing.T, store *replicastore.Store, confirmed replicastore.ExchangeContext, signer ed25519.PrivateKey, id string) []byte {
	t.Helper()
	wire, err := QueueLocal(t.Context(), store, confirmed, signer, id, syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestRunOnceResendsAfterLostReply(t *testing.T) {
	store, _, confirmed, signer := queueFixture(t)
	first := queueForRun(t, store, confirmed, signer, "first")
	queueForRun(t, store, confirmed, signer, "second")
	log := syncrelay.NewLog(10, syncrelay.MaxEnvelopeSize)
	for i := range 7 {
		if _, err := log.Append([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var attempts [][]byte
	pulls := 0
	session := NewSession(store, confirmed, runRelay{
		push: func(_ context.Context, wire []byte) (uint64, error) {
			attempts = append(attempts, bytes.Clone(wire))
			cursor, err := log.Append(wire)
			if err == nil && len(attempts) == 1 {
				return 0, io.ErrUnexpectedEOF
			}
			return cursor, err
		},
		pull: func(_ context.Context, after uint64, limit int) ([]syncrelay.Entry, uint64, error) {
			pulls++
			page, err := log.List(after, limit)
			return page, after + uint64(len(page)), err
		},
	})
	session.SetAccess(true, true)
	if err := session.RunOnce(t.Context()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost reply: %v", err)
	}
	if view := readQueue(t, store, confirmed); view.State.SentSequence != 0 || view.State.Cursor != 7 || pulls != 0 {
		t.Fatal("lost reply advanced local progress")
	}
	if err := session.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	view := readQueue(t, store, confirmed)
	if len(attempts) != 2 || !bytes.Equal(attempts[0], first) || !bytes.Equal(attempts[1], first) ||
		view.State.SentSequence != 1 || view.State.Cursor != 8 || len(view.State.Journal) != 2 || pulls != 1 {
		t.Fatal("retry did not resend and acknowledge exactly the oldest queued envelope")
	}
}

func TestRunOnceGatesNetworkAndPullsAtQuota(t *testing.T) {
	store, _, confirmed, signer := queueFixture(t)
	local := queueForRun(t, store, confirmed, signer, "local")
	header, remoteSigner := incomingWriter(confirmed, 3)
	remote, _ := sealIncoming(t, header, confirmed.EpochKey, remoteSigner, []byte("incoming"))
	requests := 0
	session := NewSession(store, confirmed, runRelay{
		push: func(context.Context, []byte) (uint64, error) {
			requests++
			return 0, syncrelay.ErrQuotaExceeded
		},
		pull: func(context.Context, uint64, int) ([]syncrelay.Entry, uint64, error) {
			requests++
			return []syncrelay.Entry{{Cursor: 8, Wire: remote}}, 8, nil
		},
	})
	for _, access := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		session.SetAccess(access[0], access[1])
		if err := session.RunOnce(t.Context()); !errors.Is(err, ErrSessionInactive) || requests != 0 {
			t.Fatalf("inactive session made %d requests: %v", requests, err)
		}
	}
	session.SetAccess(true, true)
	if err := session.RunOnce(t.Context()); !errors.Is(err, syncrelay.ErrQuotaExceeded) {
		t.Fatalf("quota result: %v", err)
	}
	view := readQueue(t, store, confirmed)
	if requests != 2 || view.State.SentSequence != 0 || view.State.Cursor != 8 || len(view.State.Journal) != 2 ||
		!bytes.Equal(view.State.Journal[0].Wire, local) || !bytes.Equal(view.State.Journal[1].Wire, remote) {
		t.Fatal("a full relay should preserve the outbox and still commit the incoming page")
	}
}

func TestRunOnceDiscardsLateResponseAfterLock(t *testing.T) {
	for _, stage := range []string{"push", "pull"} {
		t.Run(stage, func(t *testing.T) {
			store, _, confirmed, signer := queueFixture(t)
			wire := queueForRun(t, store, confirmed, signer, "local")
			started, release, done := make(chan context.Context), make(chan struct{}), make(chan error, 1)
			delay := func(ctx context.Context, call string) {
				if call == stage {
					started <- ctx
					<-release
				}
			}
			session := NewSession(store, confirmed, runRelay{
				push: func(ctx context.Context, _ []byte) (uint64, error) {
					delay(ctx, "push")
					return 8, nil
				},
				pull: func(ctx context.Context, _ uint64, _ int) ([]syncrelay.Entry, uint64, error) {
					delay(ctx, "pull")
					return []syncrelay.Entry{{Cursor: 8, Wire: wire}}, 8, nil
				},
			})
			session.SetAccess(true, true)
			go func() { done <- session.RunOnce(t.Context()) }()
			var active context.Context
			select {
			case active = <-started:
			case err := <-done:
				t.Fatalf("run ended before the request: %v", err)
			}
			before := readQueue(t, store, confirmed)
			session.SetAccess(true, false)
			canceled := errors.Is(active.Err(), context.Canceled)
			session.SetAccess(true, true)
			close(release)
			if err := <-done; !canceled || !errors.Is(err, ErrSessionChanged) || !reflect.DeepEqual(readQueue(t, store, confirmed), before) {
				t.Fatalf("late %s response changed progress or was not canceled: %v", stage, err)
			}
		})
	}
}
