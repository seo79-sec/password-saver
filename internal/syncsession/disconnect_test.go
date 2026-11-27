package syncsession

import (
	"context"
	"errors"
	"reflect"
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
