package syncsession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncrelay"
)

type reconnectFaultStore struct {
	*replicastore.Store
	fault  error
	commit bool
}

func (s reconnectFaultStore) ReconnectExchange(ctx context.Context, b replicastore.ExchangeBinding, generation int64, cursor uint64, confirmation replicastore.ReconnectConfirmation, id [16]byte) error {
	if s.commit {
		if err := s.Store.ReconnectExchange(ctx, b, generation, cursor, confirmation, id); err != nil {
			return err
		}
	}
	return s.fault
}

func TestNewReconnectSession(t *testing.T) {
	ctx := t.Context()
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, confirmed, signer := queueFixture(t)
	path := filepath.Join(t.TempDir(), "reconnect.sqlite")
	store, err := replicastore.Create(ctx, path, queueTestKey)
	require(err)
	t.Cleanup(func() { _ = store.Close() })
	read := func() replicastore.ExchangeView { return readQueue(t, store, confirmed) }
	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 0, 0))
	first := queueForRun(t, store, confirmed, signer, "first")
	log := syncrelay.NewLog(8, syncrelay.MaxEnvelopeSize)
	_, err = log.Append(first)
	require(err)
	require(AcceptPage(ctx, store, confirmed, 0, []syncrelay.Entry{{Cursor: 1, Wire: first}}, 1))
	require(store.CommitExchange(ctx, confirmed, read().Generation, nil, 1, 1))
	old := NewSession(store, confirmed, nil)
	require(old.Disconnect(ctx))
	wire, err := replayRemovalCheckpoint(confirmed, read().State)
	require(err)
	defer clear(wire)
	b := confirmed.Binding
	hash := sha256.Sum256(wire)
	require(ConfirmReconnect(ctx, store, confirmed, ReconnectCheckpoint{SpaceID: b.SpaceID, Epoch: b.Epoch,
		MembershipHash: b.MembershipHash, CheckpointHash: hash, Wire: wire},
		replicastore.ReconnectConfirmation{Generation: read().Generation, CheckpointHash: hash}))
	proof, err := VerifyReconnectRelayLog(ctx, store, confirmed, log)
	require(err)
	before := read()
	header, peer := incomingWriter(confirmed, 3)
	incoming, _ := sealIncoming(t, header, confirmed.EpochKey, peer, []byte("after cursor"))
	_, err = log.Append(incoming)
	require(err)

	token := [32]byte{1}
	handler := syncrelay.NewHandler(log, sha256.Sum256(token[:]))
	var requests atomic.Int32
	firstQuery := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			firstQuery <- r.Method + " " + r.URL.Query().Get("after")
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	factoryCalls := 0
	factory := func(got *syncrelay.Log) (Relay, error) {
		factoryCalls++
		if got != log {
			t.Fatal("factory got a different log")
		}
		return syncrelay.NewClient(server.URL, base64.RawURLEncoding.EncodeToString(token[:]), server.Client())
	}
	stale := proof
	stale.generation--
	otherReplica, _, _, _ := queueFixture(t)
	for _, test := range []struct {
		store reconnectSessionStore
		log   *syncrelay.Log
		proof ReconnectRelayVerification
		want  error
	}{
		{store, log, ReconnectRelayVerification{}, ErrReconnectRelayLog},
		{store, syncrelay.NewLog(8, syncrelay.MaxEnvelopeSize), proof, ErrReconnectRelayLog},
		{otherReplica, log, proof, ErrReconnectRelayLog},
		{store, log, stale, replicastore.ErrGeneration},
	} {
		if s, err := NewReconnectSession(ctx, test.store, confirmed, test.log, test.proof, factory); s != nil || !errors.Is(err, test.want) {
			t.Fatalf("invalid verification returned session %v, error %v", s != nil, err)
		}
	}
	if factoryCalls != 0 {
		t.Fatal("invalid verification reached the factory")
	}
	injected := errors.New("injected failure")
	failFactory := func(*syncrelay.Log) (Relay, error) { return nil, injected }
	if s, err := NewReconnectSession(ctx, store, confirmed, log, proof, failFactory); s != nil || !errors.Is(err, injected) {
		t.Fatalf("factory failure: %v", err)
	}
	for _, fault := range []error{injected, replicastore.ErrCommitUnknown} {
		if s, err := NewReconnectSession(ctx, reconnectFaultStore{Store: store, fault: fault}, confirmed, log, proof, factory); s != nil || !errors.Is(err, fault) {
			t.Fatalf("uncommitted write: %v", err)
		}
	}
	if got := read(); !reflect.DeepEqual(got, before) || requests.Load() != 0 {
		t.Fatal("failed attempts changed the replica or contacted the relay")
	}

	session, err := NewReconnectSession(ctx, reconnectFaultStore{Store: store, fault: replicastore.ErrCommitUnknown, commit: true}, confirmed, log, proof, factory)
	require(err)
	expected := before
	expected.Generation++
	expected.State.Disconnected, expected.State.ReconnectConfirmation, expected.State.ReconnectID = false, nil, session.reconnectID
	require(old.Disconnect(ctx))
	if got := read(); !reflect.DeepEqual(got, expected) {
		t.Fatal("reconnect or repeated old Disconnect changed the replica unexpectedly")
	}
	assertClosedDisconnectSession(t, old)
	calls := factoryCalls
	if s, err := NewReconnectSession(ctx, store, confirmed, log, proof, factory); s != nil || err == nil || factoryCalls != calls {
		t.Fatalf("used verification reached the factory or returned a session: %v", err)
	}
	for _, access := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		session.SetAccess(access[0], access[1])
		if err := session.RunOnce(ctx); !errors.Is(err, ErrSessionInactive) || requests.Load() != 0 {
			t.Fatalf("inactive session made a request: %v", err)
		}
	}
	session.SetAccess(true, true)
	require(session.RunOnce(ctx))
	if requests.Load() != 1 || <-firstQuery != "GET 1" {
		t.Fatal("first exchange did not pull exclusively after cursor 1")
	}
	after := read()
	if after.State.Cursor != 2 || after.State.SentSequence != 1 ||
		len(after.State.Journal) != 2 || !reflect.DeepEqual(after.State.Journal[1].Wire, incoming) {
		t.Fatal("reconnected session did not persist the incoming envelope")
	}
	require(store.Close())
	store, err = replicastore.Open(ctx, path, queueTestKey)
	require(err)
	if !reflect.DeepEqual(read(), after) {
		t.Fatal("reopening lost reconnect state or progress")
	}
}
