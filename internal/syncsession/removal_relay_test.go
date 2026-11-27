package syncsession

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncrelay"
)

// The caller has reopened the activated replica and queued its first local edit.
func testRemovalRelayResume(t *testing.T, store *replicastore.Store, previous replicastore.ExchangeBinding, fingerprint [32]byte, keys *syncpair.SpaceKeys, peer [16]byte, wire []byte) {
	t.Helper()
	ctx := t.Context()
	ownerToken, peerToken := [32]byte{1}, [32]byte{2}
	token := base64.RawURLEncoding.EncodeToString(ownerToken[:])
	oldLog := syncrelay.NewLog(8, 1024)
	oldAccess, err := syncrelay.NewDeviceAccess(map[[16]byte][32]byte{
		previous.DeviceID: sha256.Sum256(ownerToken[:]), peer: sha256.Sum256(peerToken[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldHandler := syncrelay.NewDeviceHandler(oldLog, oldAccess)
	status := func(handler http.Handler, raw [32]byte) int {
		request := httptest.NewRequest(http.MethodGet, "https://relay.test/v1/envelopes", nil)
		request.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(raw[:]))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	forbidFactory := func(*syncrelay.Log, *syncrelay.DeviceAccess) (Relay, error) {
		t.Fatal("invalid transition reached the relay factory")
		return nil, nil
	}
	foreign := previous
	foreign.SpaceID[0] ^= 1
	if _, err := NewRemovalSession(ctx, store, foreign, fingerprint, keys, oldLog, oldAccess, forbidFactory); !errors.Is(err, replicastore.ErrExchange) {
		t.Fatalf("foreign binding: %v", err)
	}
	wrongFingerprint := fingerprint
	wrongFingerprint[0] ^= 1
	if _, err := NewRemovalSession(ctx, store, previous, wrongFingerprint, keys, oldLog, oldAccess, forbidFactory); err == nil {
		t.Fatal("accepted an untrusted transition")
	}
	active, err := store.ReadActivatedRemoval(ctx)
	if err != nil || active == nil {
		t.Fatalf("missing activated transition: %v", err)
	}
	tampered := *active
	tampered.Transition.Membership = bytes.Clone(active.Transition.Membership)
	tampered.Transition.Membership[len(tampered.Transition.Membership)-1] ^= 1
	if _, _, err := removalRelayDevices(&tampered, previous, fingerprint); err == nil {
		t.Fatal("accepted a changed signed transition")
	}
	if status(oldHandler, ownerToken) != http.StatusOK {
		t.Fatal("validation failure retired the original relay")
	}

	var requests atomic.Int32
	var liveLog *syncrelay.Log
	var liveAccess *syncrelay.DeviceAccess
	var server *httptest.Server
	connect := func(log *syncrelay.Log, access *syncrelay.DeviceAccess) (Relay, error) {
		if server == nil {
			liveLog, liveAccess = log, access
			handler := syncrelay.NewDeviceHandler(log, access)
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
		} else if log != liveLog || access != liveAccess {
			t.Fatal("connection retry received a different relay pair")
		}
		return syncrelay.NewClient(server.URL, token, server.Client())
	}
	dialErr := errors.New("injected connection failure")
	if _, err := NewRemovalSession(ctx, store, previous, fingerprint, keys, oldLog, oldAccess, func(log *syncrelay.Log, access *syncrelay.DeviceAccess) (Relay, error) {
		if _, err := connect(log, access); err != nil {
			return nil, err
		}
		return nil, dialErr
	}); !errors.Is(err, dialErr) {
		t.Fatalf("initial connection failure: %v", err)
	}
	session, err := NewRemovalSession(ctx, store, previous, fingerprint, keys, oldLog, oldAccess, connect)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(session.confirmed.Checkpoint)
	defer clear(session.confirmed.EpochKey)
	assertPaused := func(s *Session, want error) {
		t.Helper()
		if err := s.RunOnce(ctx); !errors.Is(err, want) || requests.Load() != 0 {
			t.Fatalf("expected %v and zero network requests, got %v and %d", want, err, requests.Load())
		}
	}
	assertPaused(session, ErrSessionInactive)
	session.SetAccess(true, false)
	assertPaused(session, ErrSessionInactive)
	session.SetAccess(false, true)
	assertPaused(session, ErrSessionInactive)
	ordinary := NewSession(store, session.confirmed, session.relay)
	ordinary.SetAccess(true, true)
	assertPaused(ordinary, ErrRemovalRelayPaused)
	ordinary.removalID = active.ID
	ordinary.removalID[0] ^= 1
	assertPaused(ordinary, ErrRemovalRelayPaused)

	session.SetAccess(true, true)
	if err := session.RunOnce(ctx); err != nil || requests.Load() != 2 {
		t.Fatalf("first exchange: %v, %d requests", err, requests.Load())
	}
	view, err := store.ReadExchange(ctx, session.confirmed)
	if err != nil || view.State.SentSequence != 1 || view.State.Cursor != 1 {
		t.Fatalf("first write and echo did not commit cursor 1: %+v, %v", view, err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request, err := http.NewRequestWithContext(ctx, method, server.URL+"/v1/envelopes", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(peerToken[:]))
		request.Header.Set("Content-Type", "application/octet-stream")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s with removed token returned %d", method, response.StatusCode)
		}
	}

	fail := func(log *syncrelay.Log, access *syncrelay.DeviceAccess) (Relay, error) {
		if log != liveLog || access != liveAccess {
			t.Fatal("failed connection received a different relay pair")
		}
		return nil, dialErr
	}
	if _, err := NewRemovalSession(ctx, store, previous, fingerprint, keys, oldLog, oldAccess, fail); !errors.Is(err, dialErr) {
		t.Fatalf("connection failure: %v", err)
	}
	retry, err := NewRemovalSession(ctx, store, previous, fingerprint, keys, oldLog, oldAccess, connect)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retry.confirmed.Checkpoint)
	defer clear(retry.confirmed.EpochKey)
	page, next, err := retry.relay.Pull(ctx, 0, 8)
	if err != nil || next != 1 || len(page) != 1 || page[0].Cursor != 1 || !bytes.Equal(page[0].Wire, wire) {
		t.Fatalf("connection retry lost the exact envelope or cursor: %v, %d, %v", page, next, err)
	}
}
