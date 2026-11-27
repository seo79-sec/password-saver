package syncrelay

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

func TestRotateForRemoval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner, peer := [16]byte{1}, [16]byte{2}
		log := NewLog(2, 5)
		access := newRotationAccess(t, owner, peer)
		oldHandler := NewDeviceHandler(log, access)
		serve := func(handler http.Handler, method string, device byte, body io.Reader, status int) *httptest.ResponseRecorder {
			t.Helper()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, deviceRevocationRequest(method, device, body))
			if response.Code != status {
				t.Fatalf("%s with token %d returned %d, want %d: %s", method, device, response.Code, status, response.Body)
			}
			if status == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing Bearer challenge")
			}
			return response
		}
		serve(oldHandler, http.MethodPost, 2, strings.NewReader("old"), http.StatusOK)
		body, writer := io.Pipe()
		defer writer.Close()
		delayed := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			oldHandler.ServeHTTP(delayed, deviceRevocationRequest(http.MethodPost, 1, body))
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("POST returned before its body was sent")
		default:
		}

		nextLog, nextAccess, err := RotateForRemoval(log, access, owner, peer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, "late"); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		<-done
		if delayed.Code != http.StatusUnauthorized || delayed.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("delayed POST returned %d with headers %v", delayed.Code, delayed.Header())
		}

		newHandler := NewDeviceHandler(nextLog, nextAccess)
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			serve(oldHandler, method, 1, strings.NewReader("x"), http.StatusUnauthorized)
			serve(oldHandler, method, 2, strings.NewReader("x"), http.StatusUnauthorized)
			serve(newHandler, method, 2, strings.NewReader("x"), http.StatusUnauthorized)
		}
		requireDeviceRevocationCursor(t, serve(newHandler, http.MethodGet, 1, nil, http.StatusOK), 0)
		post := serve(newHandler, http.MethodPost, 1, strings.NewReader("new"), http.StatusOK)
		var receipt struct {
			Cursor uint64
		}
		if err := json.Unmarshal(post.Body.Bytes(), &receipt); err != nil || receipt.Cursor != 1 {
			t.Fatalf("first new write did not return cursor 1: %s", post.Body)
		}
		retryLog, retryAccess, err := RotateForRemoval(log, access, owner, peer)
		if err != nil || retryLog != nextLog || retryAccess != nextAccess {
			t.Fatalf("exact retry did not return the same successor pair: %v", err)
		}
		requireDeviceRevocationCursor(t, serve(NewDeviceHandler(retryLog, retryAccess), http.MethodGet, 1, nil, http.StatusOK), 1)
		serve(newHandler, http.MethodPost, 1, strings.NewReader("big"), http.StatusInsufficientStorage)
		serve(newHandler, http.MethodPost, 1, strings.NewReader("a"), http.StatusOK)
		serve(newHandler, http.MethodPost, 1, strings.NewReader("b"), http.StatusInsufficientStorage)
		page, err := log.List(0, MaxPageSize)
		if err != nil || !reflect.DeepEqual(page, []Entry{{Cursor: 1, Wire: []byte("old")}}) {
			t.Fatalf("original journal changed: %v, %v", page, err)
		}
		serve(NewDeviceHandler(log, newRotationAccess(t, owner)), http.MethodGet, 1, nil, http.StatusUnauthorized)
	})
}

func TestRotateForRemovalChecksPairAndIDs(t *testing.T) {
	owner, peer, other := [16]byte{1}, [16]byte{2}, [16]byte{3}
	log, access := NewLog(2, 5), newRotationAccess(t, owner, peer)
	handler := NewDeviceHandler(log, access)
	for _, test := range []struct {
		log            *Log
		access         *DeviceAccess
		owner, removed [16]byte
	}{
		{log, access, owner, owner},
		{log, access, owner, [16]byte{}},
		{log, access, [16]byte{}, peer},
		{log, access, other, peer},
		{log, access, owner, other},
		{NewLog(2, 5), access, owner, peer},
		{log, newRotationAccess(t, owner, peer), owner, peer},
		{NewLog(2, 5), newRotationAccess(t, owner, peer, other), owner, peer},
	} {
		if nextLog, nextAccess, err := RotateForRemoval(test.log, test.access, test.owner, test.removed); !errors.Is(err, ErrRemovalRotation) || nextLog != nil || nextAccess != nil {
			t.Fatalf("invalid rotation changed the pair: %v", err)
		}
	}
	for _, id := range []byte{1, 2} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, deviceRevocationRequest(http.MethodGet, id, nil))
		requireDeviceRevocationCursor(t, response, 0)
	}
}

func TestRotateForRemovalAfterRevoke(t *testing.T) {
	owner, peer, other := [16]byte{1}, [16]byte{2}, [16]byte{3}
	log, access := NewLog(2, 5), newRotationAccess(t, owner, peer)
	access.Revoke(peer)
	type result struct {
		removed [16]byte
		log     *Log
		access  *DeviceAccess
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, removed := range [][16]byte{peer, other} {
		go func() {
			<-start
			nextLog, nextAccess, err := RotateForRemoval(log, access, owner, removed)
			results <- result{removed: removed, log: nextLog, access: nextAccess, err: err}
		}()
	}
	close(start)
	winner, loser := <-results, <-results
	if winner.err != nil {
		winner, loser = loser, winner
	}
	if winner.err != nil || !errors.Is(loser.err, ErrRemovalRotation) {
		t.Fatalf("expected exactly one transition after revocation, got %v and %v", winner.err, loser.err)
	}
	retryLog, retryAccess, err := RotateForRemoval(log, access, owner, winner.removed)
	if err != nil || retryLog != winner.log || retryAccess != winner.access {
		t.Fatalf("winning retry did not return the original successor pair: %v", err)
	}
}

func newRotationAccess(t *testing.T, ids ...[16]byte) *DeviceAccess {
	t.Helper()
	hashes := make(map[[16]byte][sha256.Size]byte, len(ids))
	for _, id := range ids {
		token := [32]byte{id[0]}
		hashes[id] = sha256.Sum256(token[:])
	}
	access, err := NewDeviceAccess(hashes)
	if err != nil {
		t.Fatal(err)
	}
	return access
}
