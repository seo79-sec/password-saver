package syncrelay

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
)

func TestNewDeviceAccessRejectsInvalidConfig(t *testing.T) {
	owner, peer := [16]byte{1}, [16]byte{2}
	hash := sha256.Sum256([]byte("token"))
	for name, config := range map[string]map[[16]byte][sha256.Size]byte{
		"empty":     {},
		"zero ID":   {{0}: hash},
		"zero hash": {owner: {}},
		"duplicate": {owner: hash, peer: hash},
	} {
		t.Run(name, func(t *testing.T) {
			if access, err := NewDeviceAccess(config); err == nil || access != nil {
				t.Fatal("accepted invalid device access configuration")
			}
		})
	}
}

func TestDeviceHandlerRevocation(t *testing.T) {
	handler, access, hashes := newDeviceRevocationTestHandler(t)
	hashes[[16]byte{1}] = sha256.Sum256(make([]byte, 32))
	delete(hashes, [16]byte{2})
	request := func(method string, device byte, body string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, deviceRevocationRequest(method, device, strings.NewReader(body)))
		if response.Code != wantStatus {
			t.Fatalf("%s with token %d returned %d, want %d: %s", method, device, response.Code, wantStatus, response.Body)
		}
		if wantStatus == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatal("missing Bearer challenge")
		}
		return response
	}
	request(http.MethodGet, 0, "", http.StatusUnauthorized)
	for _, device := range []byte{1, 2} {
		request(http.MethodPost, device, string([]byte{device}), http.StatusOK)
		request(http.MethodGet, device, "", http.StatusOK)
	}

	access.Revoke([16]byte{2})
	access.Revoke([16]byte{2})
	request(http.MethodGet, 2, "", http.StatusUnauthorized)
	request(http.MethodPost, 2, "revoked", http.StatusUnauthorized)
	request(http.MethodPost, 1, "owner after revocation", http.StatusOK)
	requireDeviceRevocationCursor(t, request(http.MethodGet, 1, "", http.StatusOK), 3)
}

func TestDeviceHandlerRevocationDuringRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		handler, access, _ := newDeviceRevocationTestHandler(t)
		body, input := io.Pipe()
		defer input.Close()
		post := httptest.NewRecorder()
		postDone := make(chan struct{})
		go func() {
			defer close(postDone)
			handler.ServeHTTP(post, deviceRevocationRequest(http.MethodPost, 2, body))
		}()

		get := &deviceRevocationBlockedResponse{
			ResponseRecorder: httptest.NewRecorder(),
			writing:          make(chan struct{}),
			resume:           make(chan struct{}),
		}
		getDone := make(chan struct{})
		go func() {
			defer close(getDone)
			handler.ServeHTTP(get, deviceRevocationRequest(http.MethodGet, 2, nil))
		}()
		<-get.writing
		synctest.Wait()
		select {
		case <-postDone:
			close(get.resume)
			<-getDone
			t.Fatal("POST returned before its body was sent")
		default:
		}

		access.Revoke([16]byte{2})
		close(get.resume)
		<-getDone
		requireDeviceRevocationCursor(t, get.ResponseRecorder, 0)
		if _, err := io.WriteString(input, "revoked"); err != nil {
			t.Fatal(err)
		}
		_ = input.Close()
		<-postDone
		if post.Code != http.StatusUnauthorized || post.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("delayed POST returned %d with headers %v", post.Code, post.Header())
		}
		owner := httptest.NewRecorder()
		handler.ServeHTTP(owner, deviceRevocationRequest(http.MethodGet, 1, nil))
		requireDeviceRevocationCursor(t, owner, 0)
	})
}

func newDeviceRevocationTestHandler(t *testing.T) (http.Handler, *DeviceAccess, map[[16]byte][sha256.Size]byte) {
	t.Helper()
	ownerToken, peerToken := [32]byte{1}, [32]byte{2}
	hashes := map[[16]byte][sha256.Size]byte{
		{1}: sha256.Sum256(ownerToken[:]),
		{2}: sha256.Sum256(peerToken[:]),
	}
	access, err := NewDeviceAccess(hashes)
	if err != nil {
		t.Fatal(err)
	}
	return NewDeviceHandler(NewLog(8, 1024), access), access, hashes
}

func deviceRevocationRequest(method string, device byte, body io.Reader) *http.Request {
	token := [32]byte{device}
	request := httptest.NewRequest(method, "https://relay.test/v1/envelopes", body)
	request.Header.Set("Authorization", "Bearer "+relayTokenEncoding.EncodeToString(token[:]))
	request.Header.Set("Content-Type", "application/octet-stream")
	return request
}

func requireDeviceRevocationCursor(t *testing.T, response *httptest.ResponseRecorder, want uint64) {
	t.Helper()
	var page struct {
		Next uint64 `json:"next"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); response.Code != http.StatusOK || err != nil || page.Next != want {
		t.Fatalf("expected a successful page with cursor %d, got %d: %s", want, response.Code, response.Body)
	}
}

type deviceRevocationBlockedResponse struct {
	*httptest.ResponseRecorder
	writing, resume chan struct{}
}

func (w *deviceRevocationBlockedResponse) Write(data []byte) (int, error) {
	close(w.writing)
	<-w.resume
	return w.ResponseRecorder.Write(data)
}
