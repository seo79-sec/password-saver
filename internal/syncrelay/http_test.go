package syncrelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const octetStream = "application/octet-stream"

func relayFixture() (*Log, http.Handler, string) {
	log := NewLog(2, 2*MaxEnvelopeSize)
	token := [32]byte{0xff, 0xad, 0xeb}
	return log, NewHandler(log, sha256.Sum256(token[:])), base64.RawURLEncoding.EncodeToString(token[:])
}

func relayRequest(t *testing.T, server *httptest.Server, method, path, token, contentType string, body io.Reader, wantStatus int) string {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		t.Fatalf("%s %s: status %d, want %d", method, path, response.StatusCode, wantStatus)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestRelayHTTPSPagination(t *testing.T) {
	_, handler, token := relayFixture()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	post := func(wire []byte, status int) string {
		return relayRequest(t, server, http.MethodPost, envelopesPath, token, octetStream, bytes.NewReader(wire), status)
	}
	for _, test := range []struct {
		wire []byte
		want string
	}{
		{[]byte{0xff, 0}, `{"cursor":1}`},
		{[]byte("z"), `{"cursor":2}`},
		{[]byte{0xff, 0}, `{"cursor":1}`},
	} {
		if got := post(test.wire, http.StatusOK); got != test.want {
			t.Fatalf("POST response = %s, want %s", got, test.want)
		}
	}
	post([]byte("over quota"), http.StatusInsufficientStorage)
	for _, test := range []struct{ query, want string }{
		{"?after=0&limit=1", `{"entries":[{"cursor":1,"wire":"/wA="}],"next":1}`},
		{"?after=1&limit=1", `{"entries":[{"cursor":2,"wire":"eg=="}],"next":2}`},
		{"?after=2&limit=64", `{"entries":[],"next":2}`},
		{"", `{"entries":[{"cursor":1,"wire":"/wA="},{"cursor":2,"wire":"eg=="}],"next":2}`},
	} {
		got := relayRequest(t, server, http.MethodGet, envelopesPath+test.query, token, "", nil, http.StatusOK)
		if got != test.want {
			t.Fatalf("page %s = %s, want %s", test.query, got, test.want)
		}
	}
	for _, query := range []string{"after=-1", "after=3", "after=%", "limit=0", "limit=65", "limit=1&limit=2", "unknown=1"} {
		relayRequest(t, server, http.MethodGet, envelopesPath+"?"+query, token, "", nil, http.StatusBadRequest)
	}
}

func TestRelayHTTPSRejectsWritesWithoutChangingLog(t *testing.T) {
	log, handler, token := relayFixture()
	secure := httptest.NewTLSServer(handler)
	defer secure.Close()
	plaintext := httptest.NewServer(handler)
	defer plaintext.Close()
	wrongToken := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, test := range []struct {
		name, token, contentType string
		server                   *httptest.Server
		body                     io.Reader
		status                   int
	}{
		{"missing token", "", octetStream, secure, strings.NewReader("opaque"), http.StatusUnauthorized},
		{"wrong token", wrongToken, octetStream, secure, strings.NewReader("opaque"), http.StatusUnauthorized},
		{"padded token", token + "=", octetStream, secure, strings.NewReader("opaque"), http.StatusUnauthorized},
		{"without TLS", token, octetStream, plaintext, strings.NewReader("opaque"), http.StatusForbidden},
		{"oversized chunked body", token, octetStream, secure, io.LimitReader(bytes.NewReader(make([]byte, MaxEnvelopeSize+1)), MaxEnvelopeSize+1), http.StatusRequestEntityTooLarge},
		{"empty body", token, octetStream, secure, nil, http.StatusBadRequest},
		{"wrong media type", token, "text/plain", secure, strings.NewReader("opaque"), http.StatusUnsupportedMediaType},
	} {
		t.Run(test.name, func(t *testing.T) {
			relayRequest(t, test.server, http.MethodPost, envelopesPath, test.token, test.contentType, test.body, test.status)
			if entries, err := log.List(0, MaxPageSize); err != nil || len(entries) != 0 {
				t.Fatalf("rejected POST changed the log: %d entries, error %v", len(entries), err)
			}
		})
	}
	wire := make([]byte, MaxEnvelopeSize)
	got := relayRequest(t, secure, http.MethodPost, envelopesPath, token, octetStream, bytes.NewReader(wire), http.StatusOK)
	if entries, err := log.List(0, 1); got != `{"cursor":1}` || err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Wire, wire) {
		t.Fatalf("max-size POST after refusals: response %s, %d entries, error %v", got, len(entries), err)
	}
}
