package syncrelay

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func clientForTest(t *testing.T, server *httptest.Server, token string) *Client {
	t.Helper()
	client, err := NewClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientPushAndPull(t *testing.T) {
	_, handler, token := relayFixture()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := clientForTest(t, server, token)
	ctx := t.Context()
	first, second := bytes.Repeat([]byte{0xff}, MaxEnvelopeSize), []byte{0, 2}
	for i, wire := range [][]byte{first, second, first} {
		want := uint64(i%2 + 1)
		if cursor, err := client.Push(ctx, wire); err != nil || cursor != want {
			t.Fatalf("push %d: cursor %d, error %v", i, cursor, err)
		}
	}
	if _, err := client.Push(ctx, []byte{3}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota error = %v", err)
	}
	var after uint64
	for _, want := range [][]byte{first, second} {
		entries, next, err := client.Pull(ctx, after, 1)
		if err != nil || next != after+1 || len(entries) != 1 || entries[0].Cursor != next || !bytes.Equal(entries[0].Wire, want) {
			t.Fatalf("pull after %d: %d entries, next %d, error %v", after, len(entries), next, err)
		}
		after = next
	}
	if entries, next, err := client.Pull(ctx, after, MaxPageSize); err != nil || len(entries) != 0 || next != after {
		t.Fatalf("empty page: %d entries, next %d, error %v", len(entries), next, err)
	}
}

func TestClientRejectsInvalidResponses(t *testing.T) {
	token := strings.Repeat("A", 43)
	largeWire := base64.StdEncoding.EncodeToString(make([]byte, MaxEnvelopeSize+1))
	for _, test := range []struct {
		name, body string
		push       bool
		want       error
	}{
		{"zero cursor", `{"cursor":0}`, true, ErrInvalidRelayResponse},
		{"missing cursor", `{}`, true, ErrInvalidRelayResponse},
		{"large push response", strings.Repeat(" ", 1024) + `{"cursor":1}`, true, ErrRelayResponseTooLarge},
		{"wrong next", `{"entries":[{"cursor":8,"wire":"AQ=="}],"next":9}`, false, ErrInvalidRelayResponse},
		{"missing next", `{"entries":[]}`, false, ErrInvalidRelayResponse},
		{"cursor gap", `{"entries":[{"cursor":9,"wire":"AQ=="}],"next":9}`, false, ErrInvalidRelayResponse},
		{"empty envelope", `{"entries":[{"cursor":8,"wire":""}],"next":8}`, false, ErrInvalidRelayResponse},
		{"large envelope", `{"entries":[{"cursor":8,"wire":"` + largeWire + `"}],"next":8}`, false, ErrInvalidRelayResponse},
		{"large pull response", strings.Repeat(" ", 1<<20) + `{"entries":[],"next":7}`, false, ErrRelayResponseTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client := clientForTest(t, server, token)
			if test.push {
				if cursor, err := client.Push(t.Context(), []byte{1}); cursor != 0 || !errors.Is(err, test.want) {
					t.Fatalf("push: cursor %d, error %v", cursor, err)
				}
				return
			}
			if entries, next, err := client.Pull(t.Context(), 7, 1); entries != nil || next != 7 || !errors.Is(err, test.want) {
				t.Fatalf("pull: %d entries, next %d, error %v", len(entries), next, err)
			}
		})
	}
}

func TestClientDoesNotFollowRedirect(t *testing.T) {
	var visits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visits.Add(1)
		_, _ = io.WriteString(w, `{"cursor":1}`)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+envelopesPath, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := clientForTest(t, server, strings.Repeat("A", 43))
	if _, err := client.Push(t.Context(), []byte{1}); err == nil || visits.Load() != 0 {
		t.Fatalf("redirect reached target %d times, error %v", visits.Load(), err)
	}
}

func TestClientRequiresVerifiedTLS(t *testing.T) {
	_, handler, token := relayFixture()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	client, err := NewClient(server.URL, token, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	var untrusted x509.UnknownAuthorityError
	if _, err := client.Push(t.Context(), []byte{1}); !errors.As(err, &untrusted) {
		t.Fatalf("untrusted server certificate: %v", err)
	}
	transport = transport.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	if _, err := NewClient(server.URL, token, &http.Client{Transport: transport}); err == nil {
		t.Fatal("accepted a transport with certificate verification disabled")
	}
	if _, err := NewClient("http://"+server.Listener.Addr().String(), token, server.Client()); err == nil {
		t.Fatal("accepted a plaintext URL")
	}
}
