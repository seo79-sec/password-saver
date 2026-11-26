package syncrelay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

const (
	maxEncodedEnvelopeSize = 4 * ((MaxEnvelopeSize + 2) / 3)
	responseOverhead       = 256
)

var (
	ErrRelayResponseTooLarge = errors.New("relay response exceeds size limit")
	ErrInvalidRelayResponse  = errors.New("invalid relay response")
)

// Client sends and receives opaque envelopes for one relay space.
type Client struct {
	endpoint  url.URL
	token     string
	transport *http.Client
}

// NewClient accepts an HTTPS origin and an unpadded base64url token.
// It copies the HTTP client's standard transport and timeout, including custom
// trust roots. A nil HTTP client uses the default transport.
func NewClient(origin, token string, httpClient *http.Client) (*Client, error) {
	endpoint, err := url.Parse(origin)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("relay URL must be an HTTPS origin")
	}
	var rawToken [32]byte
	if len(token) != relayTokenEncoding.EncodedLen(len(rawToken)) {
		return nil, errors.New("invalid relay bearer token")
	}
	if n, err := relayTokenEncoding.Decode(rawToken[:], []byte(token)); err != nil || n != len(rawToken) {
		return nil, errors.New("invalid relay bearer token")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	roundTripper := httpClient.Transport
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok || transport == nil || transport.DialTLS != nil || transport.DialTLSContext != nil ||
		(transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify) {
		return nil, errors.New("relay requires a transport with standard TLS verification")
	}
	transport = transport.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig.ServerName = ""
	}
	endpoint.Path, endpoint.RawPath = envelopesPath, ""
	return &Client{endpoint: *endpoint, token: token, transport: &http.Client{
		Transport: transport, Timeout: httpClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Push returns the relay cursor for an envelope or its exact repeat.
func (c *Client) Push(ctx context.Context, wire []byte) (uint64, error) {
	if len(wire) == 0 {
		return 0, errors.New("empty relay envelope")
	}
	if len(wire) > MaxEnvelopeSize {
		return 0, ErrEnvelopeTooLarge
	}
	var result struct {
		Cursor uint64 `json:"cursor"`
	}
	if err := c.fetch(ctx, http.MethodPost, c.endpoint, bytes.NewReader(wire), responseOverhead, &result); err != nil {
		return 0, err
	}
	if result.Cursor == 0 {
		return 0, ErrInvalidRelayResponse
	}
	return result.Cursor, nil
}

// Pull validates a complete page before returning the entries and next cursor.
// A failed pull returns the unchanged cursor and no entries.
func (c *Client) Pull(ctx context.Context, after uint64, limit int) ([]Entry, uint64, error) {
	if limit < 1 || limit > MaxPageSize {
		return nil, after, errInvalidListQuery
	}
	endpoint := c.endpoint
	endpoint.RawQuery = "after=" + strconv.FormatUint(after, 10) + "&limit=" + strconv.Itoa(limit)
	var page struct {
		Entries []struct {
			Cursor uint64 `json:"cursor"`
			Wire   string `json:"wire"`
		} `json:"entries"`
		Next *uint64 `json:"next"`
	}
	maxResponse := responseOverhead + limit*(maxEncodedEnvelopeSize+64)
	if err := c.fetch(ctx, http.MethodGet, endpoint, nil, maxResponse, &page); err != nil {
		return nil, after, err
	}
	if page.Entries == nil || len(page.Entries) > limit || page.Next == nil {
		return nil, after, ErrInvalidRelayResponse
	}
	entries := make([]Entry, len(page.Entries))
	next := after
	for i, entry := range page.Entries {
		if entry.Cursor <= next || entry.Cursor-next != 1 || len(entry.Wire) > maxEncodedEnvelopeSize {
			return nil, after, ErrInvalidRelayResponse
		}
		wire, err := base64.StdEncoding.Strict().DecodeString(entry.Wire)
		if err != nil || len(wire) == 0 || len(wire) > MaxEnvelopeSize {
			return nil, after, ErrInvalidRelayResponse
		}
		entries[i] = Entry{Cursor: entry.Cursor, Wire: wire}
		next = entry.Cursor
	}
	if *page.Next != next {
		return nil, after, ErrInvalidRelayResponse
	}
	return entries, next, nil
}

func (c *Client) fetch(ctx context.Context, method string, endpoint url.URL, body io.Reader, maxResponse int, result any) error {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	response, err := c.transport.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusInsufficientStorage {
		return ErrQuotaExceeded
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("relay returned HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(maxResponse)+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return ErrRelayResponseTooLarge
	}
	if json.Unmarshal(data, result) != nil {
		return ErrInvalidRelayResponse
	}
	return nil
}
