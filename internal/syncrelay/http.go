package syncrelay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const envelopesPath = "/v1/envelopes"

var (
	relayTokenEncoding  = base64.RawURLEncoding.Strict()
	errInvalidListQuery = errors.New("invalid envelope list query")
)

// NewHandler serves one log over TLS. tokenHash is the SHA-256 of the raw
// 32-byte token represented as unpadded base64url in the Authorization header.
func NewHandler(log *Log, tokenHash [sha256.Size]byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusForbidden)
			return
		}
		if !authorized(r.Header.Values("Authorization"), tokenHash) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != envelopesPath {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost:
			appendEnvelope(w, r, log)
		case http.MethodGet:
			listEnvelopes(w, r, log)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func authorized(values []string, want [sha256.Size]byte) bool {
	if len(values) != 1 {
		return false
	}
	scheme, encoded, _ := strings.Cut(values[0], " ")
	encoded = strings.TrimLeft(encoded, " ")
	var token [32]byte
	if !strings.EqualFold(scheme, "Bearer") || len(encoded) != relayTokenEncoding.EncodedLen(len(token)) {
		return false
	}
	n, err := relayTokenEncoding.Decode(token[:], []byte(encoded))
	if err != nil || n != len(token) {
		return false
	}
	digest := sha256.Sum256(token[:])
	return subtle.ConstantTimeCompare(digest[:], want[:]) == 1
}

func appendEnvelope(w http.ResponseWriter, r *http.Request, log *Log) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		http.Error(w, "application/octet-stream required", http.StatusUnsupportedMediaType)
		return
	}
	body := http.MaxBytesReader(w, r.Body, MaxEnvelopeSize)
	defer body.Close()
	wire, err := io.ReadAll(body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "envelope too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil || len(wire) == 0 {
		http.Error(w, "invalid envelope body", http.StatusBadRequest)
		return
	}
	cursor, err := log.Append(wire)
	if errors.Is(err, ErrQuotaExceeded) {
		http.Error(w, "relay quota exceeded", http.StatusInsufficientStorage)
		return
	}
	if err != nil {
		http.Error(w, "could not append envelope", http.StatusInternalServerError)
		return
	}
	writeRelayJSON(w, struct {
		Cursor uint64 `json:"cursor"`
	}{Cursor: cursor})
}

type relayEntry struct {
	Cursor uint64 `json:"cursor"`
	Wire   []byte `json:"wire"`
}

func listEnvelopes(w http.ResponseWriter, r *http.Request, log *Log) {
	after, limit, err := listQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid envelope list query", http.StatusBadRequest)
		return
	}
	page, err := log.List(after, limit)
	if err != nil {
		http.Error(w, "cursor out of range", http.StatusBadRequest)
		return
	}
	response := struct {
		Entries []relayEntry `json:"entries"`
		Next    uint64       `json:"next"`
	}{Entries: make([]relayEntry, len(page)), Next: after}
	for i, entry := range page {
		response.Entries[i] = relayEntry(entry)
		response.Next = entry.Cursor
	}
	writeRelayJSON(w, response)
}

// listQuery defaults to the first page and accepts limit values from 1 to 64.
func listQuery(raw string) (uint64, int, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return 0, 0, errInvalidListQuery
	}
	var after uint64
	limit := MaxPageSize
	for name, values := range query {
		if len(values) != 1 {
			return 0, 0, errInvalidListQuery
		}
		value, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return 0, 0, errInvalidListQuery
		}
		switch {
		case name == "after":
			after = value
		case name == "limit" && value >= 1 && value <= MaxPageSize:
			limit = int(value)
		default:
			return 0, 0, errInvalidListQuery
		}
	}
	return after, limit, nil
}

func writeRelayJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
