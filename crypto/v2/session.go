package cryptov2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
)

var ErrSessionClosed = errors.New("v2 crypto session is closed")

// Session is an opaque, in-memory DEK holder. Its key material cannot be read
// through the API. Close must be called when the owning application session
// ends; clearing memory remains best-effort in Go.
type Session struct {
	mu         sync.Mutex
	engine     *Engine
	container  Container
	dek        []byte
	usedNonces map[string]struct{}
	closed     bool
}

// Unlock authenticates both AEAD layers and retains the DEK in an opaque
// session. The returned plaintext belongs to the caller and should be cleared
// after decoding. The master password is not retained by Session.
func (e *Engine) Unlock(masterPassword string, serialized []byte) (*Session, []byte, error) {
	if e == nil {
		return nil, nil, ErrInvalidParameters
	}
	opened, err := e.openContainer(masterPassword, serialized)
	if err != nil {
		return nil, nil, err
	}
	payloadNonce, err := base64.StdEncoding.DecodeString(opened.container.Nonce)
	if err != nil {
		wipe(opened.dek)
		wipe(opened.plaintext)
		return nil, nil, ErrInvalidContainer
	}
	session := &Session{
		engine:     e,
		container:  opened.container,
		dek:        opened.dek,
		usedNonces: map[string]struct{}{string(payloadNonce): {}},
	}
	return session, opened.plaintext, nil
}

// Encrypt seals updated plaintext with the retained DEK and a fresh
// algorithm-validated nonce, preserving the original DEK wrapper byte-for-byte.
// A nonce is burned as soon as generated, including when a later write fails.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrSessionClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.engine == nil || len(s.dek) != DEKSize {
		return nil, ErrSessionClosed
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrInputTooLarge
	}
	algorithm := s.engine.algorithms[s.container.AEAD]
	if algorithm == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	var nonce []byte
	for attempt := 0; attempt < 16; attempt++ {
		candidate, err := s.engine.generateNonce(algorithm)
		if err != nil {
			return nil, err
		}
		key := string(candidate)
		if _, exists := s.usedNonces[key]; exists {
			continue
		}
		s.usedNonces[key] = struct{}{}
		nonce = candidate
		break
	}
	if nonce == nil {
		return nil, ErrInvalidParameters
	}
	ciphertext, err := sealAEAD(algorithm, s.dek, nonce, plaintext, makePayloadAAD(s.container, nonce))
	if err != nil {
		return nil, err
	}
	updated := s.container
	updated.Nonce = base64.StdEncoding.EncodeToString(nonce)
	updated.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	return json.Marshal(updated)
}

// Close invalidates the session and overwrites the retained DEK.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *Session) closeLocked() {
	if s.closed {
		return
	}
	wipe(s.dek)
	s.dek = nil
	s.usedNonces = nil
	s.engine = nil
	s.container = Container{}
	s.closed = true
}

// IsClosed is provided for lifecycle checks and tests; it exposes no key data.
func (s *Session) IsClosed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
