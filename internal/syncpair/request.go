// Package syncpair implements the signed files used to pair PasswordSaver devices.
package syncpair

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	requestVersion         = 1
	requestLifetimeSeconds = 600
	maxRequestSize         = 512
	requestDomain          = "PasswordSaver/sync/pair/request/v1"
)

// RequestHeader is the signed header. Its timestamps are Unix seconds.
type RequestHeader struct {
	_                     struct{} `cbor:",toarray"`
	Version               uint64
	RequestID             [16]byte
	DeviceID              [16]byte
	SigningPub            [ed25519.PublicKeySize]byte
	ExchangePub           [32]byte
	ControllerFingerprint [sha256.Size]byte
	IssuedAt              int64
	ExpiresAt             int64
}

// Request is the public wire object [H, Signature].
type Request struct {
	_         struct{} `cbor:",toarray"`
	Header    RequestHeader
	Signature [ed25519.SignatureSize]byte
}

// DeviceKeys holds the new device's private keys in Go for subsequent pairing steps.
type DeviceKeys struct {
	signing  ed25519.PrivateKey
	exchange *ecdh.PrivateKey
}

var (
	errRequestTooLarge = errors.New("pairing request exceeds size limit")
	encMode, decMode   = requestModes()
)

func requestModes() (cbor.EncMode, cbor.DecMode) {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	dec, err := (cbor.DecOptions{
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  4,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return enc, dec
}

// NewRequest generates a device identity and returns the signed file, its SHA-256
// fingerprint for comparison, and the private keys for use inside this package.
func NewRequest(controllerFingerprint [sha256.Size]byte, now time.Time) (wire []byte, fingerprint [sha256.Size]byte, keys *DeviceKeys, err error) {
	issuedAt := now.Unix()
	if issuedAt < 0 || issuedAt > math.MaxInt64-requestLifetimeSeconds {
		return nil, fingerprint, nil, errors.New("invalid pairing request issue time")
	}
	keys, err = generateDeviceKeys()
	if err != nil {
		return nil, fingerprint, nil, err
	}
	header := RequestHeader{
		Version: requestVersion, RequestID: randomID(), DeviceID: randomID(),
		SigningPub: [32]byte(keys.signing.Public().(ed25519.PublicKey)), ExchangePub: [32]byte(keys.exchange.PublicKey().Bytes()),
		ControllerFingerprint: controllerFingerprint, IssuedAt: issuedAt, ExpiresAt: issuedAt + requestLifetimeSeconds,
	}
	wire, err = signRequest(header, keys.signing)
	if err != nil {
		clear(keys.signing)
		return nil, fingerprint, nil, err
	}
	return wire, sha256.Sum256(wire), keys, nil
}

func generateDeviceKeys() (*DeviceKeys, error) {
	exchange, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DeviceKeys{signing: signing, exchange: exchange}, nil
}

func randomID() (id [16]byte) {
	for id == [16]byte{} {
		rand.Read(id[:])
	}
	return id
}

func signRequest(header RequestHeader, signing ed25519.PrivateKey) ([]byte, error) {
	message, err := requestSignatureInput(header)
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(Request{Header: header, Signature: [64]byte(ed25519.Sign(signing, message))})
}

// ParseRequest checks the request's format, lifetime and self-signature, and
// returns the full fingerprint for the caller to compare over a trusted channel.
func ParseRequest(wire []byte, now time.Time) (Request, [sha256.Size]byte, error) {
	if len(wire) > maxRequestSize {
		return Request{}, [sha256.Size]byte{}, errRequestTooLarge
	}
	var request Request
	if err := decMode.Unmarshal(wire, &request); err != nil {
		return Request{}, [sha256.Size]byte{}, fmt.Errorf("decode pairing request: %w", err)
	}
	canonical, err := encMode.Marshal(request)
	if err != nil {
		return Request{}, [sha256.Size]byte{}, err
	}
	if !bytes.Equal(wire, canonical) {
		return Request{}, [sha256.Size]byte{}, errors.New("non-canonical pairing request")
	}
	h := request.Header
	if h.Version != requestVersion || h.RequestID == [16]byte{} || h.DeviceID == [16]byte{} {
		return Request{}, [sha256.Size]byte{}, errors.New("invalid pairing request version or IDs")
	}
	if h.IssuedAt < 0 || h.ExpiresAt <= h.IssuedAt || h.ExpiresAt-h.IssuedAt != requestLifetimeSeconds ||
		now.Unix() < h.IssuedAt || now.Unix() >= h.ExpiresAt {
		return Request{}, [sha256.Size]byte{}, errors.New("pairing request is outside its validity interval")
	}
	message, err := requestSignatureInput(h)
	if err != nil {
		return Request{}, [sha256.Size]byte{}, err
	}
	if !ed25519.Verify(h.SigningPub[:], message, request.Signature[:]) {
		return Request{}, [sha256.Size]byte{}, errors.New("invalid pairing request signature")
	}
	return request, sha256.Sum256(wire), nil
}

func requestSignatureInput(header RequestHeader) ([]byte, error) {
	encoded, err := encMode.Marshal(header)
	if err != nil {
		return nil, err
	}
	return append([]byte(requestDomain), encoded...), nil
}
