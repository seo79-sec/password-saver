// Package syncwire encodes and parses PasswordSaver v3 change envelopes.
package syncwire

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	changeType        = 1
	envelopeVersion   = 1
	maxSeq            = 1_048_576
	minCiphertextSize = 29
	maxCiphertextSize = 65_564
	maxEnvelopeSize   = 65_792
)

// Header is the seven-element header of a version 1 change envelope.
type Header struct {
	_        struct{} `cbor:",toarray"`
	Type     uint64
	Version  uint64
	SpaceID  [16]byte
	Epoch    uint64
	DeviceID [16]byte
	Seq      uint64
	PrevHash [32]byte
}

// Envelope holds the wire header, ciphertext and signature bytes.
type Envelope struct {
	_          struct{} `cbor:",toarray"`
	Header     Header
	Ciphertext []byte
	Signature  [64]byte
}

var (
	errEnvelopeTooLarge = errors.New("change envelope exceeds size limit")
	encMode, decMode    = envelopeModes()
)

func envelopeModes() (cbor.EncMode, cbor.DecMode) {
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

// Marshal validates and deterministically encodes a change envelope as [H, C, S].
func Marshal(envelope Envelope) ([]byte, error) {
	if err := envelope.validate(); err != nil {
		return nil, err
	}
	return encMode.Marshal(envelope)
}

// Parse accepts one complete, deterministic encoding of a change envelope.
func Parse(data []byte) (Envelope, error) {
	if len(data) > maxEnvelopeSize {
		return Envelope{}, errEnvelopeTooLarge
	}

	var envelope Envelope
	if err := decMode.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode change envelope: %w", err)
	}
	canonical, err := Marshal(envelope)
	if err != nil {
		return Envelope{}, err
	}
	// The decoder can pad or truncate byte strings when decoding into Go arrays.
	// Comparing the encoding also enforces their exact wire types and lengths.
	if !bytes.Equal(data, canonical) {
		return Envelope{}, errors.New("non-canonical change envelope")
	}
	return envelope, nil
}

func (e Envelope) validate() error {
	h := e.Header
	switch {
	case h.Type != changeType:
		return errors.New("unsupported change envelope type")
	case h.Version != envelopeVersion:
		return errors.New("unsupported change envelope version")
	case h.SpaceID == [16]byte{} || h.DeviceID == [16]byte{}:
		return errors.New("change envelope IDs must be nonzero")
	case h.Epoch == 0:
		return errors.New("change envelope epoch must be positive")
	case h.Seq == 0 || h.Seq > maxSeq:
		return errors.New("change envelope sequence is out of range")
	case (h.PrevHash == [32]byte{}) != (h.Seq == 1):
		return errors.New("change envelope previous hash is invalid for its sequence")
	case len(e.Ciphertext) < minCiphertextSize || len(e.Ciphertext) > maxCiphertextSize:
		return errors.New("change envelope ciphertext length is out of range")
	default:
		return nil
	}
}
