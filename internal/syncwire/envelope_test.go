package syncwire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const envelopeHex = "83870101" +
	"50010200000000000000000000000000a1" +
	"1818" +
	"50030400000000000000000000000000b2" +
	"0158200000000000000000000000000000000000000000000000000000000000000000" +
	"581dabababababababababababababababab" +
	"ababababababababababababab" +
	"58405a000000000000000000000000000000" +
	"00000000000000000000000000000000" +
	"00000000000000000000000000000000" +
	"000000000000000000000000000000a5"

func exampleEnvelope() Envelope {
	return Envelope{
		Header: Header{
			Type: 1, Version: 1, Epoch: 24, Seq: 1,
			SpaceID: [16]byte{1, 2, 15: 0xa1}, DeviceID: [16]byte{3, 4, 15: 0xb2},
		},
		Ciphertext: bytes.Repeat([]byte{0xab}, 29),
		Signature:  [64]byte{0x5a, 63: 0xa5},
	}
}

func vectorBytes(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(envelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEnvelopeVector(t *testing.T) {
	want := exampleEnvelope()
	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(data); got != envelopeHex {
		t.Fatalf("Marshal = %s, want %s", got, envelopeHex)
	}
	checkParsed(t, vectorBytes(t), want)
}

func TestEnvelopeRoundTripAtUpperBounds(t *testing.T) {
	want := exampleEnvelope()
	want.Header.Epoch = math.MaxUint64
	want.Header.Seq = 1_048_576
	want.Header.PrevHash[31] = 1
	want.Ciphertext = bytes.Repeat([]byte{0xcd}, 65_564)
	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	checkParsed(t, data, want)
}

func checkParsed(t *testing.T, data []byte, want Envelope) {
	t.Helper()
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != want.Header || got.Signature != want.Signature || !bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Fatal("Parse returned different envelope fields")
	}
}

func TestEnvelopeRejectsInvalidFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Envelope)
	}{
		{"unknown type", func(e *Envelope) { e.Header.Type = 2 }},
		{"unknown version", func(e *Envelope) { e.Header.Version = 2 }},
		{"zero space ID", func(e *Envelope) { e.Header.SpaceID = [16]byte{} }},
		{"zero device ID", func(e *Envelope) { e.Header.DeviceID = [16]byte{} }},
		{"zero epoch", func(e *Envelope) { e.Header.Epoch = 0 }},
		{"zero sequence", func(e *Envelope) { e.Header.Seq = 0 }},
		{"sequence too large", func(e *Envelope) { e.Header.Seq = 1_048_577 }},
		{"first sequence with nonzero hash", func(e *Envelope) { e.Header.PrevHash[0] = 1 }},
		{"later sequence with zero hash", func(e *Envelope) { e.Header.Seq = 2 }},
		{"short ciphertext", func(e *Envelope) { e.Ciphertext = e.Ciphertext[:28] }},
		{"long ciphertext", func(e *Envelope) { e.Ciphertext = make([]byte, 65_565) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := exampleEnvelope()
			test.change(&e)
			if _, err := Marshal(e); err == nil {
				t.Fatal("Marshal accepted invalid fields")
			}
			rejectCBOR(t, e)
		})
	}
}

func TestParseRejectsWrongShape(t *testing.T) {
	e := exampleEnvelope()
	h := e.Header
	header := []any{h.Type, h.Version, h.SpaceID, h.Epoch, h.DeviceID, h.Seq, h.PrevHash}
	withHeader := func(value any) []any {
		return []any{value, e.Ciphertext, e.Signature}
	}
	withHeaderField := func(index int, value any) []any {
		changed := slices.Clone(header)
		changed[index] = value
		return withHeader(changed)
	}
	for _, test := range []struct {
		name  string
		value any
	}{
		{"short envelope", []any{header, e.Ciphertext}},
		{"long envelope", []any{header, e.Ciphertext, e.Signature, nil}},
		{"short header", withHeader(header[:6])},
		{"long header", withHeader(append(slices.Clone(header), nil))},
		{"map header", withHeader(map[int]int{})},
		{"short space ID", withHeaderField(2, h.SpaceID[:15])},
		{"negative epoch", withHeaderField(3, -1)},
		{"long device ID", withHeaderField(4, append(slices.Clone(h.DeviceID[:]), 0))},
		{"short hash", withHeaderField(6, h.PrevHash[:31])},
		{"null hash", withHeaderField(6, nil)},
		{"short signature", []any{header, e.Ciphertext, e.Signature[:63]}},
		{"long signature", []any{header, e.Ciphertext, append(slices.Clone(e.Signature[:]), 0)}},
		{"text ciphertext", []any{header, string(bytes.Repeat([]byte{'x'}, 29)), e.Signature}},
	} {
		t.Run(test.name, func(t *testing.T) { rejectCBOR(t, test.value) })
	}
}

func rejectCBOR(t *testing.T, value any) {
	t.Helper()
	data, err := cbor.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted invalid CBOR envelope")
	}
}

func TestParseRejectsNonCanonicalCBOR(t *testing.T) {
	valid := vectorBytes(t)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"overlong type", slices.Concat(valid[:2], []byte{0x18, 0x01}, valid[3:])},
		{"overlong array length", slices.Concat([]byte{0x98, 0x03}, valid[1:])},
		{"indefinite-length array", slices.Concat([]byte{0x9f}, valid[1:], []byte{0xff})},
		{"tagged envelope", slices.Concat([]byte{0xd9, 0xd9, 0xf7}, valid)},
		{"trailing CBOR item", slices.Concat(valid, []byte{0x00})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.data); err == nil {
				t.Fatal("Parse accepted non-canonical CBOR envelope")
			}
		})
	}
}

func TestParseChecksSizeBeforeDecoding(t *testing.T) {
	if _, err := Parse(make([]byte, 65_793)); !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("Parse error = %v, want size limit error", err)
	}
}
