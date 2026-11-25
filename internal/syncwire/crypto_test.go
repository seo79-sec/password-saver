package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func testChangeKeys() ([]byte, ed25519.PrivateKey) {
	return bytes.Repeat([]byte{0x32}, 32), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
}

func TestSealOpen(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	trusted := map[[16]byte]ed25519.PublicKey{header.DeviceID: signer.Public().(ed25519.PublicKey)}
	for _, test := range []struct {
		name string
		size int
	}{{"minimum payload", 1}, {"maximum payload", 65_536}} {
		t.Run(test.name, func(t *testing.T) {
			want := bytes.Repeat([]byte{0xab}, test.size)
			sealed, err := Seal(header, want, key, signer)
			if err != nil {
				t.Fatal(err)
			}
			if sealed.Header != header || len(sealed.Ciphertext) != test.size+28 {
				t.Fatal("unexpected sealed header or ciphertext length")
			}
			wire, err := Marshal(sealed)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Open(parsed, header.SpaceID, header.Epoch, key, trusted)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("Open did not recover the payload: %v", err)
			}
		})
	}
}

func TestSealRejectsInvalidInput(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	for _, test := range []struct {
		name      string
		plaintext []byte
		epochKey  []byte
		signer    ed25519.PrivateKey
	}{
		{"empty payload", nil, key, signer},
		{"oversized payload", make([]byte, 65_537), key, signer},
		{"short epoch key", []byte{1}, key[:31], signer},
		{"short private key", []byte{1}, key, signer[:63]},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Seal(header, test.plaintext, test.epochKey, test.signer); err == nil {
				t.Fatal("Seal accepted invalid input")
			}
		})
	}
}

func TestOpenRejectsInvalidInput(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	pub := signer.Public().(ed25519.PublicKey)
	sealed, err := Seal(header, []byte("payload"), key, signer)
	if err != nil {
		t.Fatal(err)
	}
	type input struct {
		envelope Envelope
		space    [16]byte
		epoch    uint64
		key      []byte
		trusted  map[[16]byte]ed25519.PublicKey
	}
	for _, test := range []struct {
		name   string
		change func(*input)
		cause  error
	}{
		{"wrong epoch key", func(i *input) { i.key = bytes.Repeat([]byte{0x33}, 32) }, errChangeDecrypt},
		{"short epoch key", func(i *input) { i.key = i.key[:31] }, nil},
		{"different space", func(i *input) { i.space[0] ^= 0x80 }, nil},
		{"different epoch", func(i *input) { i.epoch++ }, nil},
		{"unknown signer", func(i *input) {
			other := header.DeviceID
			other[0] ^= 0x80
			i.trusted = map[[16]byte]ed25519.PublicKey{other: pub}
		}, nil},
		{"short public key", func(i *input) { i.trusted[header.DeviceID] = pub[:31] }, nil},
		{"changed ciphertext", func(i *input) {
			i.envelope.Ciphertext = bytes.Clone(i.envelope.Ciphertext)
			i.envelope.Ciphertext[len(i.envelope.Ciphertext)-1] ^= 1
		}, errChangeSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := input{sealed, header.SpaceID, header.Epoch, key, map[[16]byte]ed25519.PublicKey{header.DeviceID: pub}}
			test.change(&i)
			got, err := Open(i.envelope, i.space, i.epoch, i.key, i.trusted)
			if got != nil || err == nil || (test.cause != nil && !errors.Is(err, test.cause)) {
				t.Fatalf("Open returned %d plaintext bytes and error %v, want rejection (%v)", len(got), err, test.cause)
			}
		})
	}
}

func TestOpenRejectsResignedHeader(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	sealed, err := Seal(header, []byte("payload"), key, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Seq and PrevHash change the AAD while leaving the derived key intact.
	sealed.Header.Seq = 2
	sealed.Header.PrevHash[0] = 1
	signed, err := changeSignatureInput(sealed)
	if err != nil {
		t.Fatal(err)
	}
	copy(sealed.Signature[:], ed25519.Sign(signer, signed))
	trusted := map[[16]byte]ed25519.PublicKey{header.DeviceID: signer.Public().(ed25519.PublicKey)}
	got, err := Open(sealed, header.SpaceID, header.Epoch, key, trusted)
	if got != nil || !errors.Is(err, errChangeDecrypt) {
		t.Fatalf("Open returned %d plaintext bytes and error %v, want AEAD rejection", len(got), err)
	}
}

func TestOpenCryptoVector(t *testing.T) {
	// Built with Python hmac and cryptography using nonce 000102030405060708090a0b.
	data, err := hex.DecodeString("83870101" +
		"50010200000000000000000000000000a11818" +
		"50030400000000000000000000000000b2" +
		"0158200000000000000000000000000000000000000000000000000000000000000000" +
		"5825000102030405060708090a0bf5f721314d5f2d70d93f64b132d645238c2f4d32cd4315a499" +
		"58406f714dcef64a7d864e09d5ef22c0163c8761d48b8274bad7da307353226a4853" +
		"3bb6bb7cd30a6f04d7c3af4f05e161f09a3682e1f393fdde0517e42de95c0b00")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	trusted := map[[16]byte]ed25519.PublicKey{header.DeviceID: signer.Public().(ed25519.PublicKey)}
	got, err := Open(parsed, header.SpaceID, header.Epoch, key, trusted)
	if err != nil || string(got) != "v3 change" {
		t.Fatalf("Open did not recover the vector payload: %v", err)
	}
}
