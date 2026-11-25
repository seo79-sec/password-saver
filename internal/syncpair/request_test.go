package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"
)

// The canonical file and digest were constructed independently with Python cryptography.
const requestVector = "828801" +
	"50000102030405060708090a0b0c0d0e0f50101112131415161718191a1b1c1d1e1f" +
	"582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8" +
	"5820358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254" +
	"5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
	"1a6553f1001a6553f3585840" +
	"97627f9201e6991fbad8c3f6ab8cdf033b6c9076c8a412ea32674a6a76b4d0271" +
	"663000c4a5fc5e644232b12daf0d4f6809daa7f7ee514eabe726c62b6858407"

const requestVectorIssuedAt = 1_700_000_000

func vectorRequest(t *testing.T) ([]byte, Request) {
	t.Helper()
	wire, err := hex.DecodeString(requestVector)
	if err != nil {
		t.Fatal(err)
	}
	request, fingerprint, err := ParseRequest(wire, time.Unix(requestVectorIssuedAt, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fingerprint[:]); got != "e232f30f42ee78ee8b8f64b8747ea6738e464c428d920993dae2ae94a34b1421" {
		t.Fatalf("fingerprint = %s", got)
	}
	return wire, request
}

func vectorSigner() ed25519.PrivateKey {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed[:])
}

func TestRequestVector(t *testing.T) {
	wire, request := vectorRequest(t)
	signed, err := signRequest(request.Header, vectorSigner())
	if err != nil || !bytes.Equal(signed, wire) {
		t.Fatalf("signed request differs from vector: %v", err)
	}
}

func TestNewRequest(t *testing.T) {
	now := time.Unix(requestVectorIssuedAt, 0)
	controller := sha256.Sum256([]byte("test controller"))
	wire, fingerprint, keys, err := NewRequest(controller, now)
	if err != nil {
		t.Fatal(err)
	}
	request, parsedFingerprint, err := ParseRequest(wire, now)
	if err != nil || fingerprint != parsedFingerprint || fingerprint != sha256.Sum256(wire) {
		t.Fatalf("generated request verification failed: %v", err)
	}
	h := request.Header
	if h.ControllerFingerprint != controller || h.IssuedAt != now.Unix() || h.ExpiresAt != now.Unix()+600 {
		t.Fatalf("unexpected generated request header: %+v", h)
	}
	if !bytes.Equal(h.SigningPub[:], keys.signing.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(h.ExchangePub[:], keys.exchange.PublicKey().Bytes()) || bytes.Equal(keys.signing.Seed(), keys.exchange.Bytes()) {
		t.Fatal("generated request does not contain separate public keys matching the device keys")
	}
}

func TestRequestLifetime(t *testing.T) {
	wire, request := vectorRequest(t)
	for _, test := range []struct {
		after int64
		valid bool
	}{{-1, false}, {0, true}, {599, true}, {600, false}, {601, false}} {
		_, _, err := ParseRequest(wire, time.Unix(requestVectorIssuedAt+test.after, 0))
		if (err == nil) != test.valid {
			t.Errorf("after %d seconds, expected validity %t, got error %v", test.after, test.valid, err)
		}
	}
	request.Header.ExpiresAt++
	extended, err := signRequest(request.Header, vectorSigner())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseRequest(extended, time.Unix(requestVectorIssuedAt, 0)); err == nil {
		t.Fatal("ParseRequest accepted a validity interval longer than 10 minutes")
	}
}

func TestParseRequestRejectsTampering(t *testing.T) {
	_, request := vectorRequest(t)
	otherSigner := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, test := range []struct {
		name   string
		change func(*Request)
	}{
		{"signing key", func(r *Request) { copy(r.Header.SigningPub[:], otherSigner) }},
		{"exchange key", func(r *Request) { r.Header.ExchangePub[0] ^= 1 }},
		{"signature", func(r *Request) { r.Signature[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.change(&changed)
			wire, err := encMode.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ParseRequest(wire, time.Unix(requestVectorIssuedAt, 0)); err == nil {
				t.Fatal("ParseRequest accepted tampering")
			}
		})
	}
}

func TestParseRequestRejectsInvalidEncoding(t *testing.T) {
	wire, _ := vectorRequest(t)
	now := time.Unix(requestVectorIssuedAt, 0)
	signatureStart := len(wire) - ed25519.SignatureSize
	for _, invalid := range [][]byte{
		slices.Concat(wire[:2], []byte{0x18, 1}, wire[3:]),
		slices.Concat(wire[:signatureStart-1], []byte{65}, wire[signatureStart:], []byte{0}),
		slices.Concat(wire, []byte{0}),
	} {
		if _, _, err := ParseRequest(invalid, now); err == nil {
			t.Fatal("ParseRequest accepted invalid CBOR")
		}
	}
	if _, _, err := ParseRequest(make([]byte, 513), now); !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("oversize request error = %v, want size limit error", err)
	}
}
