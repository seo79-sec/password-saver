package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"testing"
	"time"
)

func TestMembership(t *testing.T) {
	first, confirmed, keys, err := NewSpace()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := VerifyMembership(first, nil, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	h := initial.Header
	owner := h.Members[0]
	fingerprintInput := bytes.Join([][]byte{[]byte("PasswordSaver/sync/pair/controller/fingerprint/v1"), h.SpaceID[:], h.ControllerPub[:]}, nil)
	if confirmed != sha256.Sum256(fingerprintInput) || h.Revision != 1 || h.Epoch != 1 || len(h.Members) != 1 || h.OwnerID != owner.DeviceID {
		t.Fatalf("invalid initial membership: %+v", h)
	}
	if !bytes.Equal(owner.SigningPub[:], keys.device.signing.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(owner.ExchangePub[:], keys.device.exchange.PublicKey().Bytes()) || owner.SigningPub == h.ControllerPub {
		t.Fatal("owner device keys and controller key do not match the expected roles")
	}
	now := time.Unix(1_700_000_000, 0)
	request, _, _, err := NewRequest(confirmed, now)
	if err != nil {
		t.Fatal(err)
	}
	join, _, err := ParseRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	member := Member{DeviceID: join.Header.DeviceID, SigningPub: join.Header.SigningPub, ExchangePub: join.Header.ExchangePub}
	updated, err := keys.AddMember(first, confirmed, member)
	if err != nil {
		t.Fatal(err)
	}
	next, err := VerifyMembership(updated, first, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	h = next.Header
	if h.Revision != 2 || h.Epoch != 2 || h.PrevHash != sha256.Sum256(first) || !slices.Equal(h.Members, []Member{owner, member}) {
		t.Fatalf("invalid added member: %+v", h)
	}
	wrongFingerprint := confirmed
	wrongFingerprint[0] ^= 1
	if _, err := VerifyMembership(updated, first, wrongFingerprint); err == nil {
		t.Fatal("VerifyMembership accepted an unconfirmed controller fingerprint")
	}
	if _, err := VerifyMembership(updated, nil, confirmed); err == nil {
		t.Fatal("VerifyMembership accepted the transition without its predecessor")
	}
	badSignature := slices.Clone(updated)
	badSignature[len(badSignature)-1] ^= 1
	for _, wire := range [][]byte{badSignature, slices.Concat(updated[:2], []byte{0x18, 1}, updated[3:])} {
		if _, err := VerifyMembership(wire, first, confirmed); err == nil {
			t.Fatal("VerifyMembership accepted a bad signature or non-canonical encoding")
		}
	}
	for _, test := range []struct {
		name   string
		change func(*MembershipHeader)
	}{
		{"wrong previous hash", func(h *MembershipHeader) { h.PrevHash[0] ^= 1 }},
		{"epoch jump", func(h *MembershipHeader) { h.Epoch++ }},
		{"revision jump", func(h *MembershipHeader) { h.Revision++ }},
		{"duplicate ID", func(h *MembershipHeader) { h.Members[1].DeviceID = h.OwnerID }},
		{"duplicate signing key", func(h *MembershipHeader) { h.Members[1].SigningPub = owner.SigningPub }},
		{"duplicate exchange key", func(h *MembershipHeader) { h.Members[1].ExchangePub = owner.ExchangePub }},
		{"controller key reused", func(h *MembershipHeader) { h.Members[1].SigningPub = h.ControllerPub }},
		{"owner changed", func(h *MembershipHeader) {
			h.OwnerID = member.DeviceID
			h.Members = []Member{member, owner}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := h
			changed.Members = slices.Clone(h.Members)
			test.change(&changed)
			encoded, err := encMode.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			sig := ed25519.Sign(keys.controller, append([]byte(membershipDomain), encoded...))
			wire, err := encMode.Marshal(Membership{Header: changed, Signature: [64]byte(sig)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyMembership(wire, first, confirmed); err == nil {
				t.Fatal("VerifyMembership accepted an invalid signed membership")
			}
		})
	}
}
