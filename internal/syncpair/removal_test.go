package syncpair

import (
	"crypto/sha256"
	"math"
	"slices"
	"testing"
	"time"
)

func TestRemoveMember(t *testing.T) {
	pinned, confirmed, keys, old := removalFixture(t)
	removedID := old.Members[1].DeviceID
	wire, err := keys.RemoveMember(pinned, confirmed, removedID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRemoval(wire, pinned, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	h := verified.Header
	if h.Version != old.Version || h.SpaceID != old.SpaceID || h.OwnerID != old.OwnerID || h.ControllerPub != old.ControllerPub ||
		h.Revision != old.Revision+1 || h.Epoch != old.Epoch+1 || h.PrevHash != sha256.Sum256(pinned) ||
		!slices.Equal(h.Members, old.Members[:1]) {
		t.Fatalf("invalid removal header: %+v", h)
	}
	if _, err := VerifyMembership(wire, pinned, confirmed); err == nil {
		t.Fatal("VerifyMembership accepted a removal as a pairing transition")
	}
	if _, err := keys.RemoveMember(pinned, confirmed, old.OwnerID); err == nil {
		t.Fatal("removed the owner")
	}
	if _, err := keys.RemoveMember(pinned, confirmed, [16]byte{}); err == nil {
		t.Fatal("removed a device outside the membership")
	}
	deviceKeys := &SpaceKeys{controller: keys.DeviceSigningKey()}
	if _, err := deviceKeys.RemoveMember(pinned, confirmed, removedID); err == nil {
		t.Fatal("signed a removal with the owner's device key")
	}
	if _, err := keys.RemoveMember(wire, confirmed, removedID); err == nil {
		t.Fatal("removed the same device from its successor membership")
	}
	h.Revision++
	h.Epoch++
	h.PrevHash = sha256.Sum256(wire)
	repeat := signRemovalFixture(t, h, confirmed, keys)
	if _, err := VerifyRemoval(repeat, wire, confirmed); err == nil {
		t.Fatal("verified a second removal from a one-device membership")
	}
}

func TestVerifyRemovalRejectsSignedInvalidTransitions(t *testing.T) {
	pinned, confirmed, keys, old := removalFixture(t)
	wire, err := keys.RemoveMember(pinned, confirmed, old.Members[1].DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := VerifyRemoval(wire, pinned, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*MembershipHeader)
	}{
		{"wrong previous hash", func(h *MembershipHeader) { h.PrevHash[0] ^= 1 }},
		{"epoch jump", func(h *MembershipHeader) { h.Epoch++ }},
		{"revision jump", func(h *MembershipHeader) { h.Revision++ }},
		{"owner removed", func(h *MembershipHeader) {
			h.Members[0] = old.Members[1]
			h.OwnerID = h.Members[0].DeviceID
		}},
		{"owner signing key changed", func(h *MembershipHeader) { h.Members[0].SigningPub[0] ^= 1 }},
		{"owner exchange key changed", func(h *MembershipHeader) { h.Members[0].ExchangePub[0] ^= 1 }},
		{"second device retained", func(h *MembershipHeader) { h.Members = slices.Clone(old.Members) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := valid.Header
			changed.Members = slices.Clone(changed.Members)
			test.change(&changed)
			forged := signRemovalFixture(t, changed, confirmed, keys)
			if _, err := VerifyRemoval(forged, pinned, confirmed); err == nil {
				t.Fatal("accepted a signed invalid removal")
			}
		})
	}
	sibling := old
	sibling.Members = slices.Clone(old.Members)
	sibling.Members[1].ExchangePub[0] ^= 1
	siblingWire := signRemovalFixture(t, sibling, confirmed, keys)
	if _, err := VerifyRemoval(wire, siblingWire, confirmed); err == nil {
		t.Fatal("accepted a removal for different pinned bytes")
	}
	wrongFingerprint := confirmed
	wrongFingerprint[0] ^= 1
	if _, err := VerifyRemoval(wire, pinned, wrongFingerprint); err == nil {
		t.Fatal("accepted a removal for an unconfirmed controller")
	}
}

func TestRemovalRejectsCounterOverflow(t *testing.T) {
	_, confirmed, keys, paired := removalFixture(t)
	for _, tc := range []struct {
		name            string
		revision, epoch uint64
	}{
		{"revision", math.MaxUint64, 2},
		{"epoch", 2, math.MaxUint64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := paired
			old.Revision, old.Epoch = tc.revision, tc.epoch
			pinned := signRemovalFixture(t, old, confirmed, keys)
			if _, err := keys.RemoveMember(pinned, confirmed, old.Members[1].DeviceID); err == nil {
				t.Fatal("signed a removal with a wrapped counter")
			}
			wrapped := old
			wrapped.Revision++
			wrapped.Epoch++
			wrapped.PrevHash = sha256.Sum256(pinned)
			wrapped.Members = old.Members[:1]
			wire := signRemovalFixture(t, wrapped, confirmed, keys)
			if _, err := VerifyRemoval(wire, pinned, confirmed); err == nil {
				t.Fatal("verified a signed removal with a wrapped counter")
			}
		})
	}
}

func removalFixture(t *testing.T) ([]byte, [32]byte, *SpaceKeys, MembershipHeader) {
	t.Helper()
	initial, confirmed, keys, err := NewSpace()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	wire, _, _, err := NewRequest(confirmed, now)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := ParseRequest(wire, now)
	if err != nil {
		t.Fatal(err)
	}
	h := request.Header
	pinned, err := keys.AddMember(initial, confirmed, Member{DeviceID: h.DeviceID, SigningPub: h.SigningPub, ExchangePub: h.ExchangePub})
	if err != nil {
		t.Fatal(err)
	}
	paired, err := VerifyMembership(pinned, initial, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	return pinned, confirmed, keys, paired.Header
}

func signRemovalFixture(t *testing.T, h MembershipHeader, confirmed [32]byte, keys *SpaceKeys) []byte {
	t.Helper()
	wire, err := signMembership(h, keys.controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySignedMembership(wire, confirmed); err != nil {
		t.Fatalf("test fixture is not a valid standalone membership: %v", err)
	}
	return wire
}
