package syncpair

import (
	"bytes"
	"slices"
	"testing"
	"time"
)

func TestAnswer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	initial, confirmedController, owner, err := NewSpace()
	if err != nil {
		t.Fatal(err)
	}
	request, confirmedRequest, recipient, err := NewRequest(confirmedController, now)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, otherFingerprint, otherRecipient, err := NewRequest(confirmedController, now)
	if err != nil {
		t.Fatal(err)
	}
	payload := AnswerPayload{EpochKey: [32]byte{1, 2, 3}, Checkpoint: bytes.Repeat([]byte{0xab}, 8<<20)}
	wire, err := owner.IssueAnswer(initial, request, confirmedRequest, payload, now)
	if err != nil {
		t.Fatal(err)
	}
	membership, got, err := recipient.OpenAnswer(wire, request, confirmedController, now)
	if err != nil || membership.Header.Epoch != 2 || got.EpochKey != payload.EpochKey || !bytes.Equal(got.Checkpoint, payload.Checkpoint) {
		t.Fatalf("OpenAnswer did not recover the membership and payload: %v", err)
	}
	if _, err := owner.IssueAnswer(initial, request, otherFingerprint, payload, now); err == nil {
		t.Fatal("IssueAnswer accepted a mismatched request fingerprint")
	}
	expired := now.Add(10 * time.Minute)
	if _, err := owner.IssueAnswer(initial, request, confirmedRequest, payload, expired); err == nil {
		t.Fatal("IssueAnswer accepted an expired request")
	}
	badController := confirmedController
	badController[0] ^= 1
	for _, test := range []struct {
		name      string
		keys      *DeviceKeys
		request   []byte
		confirmed [32]byte
		at        time.Time
	}{
		{"other recipient", otherRecipient, request, confirmedController, now},
		{"other signing key", &DeviceKeys{signing: otherRecipient.signing, exchange: recipient.exchange}, request, confirmedController, now},
		{"other request", recipient, otherRequest, confirmedController, now},
		{"wrong controller", recipient, request, badController, now},
		{"expired request", recipient, request, confirmedController, expired},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := test.keys.OpenAnswer(wire, test.request, test.confirmed, test.at); err == nil {
				t.Fatal("OpenAnswer accepted invalid pairing inputs")
			}
		})
	}
	var answer signedAnswer
	if err := decMode.Unmarshal(wire, &answer); err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{answer.Membership, answer.Ciphertext} {
		field[0] ^= 1
		changed, err := encMode.Marshal(answer)
		field[0] ^= 1
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := recipient.OpenAnswer(changed, request, confirmedController, now); err == nil {
			t.Fatal("OpenAnswer accepted a modified field")
		}
	}
	for _, invalid := range [][]byte{slices.Concat(wire[:1], []byte{0x98, 3}, wire[2:]), make([]byte, (8<<20)+(4<<10)+1)} {
		if _, _, err := recipient.OpenAnswer(invalid, request, confirmedController, now); err == nil {
			t.Fatal("OpenAnswer accepted non-canonical or oversized CBOR")
		}
	}
	payload.Checkpoint = append(payload.Checkpoint, 0)
	if _, err := owner.IssueAnswer(initial, request, confirmedRequest, payload, now); err == nil {
		t.Fatal("IssueAnswer accepted an oversized checkpoint")
	}
}
