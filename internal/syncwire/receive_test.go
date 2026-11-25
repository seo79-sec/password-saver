package syncwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/syncmerge"
)

func TestReceiveReplicas(t *testing.T) {
	key, alice := testChangeKeys()
	bob := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	a, b := exampleEnvelope().Header, exampleEnvelope().Header
	b.DeviceID[0] ^= 1
	trusted := map[[16]byte]ed25519.PublicKey{
		a.DeviceID: alice.Public().(ed25519.PublicKey), b.DeviceID: bob.Public().(ed25519.PublicKey),
	}
	first := NewReceiver(a.SpaceID, a.Epoch, key, trusted)
	second := NewReceiver(a.SpaceID, a.Epoch, key, trusted)
	record := [16]byte{7}
	root := sendChange(t, a, key, alice, changePayload{RecordID: record, Parents: [][32]byte{}, Action: 1, Data: []byte("base")})
	parent := sha256.Sum256(root)
	requireReceive(t, first, root, syncmerge.Applied)

	a.Seq, a.PrevHash = 2, parent
	left := sendChange(t, a, key, alice, changePayload{RecordID: record, Parents: [][32]byte{parent}, Action: 1, Data: []byte("alice")})
	right := sendChange(t, b, key, bob, changePayload{RecordID: record, Parents: [][32]byte{parent}, Action: 1, Data: []byte("bob")})
	fork := sendChange(t, a, key, alice, changePayload{RecordID: record, Parents: [][32]byte{parent}, Action: 2, Data: []byte{}})
	ahead := a
	ahead.Seq, ahead.PrevHash = 3, sha256.Sum256(left)
	gap := sendChange(t, ahead, key, alice, changePayload{RecordID: [16]byte{8}, Parents: [][32]byte{}, Action: 1, Data: []byte{}})
	requireReceive(t, first, gap, syncmerge.Waiting)
	for _, wire := range [][]byte{left, right} {
		requireReceive(t, second, wire, syncmerge.Waiting)
	}
	if got := second.Receive(fork); got.Status != syncmerge.Rejected || !errors.Is(got.Err, ErrChangeFork) {
		t.Fatalf("waiting sequence fork: %+v", got)
	}
	requireReceive(t, second, root, syncmerge.Applied)
	if got := second.Snapshot(); len(got) != 1 || len(got[0].Versions) != 1 || string(got[0].Versions[0].Data) != "base" {
		t.Fatalf("snapshot before resubmission: %+v", got)
	}
	requireReceive(t, second, right, syncmerge.Applied)
	requireReceive(t, second, left, syncmerge.Applied)
	requireReceive(t, first, left, syncmerge.Applied)
	requireReceive(t, first, right, syncmerge.Applied)
	requireReceive(t, second, root, syncmerge.Applied)
	if got := second.Receive(fork); got.Status != syncmerge.Rejected || !errors.Is(got.Err, ErrChangeFork) {
		t.Fatalf("accepted sequence fork: %+v", got)
	}
	got := second.Snapshot()
	if !reflect.DeepEqual(got, first.Snapshot()) || len(got) != 1 || len(got[0].Versions) != 2 {
		t.Fatalf("replicas did not converge with both versions: %+v", got)
	}
	wantAuthors := map[string]string{"alice": hex.EncodeToString(a.DeviceID[:]), "bob": hex.EncodeToString(b.DeviceID[:])}
	for _, version := range got[0].Versions {
		if version.AuthorID != wantAuthors[string(version.Data)] || version.RecordID != hex.EncodeToString(record[:]) {
			t.Fatalf("unexpected version: %+v", version)
		}
	}
	requireReceive(t, first, gap, syncmerge.Applied)
}

func TestReceiveRejectsWithoutAdvancing(t *testing.T) {
	h := exampleEnvelope().Header
	key, signer := testChangeKeys()
	r := NewReceiver(h.SpaceID, h.Epoch, key, map[[16]byte]ed25519.PublicKey{h.DeviceID: signer.Public().(ed25519.PublicKey)})
	record, other := [16]byte{1}, [16]byte{2}
	many := make([][32]byte, 33)
	for i := range many {
		many[i][0] = byte(i + 1)
	}
	for _, payload := range []any{
		[]any{record, [][32]byte{}, 1},
		[]any{record[:15], [][32]byte{}, 1, []byte{}},
		[]any{[16]byte{}, [][32]byte{}, 1, []byte{}},
		[]any{record, [][]byte{make([]byte, 31)}, 1, []byte{}},
		[]any{record, [][32]byte{{1}, {1}}, 1, []byte{}},
		[]any{record, many, 1, []byte{}},
		[]any{record, nil, 1, []byte{}},
		[]any{record, [][32]byte{}, 1, nil},
		[]any{record, [][32]byte{}, 3, []byte{}},
		[]any{record, [][32]byte{}, 2, []byte{1}},
		[]any{record, [][32]byte{}, cbor.RawMessage{0x18, 1}, []byte{}},
	} {
		requireReceive(t, r, sendChange(t, h, key, signer, payload), syncmerge.Rejected)
	}
	root := sendChange(t, h, key, signer, changePayload{RecordID: record, Parents: [][32]byte{}, Action: 1, Data: []byte{}})
	requireReceive(t, r, root, syncmerge.Applied)
	parent := sha256.Sum256(root)
	h.Seq, h.PrevHash = 2, [32]byte{1}
	deletion := changePayload{RecordID: record, Parents: [][32]byte{parent}, Action: 2, Data: []byte{}}
	requireReceive(t, r, sendChange(t, h, key, signer, deletion), syncmerge.Rejected)
	h.PrevHash = parent
	wrongRecord := deletion
	wrongRecord.RecordID = other
	if got := r.Receive(sendChange(t, h, key, signer, wrongRecord)); !errors.Is(got.Err, syncmerge.ErrParentRecord) {
		t.Fatalf("wrong record parent: %+v", got)
	}
	requireReceive(t, r, sendChange(t, h, key, signer, deletion), syncmerge.Applied)
	if got := r.Snapshot(); len(got) != 1 || len(got[0].Versions) != 1 || got[0].Versions[0].Action != syncmerge.Delete {
		t.Fatalf("snapshot after deletion: %+v", got)
	}
}

func sendChange(t *testing.T, h Header, key []byte, signer ed25519.PrivateKey, payload any) []byte {
	t.Helper()
	plain, err := encMode.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(h, plain, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func requireReceive(t *testing.T, r *Receiver, wire []byte, want syncmerge.Status) {
	t.Helper()
	got := r.Receive(wire)
	if got.Status != want || (got.Err != nil) != (want == syncmerge.Rejected) {
		t.Fatalf("Receive returned %+v, want %s", got, want)
	}
	digest := sha256.Sum256(wire)
	if want != syncmerge.Rejected && got.ID != hex.EncodeToString(digest[:]) {
		t.Fatalf("Receive ID = %s, want envelope SHA-256 %x", got.ID, digest)
	}
}
