package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"testing"

	"password-saver/internal/syncmerge"
)

func TestCheckpointRestoresHistory(t *testing.T) {
	key, alice := testChangeKeys()
	bob := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	a, b := exampleEnvelope().Header, exampleEnvelope().Header
	b.DeviceID[0] ^= 1
	trusted := map[[16]byte]ed25519.PublicKey{
		a.DeviceID: alice.Public().(ed25519.PublicKey), b.DeviceID: bob.Public().(ed25519.PublicKey),
	}
	source := NewReceiver(a.SpaceID, a.Epoch, key, trusted)
	record := [16]byte{7}
	root := sendChange(t, a, key, alice, changePayload{RecordID: record, Parents: [][32]byte{}, Action: 1, Data: []byte("base")})
	rootID := sha256.Sum256(root)
	a.Seq, a.PrevHash = 2, rootID
	update := sendChange(t, a, key, alice, changePayload{RecordID: record, Parents: [][32]byte{rootID}, Action: 1, Data: []byte("edited")})
	deletion := sendChange(t, b, key, bob, changePayload{RecordID: record, Parents: [][32]byte{rootID}, Action: 2, Data: []byte{}})
	for _, wire := range [][]byte{root, update, deletion} {
		requireReceive(t, source, wire, syncmerge.Applied)
	}
	wire, err := source.MarshalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot checkpoint
	if err := checkpointDecMode.Unmarshal(wire, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Heads) != 2 || snapshot.Heads[a.DeviceID] != (checkpointHead{Seq: 2, Hash: sha256.Sum256(update)}) ||
		snapshot.Heads[b.DeviceID] != (checkpointHead{Seq: 1, Hash: sha256.Sum256(deletion)}) {
		t.Fatalf("incorrect checkpoint writer heads: %+v", snapshot.Heads)
	}
	newKey := bytes.Clone(key)
	newKey[0] ^= 1
	target, err := RestoreCheckpoint(wire, a.SpaceID, a.Epoch+1, newKey, trusted)
	if err != nil {
		t.Fatal(err)
	}
	records := target.Snapshot()
	if !reflect.DeepEqual(target.replica.History(), source.replica.History()) || !reflect.DeepEqual(records, source.Snapshot()) ||
		len(records) != 1 || len(records[0].Versions) != 2 ||
		!slices.ContainsFunc(records[0].Versions, func(op syncmerge.Operation) bool { return op.Action == syncmerge.Delete }) {
		t.Fatalf("checkpoint did not preserve the complete history and deletion conflict: %+v", records)
	}
	a.Epoch, a.Seq, a.PrevHash = a.Epoch+1, 1, [32]byte{}
	parents := [][32]byte{rootID, sha256.Sum256(update), sha256.Sum256(deletion)}
	first := sendChange(t, a, newKey, alice, changePayload{RecordID: record, Parents: parents, Action: 1, Data: []byte("resolved")})
	requireReceive(t, target, first, syncmerge.Applied)
	if got := target.Snapshot(); len(got) != 1 || len(got[0].Versions) != 1 || string(got[0].Versions[0].Data) != "resolved" {
		t.Fatalf("unexpected new epoch snapshot: %+v", got)
	}
}

func TestCheckpointRejectsDamagedHistory(t *testing.T) {
	h := exampleEnvelope().Header
	key, signer := testChangeKeys()
	trusted := map[[16]byte]ed25519.PublicKey{h.DeviceID: signer.Public().(ed25519.PublicKey)}
	source := NewReceiver(h.SpaceID, h.Epoch, key, trusted)
	root := sendChange(t, h, key, signer, changePayload{RecordID: [16]byte{1}, Parents: [][32]byte{}, Action: 1, Data: []byte{}})
	requireReceive(t, source, root, syncmerge.Applied)
	wire, err := source.MarshalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*checkpoint)
	}{
		{"wrong space", func(s *checkpoint) { s.SpaceID[0] ^= 1 }},
		{"wrong epoch", func(s *checkpoint) { s.SourceEpoch++ }},
		{"duplicate operation", func(s *checkpoint) { s.History = append(s.History, s.History[0]) }},
		{"too many operations", func(s *checkpoint) { s.History = make([]checkpointOperation, 4097) }},
		{"unknown parent", func(s *checkpoint) { s.History[0].Parents = []string{hex.EncodeToString(make([]byte, 32))} }},
		{"cycle", func(s *checkpoint) { s.History[0].Parents = []string{s.History[0].ID} }},
		{"wrong writer hash", func(s *checkpoint) { s.Heads[h.DeviceID] = checkpointHead{Seq: 1, Hash: [32]byte{1}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var snapshot checkpoint
			if err := checkpointDecMode.Unmarshal(wire, &snapshot); err != nil {
				t.Fatal(err)
			}
			test.change(&snapshot)
			damaged, err := encMode.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if target, err := RestoreCheckpoint(damaged, h.SpaceID, h.Epoch+1, key, trusted); err == nil || target != nil {
				t.Fatal("damaged checkpoint restored a receiver")
			}
		})
	}
	for _, invalid := range [][]byte{slices.Concat(wire[:1], []byte{0x18, 1}, wire[2:]), make([]byte, (8<<20)+1)} {
		if _, err := RestoreCheckpoint(invalid, h.SpaceID, h.Epoch+1, key, trusted); err == nil {
			t.Fatal("RestoreCheckpoint accepted non-canonical or oversized CBOR")
		}
	}
}
