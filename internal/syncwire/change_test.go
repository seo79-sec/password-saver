package syncwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"password-saver/internal/syncmerge"
)

func TestSealOperationReceiver(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	trusted := map[[16]byte]ed25519.PublicKey{header.DeviceID: signer.Public().(ed25519.PublicKey)}
	receiver := NewReceiver(header.SpaceID, header.Epoch, key, trusted)
	recordID := [16]byte{7}
	root, rootHash := mustSealOperation(t, header, LocalOperation{RecordID: recordID, Action: syncmerge.Put}, key, signer)
	requireReceive(t, receiver, root, syncmerge.Applied)

	header.Seq, header.PrevHash = 2, rootHash
	edit, editHash := mustSealOperation(t, header, LocalOperation{
		RecordID: recordID, Parents: [][32]byte{rootHash}, Action: syncmerge.Put, Data: []byte("edited"),
	}, key, signer)
	requireReceive(t, receiver, edit, syncmerge.Applied)
	got := onlyChangeVersion(t, receiver)
	if got.Action != syncmerge.Put || string(got.Data) != "edited" || got.ID != hex.EncodeToString(editHash[:]) ||
		got.RecordID != hex.EncodeToString(recordID[:]) || !slices.Equal(got.Parents, []string{hex.EncodeToString(rootHash[:])}) {
		t.Fatalf("unexpected edit: %+v", got)
	}

	header.Seq, header.PrevHash = 3, editHash
	deleted, deletedHash := mustSealOperation(t, header, LocalOperation{
		RecordID: recordID, Parents: [][32]byte{editHash}, Action: syncmerge.Delete,
	}, key, signer)
	requireReceive(t, receiver, deleted, syncmerge.Applied)
	got = onlyChangeVersion(t, receiver)
	if got.Action != syncmerge.Delete || len(got.Data) != 0 || got.ID != hex.EncodeToString(deletedHash[:]) ||
		!slices.Equal(got.Parents, []string{hex.EncodeToString(editHash[:])}) {
		t.Fatalf("unexpected deletion: %+v", got)
	}
}

func TestSealOperationRejectsInvalidInput(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	recordID := [16]byte{7}
	parents := make([][32]byte, 33)
	for i := range parents {
		parents[i][0] = byte(i + 1)
	}
	for _, test := range []struct {
		name      string
		operation LocalOperation
	}{
		{"zero record ID", LocalOperation{Action: syncmerge.Put}},
		{"duplicate parents", LocalOperation{RecordID: recordID, Parents: [][32]byte{{1}, {1}}, Action: syncmerge.Put}},
		{"too many parents", LocalOperation{RecordID: recordID, Parents: parents, Action: syncmerge.Put}},
		{"data in deletion", LocalOperation{RecordID: recordID, Action: syncmerge.Delete, Data: []byte{1}}},
		{"unknown action", LocalOperation{RecordID: recordID, Action: "invalid"}},
		{"payload too large", LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: make([]byte, maxPlaintextSize)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if wire, digest, err := SealOperation(header, test.operation, key, signer); err == nil || wire != nil || digest != [32]byte{} {
				t.Fatal("SealOperation accepted invalid input or returned a partial result")
			}
		})
	}
	header.Seq = 2
	if _, _, err := SealOperation(header, LocalOperation{RecordID: recordID, Action: syncmerge.Put}, key, signer); err == nil {
		t.Fatal("SealOperation accepted sequence 2 without a previous hash")
	}
}

func TestSealOperationAccepts32Parents(t *testing.T) {
	header := exampleEnvelope().Header
	key, signer := testChangeKeys()
	parents := make([][32]byte, 32)
	for i := range parents {
		parents[i][0] = byte(i + 1)
	}
	wire, _ := mustSealOperation(t, header, LocalOperation{RecordID: [16]byte{1}, Parents: parents, Action: syncmerge.Put}, key, signer)
	trusted := map[[16]byte]ed25519.PublicKey{header.DeviceID: signer.Public().(ed25519.PublicKey)}
	receiver := NewReceiver(header.SpaceID, header.Epoch, key, trusted)
	requireReceive(t, receiver, wire, syncmerge.Waiting)
}

func mustSealOperation(t *testing.T, header Header, operation LocalOperation, key []byte, signer ed25519.PrivateKey) ([]byte, [32]byte) {
	t.Helper()
	wire, digest, err := SealOperation(header, operation, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256.Sum256(wire) {
		t.Fatal("SealOperation returned a digest different from the signed wire bytes")
	}
	envelope, err := Parse(wire)
	if err != nil || envelope.Header != header {
		t.Fatalf("sealed envelope did not preserve the supplied header: %v", err)
	}
	return wire, digest
}

func onlyChangeVersion(t *testing.T, receiver *Receiver) syncmerge.Operation {
	t.Helper()
	records := receiver.Snapshot()
	if len(records) != 1 || len(records[0].Versions) != 1 {
		t.Fatalf("expected one version, got %+v", records)
	}
	return records[0].Versions[0]
}
