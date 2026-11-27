package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

func TestRemovalCheckpoint(t *testing.T) {
	previous, current, confirmed, keys, peer := removalCheckpointTestSpace(t)
	membership, err := VerifyRemoval(current, previous, confirmed)
	checkRemovalCheckpointError(t, err)
	h := membership.Header
	owner := h.Members[0]
	peerPub := peer.signing.Public().(ed25519.PublicKey)
	pinned, err := VerifySignedMembership(previous, confirmed)
	checkRemovalCheckpointError(t, err)
	peerID := pinned.Header.Members[1].DeviceID
	var oldKey [32]byte
	rand.Read(oldKey[:])
	base := syncwire.NewReceiver(h.SpaceID, h.Epoch-1, oldKey[:], map[[16]byte]ed25519.PublicKey{
		owner.DeviceID: owner.SigningPub[:], peerID: peerPub,
	})

	recordID := [16]byte{1}
	header := syncwire.Header{Type: 1, Version: 1, SpaceID: h.SpaceID, Epoch: h.Epoch - 1, DeviceID: owner.DeviceID, Seq: 1}
	put := syncwire.LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: []byte("initial")}
	apply := func(receiver *syncwire.Receiver, h syncwire.Header, op syncwire.LocalOperation, key [32]byte, signer ed25519.PrivateKey) [32]byte {
		t.Helper()
		wire, hash, err := syncwire.SealOperation(h, op, key[:], signer)
		checkRemovalCheckpointError(t, err)
		if result := receiver.Receive(wire); result.Status != syncmerge.Applied {
			t.Fatalf("receive operation: %+v", result)
		}
		return hash
	}
	parent := apply(base, header, put, oldKey, keys.DeviceSigningKey())
	header.Seq, header.PrevHash = 2, parent
	put.Parents, put.Data = [][32]byte{parent}, []byte("edited")
	edit := apply(base, header, put, oldKey, keys.DeviceSigningKey())
	header.DeviceID, header.Seq, header.PrevHash = peerID, 1, [32]byte{}
	del := apply(base, header, syncwire.LocalOperation{RecordID: recordID, Parents: put.Parents, Action: syncmerge.Delete}, oldKey, peer.signing)

	checkpoint, err := base.MarshalCheckpoint()
	checkRemovalCheckpointError(t, err)
	newKey, wire, err := keys.SealRemovalCheckpoint(previous, current, confirmed, checkpoint)
	checkRemovalCheckpointError(t, err)
	secondKey, _, err := keys.SealRemovalCheckpoint(previous, current, confirmed, checkpoint)
	checkRemovalCheckpointError(t, err)
	if newKey == oldKey || newKey == secondKey {
		t.Fatal("expected an independent key for each seal")
	}
	fresh, err := OpenRemovalCheckpoint(wire, previous, current, confirmed, newKey)
	checkRemovalCheckpointError(t, err)
	want, got := base.Snapshot(), fresh.Snapshot()
	if len(want) != 1 || len(want[0].Versions) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("restored conflict: got %+v, want %+v", got, want)
	}
	header.Epoch = h.Epoch
	removedWire, _, err := syncwire.SealOperation(header, put, newKey[:], peer.signing)
	checkRemovalCheckpointError(t, err)
	if got := fresh.Receive(removedWire); got.Status == syncmerge.Applied {
		t.Fatal("accepted a change from the removed writer")
	}
	header.DeviceID = owner.DeviceID
	put.Parents, put.Data = [][32]byte{edit, del}, []byte("resolved")
	resolution := apply(fresh, header, put, newKey, keys.DeviceSigningKey())
	if got := fresh.Snapshot(); len(got) != 1 || len(got[0].Versions) != 1 || got[0].Versions[0].ID != hex.EncodeToString(resolution[:]) {
		t.Fatalf("first new-epoch operation did not resolve the conflict: %+v", got)
	}

	otherPrevious, otherCurrent, otherFingerprint, otherKeys, _ := removalCheckpointTestSpace(t)
	pinned.Header.PrevHash[0] ^= 1
	subPrevious, err := signMembership(pinned.Header, keys.controller)
	checkRemovalCheckpointError(t, err)
	subCurrent, err := keys.RemoveMember(subPrevious, confirmed, peerID)
	checkRemovalCheckpointError(t, err)
	wrongEpoch, err := syncwire.NewReceiver(h.SpaceID, h.Epoch, oldKey[:], nil).MarshalCheckpoint()
	checkRemovalCheckpointError(t, err)
	for _, test := range []struct {
		name string
		keys *SpaceKeys
		data []byte
	}{
		{"foreign controller", otherKeys, checkpoint},
		{"wrong source epoch", keys, wrongEpoch},
	} {
		t.Run(test.name, func(t *testing.T) {
			if key, wire, err := test.keys.SealRemovalCheckpoint(previous, current, confirmed, test.data); err == nil || key != [32]byte{} || wire != nil {
				t.Fatal("seal returned a key or envelope for invalid input")
			}
		})
	}

	var envelope signedRemovalCheckpoint
	checkRemovalCheckpointError(t, decMode.Unmarshal(wire, &envelope))
	envelope.Ciphertext[0] ^= 1
	modified, err := encMode.Marshal(envelope)
	checkRemovalCheckpointError(t, err)
	aad, err := encMode.Marshal(envelope.Header)
	checkRemovalCheckpointError(t, err)
	gcm, err := removalCheckpointAEAD(newKey)
	checkRemovalCheckpointError(t, err)
	envelope.Ciphertext = gcm.Seal(nil, nil, wrongEpoch, aad)
	envelope.Signature = [ed25519.SignatureSize]byte(ed25519.Sign(keys.controller, removalCheckpointSignatureInput(aad, envelope.Ciphertext)))
	signedWrongEpoch, err := encMode.Marshal(envelope)
	checkRemovalCheckpointError(t, err)
	for _, test := range []struct {
		name                    string
		wire, previous, current []byte
		fingerprint, key        [32]byte
	}{
		{"old epoch key", wire, previous, current, confirmed, oldKey},
		{"modified ciphertext", modified, previous, current, confirmed, newKey},
		{"substituted membership", wire, subPrevious, subCurrent, confirmed, newKey},
		{"foreign space", wire, otherPrevious, otherCurrent, otherFingerprint, newKey},
		{"signed wrong source epoch", signedWrongEpoch, previous, current, confirmed, newKey},
		{"noncanonical version", bytes.Join([][]byte{wire[:2], {0x18, 0x01}, wire[3:]}, nil), previous, current, confirmed, newKey},
		{"over size limit", make([]byte, removalCheckpointMaxEnvelopeSize+1), previous, current, confirmed, newKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := OpenRemovalCheckpoint(test.wire, test.previous, test.current, test.fingerprint, test.key); err == nil || got != nil {
				t.Fatal("opened an invalid removal checkpoint")
			}
		})
	}
}

func removalCheckpointTestSpace(t *testing.T) (previous, current []byte, confirmed [32]byte, keys *SpaceKeys, peer *DeviceKeys) {
	t.Helper()
	initial, confirmed, keys, err := NewSpace()
	checkRemovalCheckpointError(t, err)
	peer, err = generateDeviceKeys()
	checkRemovalCheckpointError(t, err)
	member := Member{DeviceID: randomID(), SigningPub: [32]byte(peer.signing.Public().(ed25519.PublicKey)),
		ExchangePub: [32]byte(peer.exchange.PublicKey().Bytes())}
	previous, err = keys.AddMember(initial, confirmed, member)
	checkRemovalCheckpointError(t, err)
	current, err = keys.RemoveMember(previous, confirmed, member.DeviceID)
	checkRemovalCheckpointError(t, err)
	return
}

func checkRemovalCheckpointError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
