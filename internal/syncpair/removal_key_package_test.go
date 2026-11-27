package syncpair

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"password-saver/internal/syncwire"
)

func TestRemovalKeyPackage(t *testing.T) {
	previous, current, confirmed, keys, revoked := removalCheckpointTestSpace(t)
	membership, err := VerifyRemoval(current, previous, confirmed)
	checkRemovalCheckpointError(t, err)
	h := membership.Header
	snapshot, err := syncwire.NewReceiver(h.SpaceID, h.Epoch-1, make([]byte, 32), nil).MarshalCheckpoint()
	checkRemovalCheckpointError(t, err)
	want, checkpoint, err := keys.SealRemovalCheckpoint(previous, current, confirmed, snapshot)
	checkRemovalCheckpointError(t, err)
	wire, err := keys.SealRemovalKeyPackage(previous, current, confirmed, checkpoint, want)
	checkRemovalCheckpointError(t, err)
	got, err := keys.device.OpenRemovalKeyPackage(wire, previous, current, confirmed, checkpoint)
	checkRemovalCheckpointError(t, err)
	if got != want {
		t.Fatal("opened the wrong epoch key")
	}
	receiver, err := OpenRemovalCheckpoint(checkpoint, previous, current, confirmed, got)
	checkRemovalCheckpointError(t, err)
	if len(receiver.Snapshot()) != 0 {
		t.Fatal("expected the empty checkpoint to be restored")
	}

	otherKey, otherCheckpoint, err := keys.SealRemovalCheckpoint(previous, current, confirmed, snapshot)
	checkRemovalCheckpointError(t, err)
	_, _, _, otherKeys, _ := removalCheckpointTestSpace(t)
	for _, test := range []struct {
		name  string
		keys  *SpaceKeys
		epoch [32]byte
	}{
		{"wrong checkpoint key", keys, otherKey},
		{"foreign controller", otherKeys, want},
	} {
		t.Run(test.name, func(t *testing.T) {
			if pkg, err := test.keys.SealRemovalKeyPackage(previous, current, confirmed, checkpoint, test.epoch); err == nil || pkg != nil {
				t.Fatal("issued a package for invalid input")
			}
		})
	}

	predecessor, err := VerifySignedMembership(previous, confirmed)
	checkRemovalCheckpointError(t, err)
	pinned := predecessor.Header
	pinned.PrevHash[0] ^= 1
	alternatePrevious, err := signMembership(pinned, keys.controller)
	checkRemovalCheckpointError(t, err)
	peerID := pinned.Members[1].DeviceID
	alternateCurrent, err := keys.RemoveMember(alternatePrevious, confirmed, peerID)
	checkRemovalCheckpointError(t, err)
	pinned.Revision++
	pinned.Epoch++
	laterPrevious, err := signMembership(pinned, keys.controller)
	checkRemovalCheckpointError(t, err)
	laterCurrent, err := keys.RemoveMember(laterPrevious, confirmed, peerID)
	checkRemovalCheckpointError(t, err)
	laterSnapshot, err := syncwire.NewReceiver(h.SpaceID, h.Epoch, make([]byte, 32), nil).MarshalCheckpoint()
	checkRemovalCheckpointError(t, err)
	_, laterCheckpoint, err := keys.SealRemovalCheckpoint(laterPrevious, laterCurrent, confirmed, laterSnapshot)
	checkRemovalCheckpointError(t, err)

	var pkg signedRemovalKeyPackage
	checkRemovalCheckpointError(t, decodeCanonicalPairing(wire, &pkg))
	change := func(mutate func(*signedRemovalKeyPackage), resign bool) []byte {
		t.Helper()
		modified := pkg
		modified.Ciphertext = bytes.Clone(pkg.Ciphertext)
		mutate(&modified)
		if resign {
			message, err := modified.signatureInput()
			checkRemovalCheckpointError(t, err)
			modified.Signature = [ed25519.SignatureSize]byte(ed25519.Sign(keys.controller, message))
		}
		encoded, err := encMode.Marshal(modified)
		checkRemovalCheckpointError(t, err)
		return encoded
	}
	modifiedEpoch := change(func(p *signedRemovalKeyPackage) { p.Header.Epoch++ }, true)
	modifiedRecipient := change(func(p *signedRemovalKeyPackage) { p.Header.RecipientID[0] ^= 1 }, true)
	modifiedSignature := change(func(p *signedRemovalKeyPackage) { p.Signature[0] ^= 1 }, false)
	modifiedEnc := change(func(p *signedRemovalKeyPackage) { p.Enc[0] ^= 1 }, false)
	modifiedCiphertext := change(func(p *signedRemovalKeyPackage) { p.Ciphertext[0] ^= 1 }, false)
	resignedCiphertext := change(func(p *signedRemovalKeyPackage) { p.Ciphertext[0] ^= 1 }, true)
	reboundCheckpoint := change(func(p *signedRemovalKeyPackage) { p.Header.CheckpointHash = sha256.Sum256(otherCheckpoint) }, true)
	shortCiphertext := change(func(p *signedRemovalKeyPackage) { p.Ciphertext = p.Ciphertext[:31+16] }, true)
	noncanonical := bytes.Join([][]byte{wire[:2], {0x18, 0x01}, wire[3:]}, nil)
	for _, test := range []struct {
		name                                string
		device                              *DeviceKeys
		wire, previous, current, checkpoint []byte
	}{
		{"revoked device", revoked, wire, previous, current, checkpoint},
		{"substituted membership", keys.device, wire, alternatePrevious, alternateCurrent, checkpoint},
		{"another removal", keys.device, wire, laterPrevious, laterCurrent, laterCheckpoint},
		{"substituted checkpoint", keys.device, wire, previous, current, otherCheckpoint},
		{"changed epoch", keys.device, modifiedEpoch, previous, current, checkpoint},
		{"changed recipient ID", keys.device, modifiedRecipient, previous, current, checkpoint},
		{"damaged signature", keys.device, modifiedSignature, previous, current, checkpoint},
		{"changed encapsulation", keys.device, modifiedEnc, previous, current, checkpoint},
		{"changed ciphertext", keys.device, modifiedCiphertext, previous, current, checkpoint},
		{"signed damaged ciphertext", keys.device, resignedCiphertext, previous, current, checkpoint},
		{"signed changed checkpoint hash", keys.device, reboundCheckpoint, previous, current, otherCheckpoint},
		{"short ciphertext", keys.device, shortCiphertext, previous, current, checkpoint},
		{"noncanonical version", keys.device, noncanonical, previous, current, checkpoint},
		{"over size limit", keys.device, make([]byte, removalKeyPackageMaxSize+1), previous, current, checkpoint},
	} {
		t.Run(test.name, func(t *testing.T) {
			if key, err := test.device.OpenRemovalKeyPackage(test.wire, test.previous, test.current, confirmed, test.checkpoint); err == nil || key != [32]byte{} {
				t.Fatal("opened an invalid removal key package")
			}
		})
	}
}
