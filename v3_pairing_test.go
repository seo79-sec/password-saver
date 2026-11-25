package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncpair"
	"password-saver/internal/syncwire"
)

func TestV3PairingFileExchange(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ownerDir, recipientDir, transferDir := t.TempDir(), t.TempDir(), t.TempDir()
	engine := migrationEngine(t)
	owner, err := openV3PairingProfile(ownerDir, engine)
	check(err)
	recipient, err := openV3PairingProfile(recipientDir, engine)
	check(err)
	initial, controllerFP, controller, err := syncpair.NewSpace()
	check(err)
	base, err := syncpair.VerifyMembership(initial, nil, controllerFP)
	check(err)
	h, member := base.Header, base.Header.Members[0]
	epochKey := bytes.Repeat([]byte{0x2a}, 32)
	source := syncwire.NewReceiver(h.SpaceID, h.Epoch, epochKey, map[[16]byte]ed25519.PublicKey{member.DeviceID: member.SigningPub[:]})
	plain, err := cbor.Marshal([]any{[16]byte{1}, [][32]byte{}, 1, []byte("synthetic record")})
	check(err)
	envelope, err := syncwire.Seal(syncwire.Header{Type: 1, Version: 1, SpaceID: h.SpaceID, Epoch: h.Epoch, DeviceID: member.DeviceID, Seq: 1}, plain, epochKey, controller.DeviceSigningKey())
	check(err)
	change, err := syncwire.Marshal(envelope)
	check(err)
	if got := source.Receive(change); got.Status != syncmerge.Applied {
		t.Fatalf("seed synthetic source: %+v", got)
	}
	now := time.Unix(1_700_000_000, 0)
	request, requestFP, err := recipient.beginPairing(migrationTestPassword, controllerFP, now)
	check(err)
	requestPath, answerPath := filepath.Join(transferDir, "request.cbor"), filepath.Join(transferDir, "answer.cbor")
	check(os.WriteFile(requestPath, request, 0600))
	request = readPasswordChangeTestFile(t, requestPath)
	if _, err := owner.issuePairingAnswer(migrationTestPassword, controller, initial, request, [32]byte{}, source, now); !errors.Is(err, errV3PairingFingerprint) {
		t.Fatalf("unconfirmed request: %v", err)
	}
	answer, err := owner.issuePairingAnswer(migrationTestPassword, controller, initial, request, requestFP, source, now)
	check(err)
	check(os.WriteFile(answerPath, answer, 0600))
	answer = readPasswordChangeTestFile(t, answerPath)
	recipient, err = openV3PairingProfile(recipientDir, migrationEngine(t))
	check(err)
	if _, err := recipient.acceptPairingAnswer(migrationTestPassword, answer, [32]byte{}, now); err == nil {
		t.Fatal("accepted an unconfirmed controller")
	}
	occupied := filepath.Join(recipientDir, "existing-file")
	check(os.WriteFile(occupied, []byte("synthetic existing data"), 0600))
	if _, err := recipient.acceptPairingAnswer(migrationTestPassword, answer, controllerFP, now); !errors.Is(err, errV3PairingDestination) {
		t.Fatalf("nonempty destination: %v", err)
	}
	check(os.Remove(occupied))
	joined, err := recipient.acceptPairingAnswer(migrationTestPassword, answer, controllerFP, now)
	check(err)
	if !reflect.DeepEqual(joined.Snapshot(), source.Snapshot()) {
		t.Fatal("the imported snapshot differs from the owner's snapshot")
	}
	recipient, err = openV3PairingProfile(recipientDir, migrationEngine(t))
	check(err)
	owner, err = openV3PairingProfile(ownerDir, migrationEngine(t))
	check(err)
	later := now.Add(time.Hour)
	reissued, err := owner.issuePairingAnswer(migrationTestPassword, nil, nil, request, requestFP, nil, later)
	if err != nil || !bytes.Equal(reissued, answer) {
		t.Fatalf("exact reissue after reopening: %v", err)
	}
	reopened, err := recipient.acceptPairingAnswer(migrationTestPassword, answer, controllerFP, later)
	if err != nil || !reflect.DeepEqual(reopened.Snapshot(), joined.Snapshot()) {
		t.Fatalf("exact acceptance after reopening: %v", err)
	}
	answer[len(answer)-1] ^= 1
	if _, err := recipient.acceptPairingAnswer(migrationTestPassword, answer, controllerFP, later); !errors.Is(err, errV3PairingReplay) {
		t.Fatalf("another answer for this request: %v", err)
	}
	request[len(request)-1] ^= 1
	if _, err := owner.issuePairingAnswer(migrationTestPassword, nil, nil, request, sha256.Sum256(request), nil, later); !errors.Is(err, errV3PairingReplay) {
		t.Fatalf("different request bytes: %v", err)
	}
}
