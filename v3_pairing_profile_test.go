package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	cryptov2 "password-saver/crypto/v2"
)

func TestV3PairingProfileReopen(t *testing.T) {
	dir := t.TempDir()
	profile, err := openV3PairingProfile(dir, migrationEngine(t))
	if err != nil {
		t.Fatal(err)
	}
	id := [16]byte{1}
	keys := v3PairingPrivateKeys{SigningSeed: bytes.Repeat([]byte{2}, 32), ExchangePrivate: bytes.Repeat([]byte{3}, 32)}
	answer := []byte{0, 1, 0xff, 0}
	states := []v3PairingState{
		{RequestID: id, Pending: &v3PairingPending{Request: []byte("signed request"), Keys: keys}},
		{RequestID: id, IssuedAnswer: answer},
		{RequestID: id, Accepted: &v3PairingAccepted{Membership: []byte("signed membership"), AnswerHash: sha256.Sum256(answer),
			EpochKey: bytes.Repeat([]byte{4}, 32), Checkpoint: []byte("checkpoint"), Keys: keys}},
	}
	var revision [sha256.Size]byte
	for _, want := range states {
		previous := revision
		revision, err = profile.save(migrationTestPassword, previous, want, nil)
		if err != nil || revision == previous {
			t.Fatalf("save revision: %v", err)
		}
		reopened, err := openV3PairingProfile(dir, migrationEngine(t))
		if err != nil {
			t.Fatal(err)
		}
		got, readRevision, err := reopened.read(migrationTestPassword)
		if err != nil || readRevision != revision || !reflect.DeepEqual(got, want) {
			t.Fatalf("reopening did not recover the exact state and revision: %v", err)
		}
		got.wipe()
	}
}

func TestV3PairingProfileRejectsUnsafeReplacement(t *testing.T) {
	profile, err := openV3PairingProfile(t.TempDir(), migrationEngine(t))
	if err != nil {
		t.Fatal(err)
	}
	state := v3PairingState{RequestID: [16]byte{1}, IssuedAnswer: []byte("first answer")}
	old, err := profile.save(migrationTestPassword, [32]byte{}, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldFile := readPasswordChangeTestFile(t, profile.path)
	state.IssuedAnswer = []byte("second answer")
	revision, err := profile.save(migrationTestPassword, old, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := readPasswordChangeTestFile(t, profile.path)
	const wrongPassword = "synthetic-incorrect-password"
	if _, _, err := profile.read(wrongPassword); !errors.Is(err, cryptov2.ErrAuthentication) {
		t.Fatalf("wrong password read: %v", err)
	}
	state.IssuedAnswer = []byte("uncommitted answer")
	if _, err := profile.save(wrongPassword, revision, state, nil); !errors.Is(err, cryptov2.ErrAuthentication) {
		t.Fatalf("wrong password replacement: %v", err)
	}
	if _, err := profile.save(migrationTestPassword, old, state, nil); !errors.Is(err, errV3PairingChanged) {
		t.Fatalf("stale revision replacement: %v", err)
	}
	interrupted := errors.New("synthetic interruption before replace")
	if _, err := profile.save(migrationTestPassword, revision, state, func() error { return interrupted }); !errors.Is(err, interrupted) {
		t.Fatalf("interrupted replacement: %v", err)
	}
	if !bytes.Equal(readPasswordChangeTestFile(t, profile.path), previous) {
		t.Fatal("a failed replacement changed the previous encrypted state")
	}
	if _, err := profile.save(migrationTestPassword, revision, state, func() error { return writeFileAtomic(profile.path, oldFile) }); !errors.Is(err, errV3PairingChanged) || !bytes.Equal(readPasswordChangeTestFile(t, profile.path), oldFile) {
		t.Fatalf("replacement did not preserve a change made before rename: %v", err)
	}
}
