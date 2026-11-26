package replicastore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

func TestExchangeLegacyReplica(t *testing.T) {
	s, path := newStore(t)
	apply(t, s, put("old", "record", "legacy"), Local, syncmerge.Applied)
	want := read(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, path)
	checkView(t, s, want)
	if err := s.CommitExchange(t.Context(), ExchangeContext{}, 2, nil, 0, 0); !errors.Is(err, ErrExchangeMode) {
		t.Fatalf("enabled exchange on a nonempty replica: %v", err)
	}
}

func TestExchangeCommitAndRollback(t *testing.T) {
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	s, path := newStore(t)
	h := syncwire.Header{Type: 1, Version: 1, SpaceID: [16]byte{1}, Epoch: 2, DeviceID: [16]byte{2}, Seq: 1}
	key := make([]byte, 32)
	signer := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trusted := map[[16]byte]ed25519.PublicKey{h.DeviceID: signer.Public().(ed25519.PublicKey)}
	checkpoint, err := syncwire.NewReceiver(h.SpaceID, 1, key, trusted).MarshalCheckpoint()
	check(err)
	confirmed := ExchangeContext{Binding: ExchangeBinding{SpaceID: h.SpaceID, Epoch: h.Epoch, DeviceID: h.DeviceID,
		CheckpointHash: sha256.Sum256(checkpoint), MembershipHash: sha256.Sum256([]byte("test membership")), RelayURL: "https://relay.example.invalid"},
		Checkpoint: checkpoint, EpochKey: key, Signers: trusted}
	readExchange := func() ExchangeView {
		t.Helper()
		view, err := s.ReadExchange(t.Context(), confirmed)
		check(err)
		return view
	}
	initial := readExchange().Generation
	op := syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put, Data: []byte("saved")}
	wire, digest, err := syncwire.SealOperation(h, op, key, signer)
	check(err)
	entry := ExchangeEnvelope{Wire: wire, CommandID: "first", CommandHash: sha256.Sum256(op.Data), Sequence: 1}
	check(s.CommitExchange(t.Context(), confirmed, initial, []ExchangeEnvelope{entry}, 1, 7))
	check(s.Close())
	s = reopen(t, path)
	saved := readExchange()
	if saved.Generation != initial+1 || !reflect.DeepEqual(saved.State, &ExchangeState{Binding: confirmed.Binding, Journal: []ExchangeEnvelope{entry}, SentSequence: 1, Cursor: 7}) ||
		len(saved.Snapshot) != 1 || string(saved.Snapshot[0].Versions[0].Data) != "saved" || saved.Heads[h.DeviceID].Hash != digest {
		t.Fatal("reopened exchange differs from the committed journal and snapshot")
	}
	if err := s.CommitExchange(t.Context(), confirmed, initial, nil, 1, 8); !errors.Is(err, ErrGeneration) {
		t.Fatalf("stale exchange write: %v", err)
	}
	if _, err := s.Apply(t.Context(), put("old-api", "record", "bypass"), Local); !errors.Is(err, ErrExchangeMode) {
		t.Fatalf("legacy write in exchange mode: %v", err)
	}
	h.Seq, h.PrevHash, op.Parents, op.Data = 2, digest, [][32]byte{digest}, []byte("interrupted")
	wire, _, err = syncwire.SealOperation(h, op, key, signer)
	check(err)
	entry = ExchangeEnvelope{Wire: wire, CommandID: "second", CommandHash: sha256.Sum256(op.Data), Sequence: 2}
	stop := errors.New("synthetic failure before commit")
	s.beforeCommit = func() error { return stop }
	if err := s.CommitExchange(t.Context(), confirmed, saved.Generation, []ExchangeEnvelope{entry}, 2, 8); !errors.Is(err, stop) {
		t.Fatalf("interrupted exchange write: %v", err)
	}
	check(s.Close())
	s = reopen(t, path)
	if !reflect.DeepEqual(readExchange(), saved) {
		t.Fatal("interrupted exchange changed committed journal, progress or generation")
	}
}
