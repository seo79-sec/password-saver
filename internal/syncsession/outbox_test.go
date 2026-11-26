package syncsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
	"password-saver/internal/syncwire"
)

var queueTestKey = [replicastore.KeySize]byte{1, 2, 3}

func queueFixture(t *testing.T) (*replicastore.Store, string, replicastore.ExchangeContext, ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "queue.sqlite")
	store, err := replicastore.Create(t.Context(), path, queueTestKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	space, device := [16]byte{1}, [16]byte{2}
	key := make([]byte, 32)
	signer := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signers := map[[16]byte]ed25519.PublicKey{device: signer.Public().(ed25519.PublicKey)}
	checkpoint, err := syncwire.NewReceiver(space, 1, key, signers).MarshalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	confirmed := replicastore.ExchangeContext{
		Binding: replicastore.ExchangeBinding{SpaceID: space, DeviceID: device, Epoch: 2, RelayURL: "https://relay.example.invalid",
			MembershipHash: sha256.Sum256([]byte("synthetic membership")), CheckpointHash: sha256.Sum256(checkpoint)},
		Checkpoint: checkpoint, EpochKey: key, Signers: signers,
	}
	view := readQueue(t, store, confirmed)
	if err := store.CommitExchange(t.Context(), confirmed, view.Generation, nil, 0, 7); err != nil {
		t.Fatal(err)
	}
	return store, path, confirmed, signer
}

func readQueue(t *testing.T, store *replicastore.Store, confirmed replicastore.ExchangeContext) replicastore.ExchangeView {
	t.Helper()
	view, err := store.ReadExchange(t.Context(), confirmed)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func TestQueueLocalOfflineAndReopen(t *testing.T) {
	store, path, confirmed, signer := queueFixture(t)
	op := syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put, Data: []byte("offline change")}
	initial := readQueue(t, store, confirmed)
	missingParent := op
	missingParent.Parents = [][32]byte{{1}}
	if wire, err := QueueLocal(t.Context(), store, confirmed, signer, "missing", missingParent); err == nil || wire != nil {
		t.Fatalf("queued an unresolved local operation: %v", err)
	}
	wire, err := QueueLocal(t.Context(), store, confirmed, signer, "first", op)
	if err != nil {
		t.Fatal(err)
	}
	saved := readQueue(t, store, confirmed)
	if saved.Generation != initial.Generation+1 || saved.State.Cursor != 7 || saved.State.SentSequence != 0 ||
		len(saved.State.Journal) != 1 || !bytes.Equal(saved.State.Journal[0].Wire, wire) || saved.State.Journal[0].CommandID != "first" ||
		len(saved.Snapshot) != 1 || string(saved.Snapshot[0].Versions[0].Data) != "offline change" {
		t.Fatal("local change and envelope were not committed together")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = replicastore.Open(t.Context(), path, queueTestKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	op.Parents = [][32]byte{}
	repeated, err := QueueLocal(t.Context(), store, confirmed, signer, "first", op)
	if err != nil || !bytes.Equal(repeated, wire) {
		t.Fatalf("retry after reopening returned different bytes: %v", err)
	}
	op.Data = []byte("different change")
	if _, err := QueueLocal(t.Context(), store, confirmed, signer, "first", op); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("reused command ID: %v", err)
	}
	if readQueue(t, store, confirmed).Generation != saved.Generation {
		t.Fatal("retry or conflict advanced the generation")
	}
	previous := sha256.Sum256(wire)
	op.Action, op.Parents, op.Data = syncmerge.Delete, [][32]byte{previous}, nil
	deleted, err := QueueLocal(t.Context(), store, confirmed, signer, "delete", op)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := syncwire.Parse(deleted)
	if err != nil || envelope.Header.Seq != 2 || envelope.Header.PrevHash != previous {
		t.Fatalf("wrong writer position for delete: %+v, %v", envelope.Header, err)
	}
}

type uncertainExchange struct {
	*replicastore.Store
	commits bool
	reads   int
}

func (s *uncertainExchange) ReadExchange(ctx context.Context, confirmed replicastore.ExchangeContext) (replicastore.ExchangeView, error) {
	s.reads++
	return s.Store.ReadExchange(ctx, confirmed)
}

func (s *uncertainExchange) CommitExchange(ctx context.Context, confirmed replicastore.ExchangeContext, generation int64, entries []replicastore.ExchangeEnvelope, sent, cursor uint64) error {
	if s.commits {
		if err := s.Store.CommitExchange(ctx, confirmed, generation, entries, sent, cursor); err != nil {
			return err
		}
	}
	return replicastore.ErrCommitUnknown
}

func TestQueueLocalResolvesUnknownCommit(t *testing.T) {
	for _, test := range []struct {
		name    string
		commits bool
	}{{"failure immediately after commit", true}, {"commit not recorded", false}} {
		t.Run(test.name, func(t *testing.T) {
			store, _, confirmed, signer := queueFixture(t)
			s := &uncertainExchange{Store: store, commits: test.commits}
			op := syncwire.LocalOperation{RecordID: [16]byte{3}, Action: syncmerge.Put}
			wire, err := QueueLocal(t.Context(), s, confirmed, signer, "maybe committed", op)
			if s.reads != 2 {
				t.Fatalf("expected a reread after uncertain commit, got %d reads", s.reads)
			}
			journal := readQueue(t, store, confirmed).State.Journal
			if test.commits {
				if err != nil || len(journal) != 1 || !bytes.Equal(wire, journal[0].Wire) {
					t.Fatalf("did not recover exact committed bytes: %v", err)
				}
			} else if !errors.Is(err, replicastore.ErrCommitUnknown) || wire != nil || len(journal) != 0 {
				t.Fatalf("returned an envelope whose commit was not confirmed: %v", err)
			}
		})
	}
}
