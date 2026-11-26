package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"password-saver/internal/syncmerge"
)

type replayFixture struct {
	header     Header
	key        []byte
	signer     ed25519.PrivateKey
	trusted    map[[16]byte]ed25519.PublicKey
	checkpoint []byte
	recordID   [16]byte
	oldHash    [32]byte
}

func newReplayFixture(t *testing.T) replayFixture {
	t.Helper()
	h := exampleEnvelope().Header
	key, signer := testChangeKeys()
	trusted := map[[16]byte]ed25519.PublicKey{h.DeviceID: signer.Public().(ed25519.PublicKey)}
	source := NewReceiver(h.SpaceID, h.Epoch, key, trusted)
	recordID := [16]byte{7}
	old, oldHash := mustSealOperation(t, h, LocalOperation{RecordID: recordID, Action: syncmerge.Put, Data: []byte("base")}, key, signer)
	requireReceive(t, source, old, syncmerge.Applied)
	checkpoint, err := source.MarshalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	h.Epoch++
	key[0] ^= 1
	return replayFixture{header: h, key: key, signer: signer, trusted: trusted, checkpoint: checkpoint, recordID: recordID, oldHash: oldHash}
}

func (f replayFixture) replay(journal ...[]byte) (ReplayResult, error) {
	return Replay(f.checkpoint, journal, f.header.SpaceID, f.header.Epoch, f.key, f.trusted)
}

func (f replayFixture) seal(t *testing.T, seq uint64, prev, parent [32]byte, data []byte) ([]byte, [32]byte) {
	t.Helper()
	h := f.header
	h.Seq, h.PrevHash = seq, prev
	return mustSealOperation(t, h, LocalOperation{RecordID: f.recordID, Parents: [][32]byte{parent}, Action: syncmerge.Put, Data: data}, f.key, f.signer)
}

func TestReplayResolvesWaitingAfterReopen(t *testing.T) {
	f := newReplayFixture(t)
	parent, parentHash := f.seal(t, 1, [32]byte{}, f.oldHash, []byte("parent"))
	child, childHash := f.seal(t, 2, parentHash, parentHash, []byte("child"))
	grandchild, grandchildHash := f.seal(t, 3, childHash, childHash, []byte("grandchild"))
	input := bytes.Clone(grandchild)
	waiting, err := f.replay(input, child, child)
	if err != nil || len(waiting.Pending) != 2 || len(waiting.Heads) != 0 {
		t.Fatalf("waiting replay: %d pending, heads %v, error %v", len(waiting.Pending), waiting.Heads, err)
	}
	input[0] ^= 1
	if !bytes.Equal(waiting.Pending[0], grandchild) || !bytes.Equal(waiting.Pending[1], child) {
		t.Fatal("pending envelopes were reordered or did not retain the exact input bytes")
	}
	if len(waiting.Snapshot) != 1 || len(waiting.Snapshot[0].Versions) != 1 ||
		waiting.Snapshot[0].Versions[0].ID != hex.EncodeToString(f.oldHash[:]) {
		t.Fatalf("waiting replay changed the checkpoint snapshot: %+v", waiting.Snapshot)
	}
	reopened, err := f.replay(append(waiting.Pending, parent)...)
	if err != nil || len(reopened.Pending) != 0 || len(reopened.Heads) != 1 ||
		reopened.Heads[f.header.DeviceID] != (WriterHead{Seq: 3, Hash: grandchildHash}) {
		t.Fatalf("reopened replay: %d pending, heads %v, error %v", len(reopened.Pending), reopened.Heads, err)
	}
	if len(reopened.Snapshot) != 1 || len(reopened.Snapshot[0].Versions) != 1 {
		t.Fatalf("unexpected replay snapshot: %+v", reopened.Snapshot)
	}
	got := reopened.Snapshot[0].Versions[0]
	if got.ID != hex.EncodeToString(grandchildHash[:]) || string(got.Data) != "grandchild" || got.Action != syncmerge.Put {
		t.Fatalf("unexpected replay version: %+v", got)
	}
}

func TestReplayRejectsWithoutPartialResult(t *testing.T) {
	f := newReplayFixture(t)
	parent, parentHash := f.seal(t, 1, [32]byte{}, f.oldHash, []byte("parent"))
	fork, _ := f.seal(t, 1, [32]byte{}, f.oldHash, []byte("fork"))
	waiting, _ := f.seal(t, 2, [32]byte{1}, parentHash, []byte("wrong previous hash"))
	unsigned := bytes.Clone(parent)
	unsigned[len(unsigned)-1] ^= 1
	for _, test := range []struct {
		name    string
		journal [][]byte
		cause   error
	}{
		{"fork", [][]byte{parent, fork}, ErrChangeFork},
		{"signature", [][]byte{parent, unsigned}, errChangeSignature},
		{"rejected on retry", [][]byte{waiting, parent}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := f.replay(test.journal...)
			if err == nil || (test.cause != nil && !errors.Is(err, test.cause)) ||
				result.Snapshot != nil || result.Heads != nil || result.Pending != nil {
				t.Fatalf("replay returned a partial result or wrong error: %+v, %v", result, err)
			}
		})
	}
}

func TestReplayPendingLimits(t *testing.T) {
	f := newReplayFixture(t)
	for _, test := range []struct {
		name   string
		count  int
		length int
	}{{"envelopes", 64, 0}, {"bytes", 4, 60 << 10}} {
		t.Run(test.name, func(t *testing.T) {
			journal := make([][]byte, test.count+1)
			data := make([]byte, test.length)
			for i := range journal {
				journal[i], _ = f.seal(t, uint64(i)+2, [32]byte{1}, f.oldHash, data)
			}
			if result, err := f.replay(journal[:test.count]...); err != nil || len(result.Pending) != test.count {
				t.Fatalf("replay within quota: %d pending, error %v", len(result.Pending), err)
			}
			if result, err := f.replay(journal...); !errors.Is(err, ErrReplayPendingLimit) ||
				result.Snapshot != nil || result.Heads != nil || result.Pending != nil {
				t.Fatalf("replay over quota: %d pending, error %v", len(result.Pending), err)
			}
		})
	}
}

func TestReplayReleasesQuotaAfterProgress(t *testing.T) {
	f := newReplayFixture(t)
	parent, lastHash := f.seal(t, 1, [32]byte{}, f.oldHash, nil)
	data := make([]byte, 60<<10)
	var journal [][]byte
	for seq := uint64(2); seq <= 5; seq++ {
		wire, digest := f.seal(t, seq, lastHash, lastHash, data)
		journal = append(journal, wire)
		lastHash = digest
	}
	blocked, _ := f.seal(t, 8, [32]byte{1}, f.oldHash, nil)
	later, _ := f.seal(t, 7, [32]byte{1}, f.oldHash, data)
	result, err := f.replay(append(journal, blocked, parent, later)...)
	if err != nil || len(result.Pending) != 2 || !bytes.Equal(result.Pending[0], blocked) || !bytes.Equal(result.Pending[1], later) ||
		result.Heads[f.header.DeviceID] != (WriterHead{Seq: 5, Hash: lastHash}) {
		t.Fatalf("replay after freeing quota: %d pending, heads %v, error %v", len(result.Pending), result.Heads, err)
	}
}
