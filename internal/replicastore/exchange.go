package replicastore

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"unicode/utf8"

	"password-saver/internal/syncwire"
)

const (
	maxExchangeEnvelopes = 4096
	maxExchangeWireBytes = 4 << 20
)

var (
	// ErrExchangeDisconnected means the binding is retained for local reads only.
	ErrExchangeDisconnected = errors.New("replica exchange is disconnected")
	ErrExchangeMode         = errors.New("replica requires the exchange transaction or is not empty")
	ErrGeneration           = errors.New("replica generation changed")
	ErrExchange             = errors.New("invalid replica exchange state or binding")
)

type ExchangeBinding struct {
	SpaceID, DeviceID              [16]byte
	Epoch                          uint64
	MembershipHash, CheckpointHash [32]byte
	RelayURL                       string
}

// ExchangeEnvelope carries command metadata only for local changes.
type ExchangeEnvelope struct {
	Wire        []byte
	CommandID   string
	CommandHash [32]byte
	Sequence    uint64
}

type ExchangeState struct {
	Binding              ExchangeBinding
	Journal              []ExchangeEnvelope
	SentSequence, Cursor uint64
	Removal              *RemovalCandidate `json:",omitempty"`
	ActivatedRemoval     *ActivatedRemoval `json:",omitempty"`
	Disconnected         bool              `json:",omitempty"`
}

// ExchangeContext supplies the confirmed binding, checkpoint and keys for replay.
type ExchangeContext struct {
	Binding    ExchangeBinding
	Checkpoint []byte
	EpochKey   []byte
	Signers    map[[16]byte]ed25519.PublicKey
}

type ExchangeView struct {
	Generation int64
	State      *ExchangeState
	syncwire.ReplayResult
}

func (e *ExchangeState) validate() (uint64, error) {
	b := e.Binding
	if b.SpaceID == [16]byte{} || b.DeviceID == [16]byte{} || b.Epoch < 2 || b.RelayURL == "" ||
		b.MembershipHash == [32]byte{} || b.CheckpointHash == [32]byte{} {
		return 0, ErrExchange
	}
	if len(e.Journal) > maxExchangeEnvelopes {
		return 0, ErrLimit
	}
	size, sequence := 0, uint64(0)
	if e.Removal != nil {
		if err := e.Removal.validate(); err != nil {
			return 0, err
		}
	}
	if e.ActivatedRemoval != nil {
		active := e.ActivatedRemoval
		if err := active.Transition.validate(); err != nil {
			return 0, err
		}
		if e.Removal != nil || active.ID != sha256.Sum256(active.Transition.Checkpoint) ||
			b.MembershipHash != sha256.Sum256(active.Transition.Membership) || active.SigningPub == [32]byte{} ||
			active.Previous.MembershipHash != sha256.Sum256(active.PreviousMembership) {
			return 0, ErrExchange
		}
	}
	commands := make(map[string]bool)
	for _, entry := range e.Journal {
		if len(entry.Wire) > maxExchangeWireBytes-size {
			return 0, ErrLimit
		}
		size += len(entry.Wire)
		if entry.CommandID == "" {
			if entry.Sequence != 0 || entry.CommandHash != [32]byte{} {
				return 0, ErrExchange
			}
			continue
		}
		sequence++
		wire, err := syncwire.Parse(entry.Wire)
		if err != nil || wire.Header.DeviceID != b.DeviceID || wire.Header.Seq != sequence || entry.Sequence != sequence ||
			entry.CommandHash == [32]byte{} || commands[entry.CommandID] || len(entry.CommandID) > maxIDBytes || !utf8.ValidString(entry.CommandID) {
			return 0, ErrExchange
		}
		commands[entry.CommandID] = true
	}
	if e.SentSequence > sequence {
		return 0, ErrExchange
	}
	return sequence, nil
}

func (e *ExchangeState) replay(confirmed ExchangeContext) (syncwire.ReplayResult, error) {
	b := e.Binding
	if e.ActivatedRemoval != nil {
		if e.ActivatedRemoval.EpochKeyHash != sha256.Sum256(confirmed.EpochKey) {
			return syncwire.ReplayResult{}, ErrExchange
		}
		confirmed.Signers = map[[16]byte]ed25519.PublicKey{b.DeviceID: e.ActivatedRemoval.SigningPub[:]}
	}
	if b != confirmed.Binding || b.CheckpointHash != sha256.Sum256(confirmed.Checkpoint) ||
		len(confirmed.EpochKey) != 32 || len(confirmed.Signers[b.DeviceID]) != ed25519.PublicKeySize {
		return syncwire.ReplayResult{}, ErrExchange
	}
	sequence, err := e.validate()
	if err != nil {
		return syncwire.ReplayResult{}, err
	}
	journal := make([][]byte, len(e.Journal))
	for i, entry := range e.Journal {
		journal[i] = entry.Wire
	}
	result, err := syncwire.Replay(confirmed.Checkpoint, journal, b.SpaceID, b.Epoch, confirmed.EpochKey, confirmed.Signers)
	if err == nil && result.Heads[b.DeviceID].Seq != sequence {
		return syncwire.ReplayResult{}, ErrExchange
	}
	return result, err
}

// ReadExchange returns the generation and rebuilds the snapshot of an enabled replica.
func (s *Store) ReadExchange(ctx context.Context, confirmed ExchangeContext) (ExchangeView, error) {
	generation, data, _, err := s.readState(ctx)
	if err != nil || data.Exchange == nil {
		return ExchangeView{Generation: generation}, err
	}
	replayed, err := data.Exchange.replay(confirmed)
	if err != nil {
		return ExchangeView{}, err
	}
	return ExchangeView{Generation: generation, State: data.Exchange, ReplayResult: replayed}, nil
}

// CommitExchange enables exchange on an empty replica or appends to its journal
// and advances its progress. The caller passes the generation read previously.
func (s *Store) CommitExchange(ctx context.Context, confirmed ExchangeContext, expected int64, entries []ExchangeEnvelope, sent, cursor uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, _, err := s.load(ctx, tx)
	if err != nil {
		return storageError(err)
	}
	if identity != s.identity {
		return ErrAuthentication
	}
	if data.Exchange != nil && data.Exchange.Disconnected {
		return ErrExchangeDisconnected
	}
	if data.Exchange != nil && data.Exchange.Removal != nil {
		return ErrRemovalStaged
	}
	if generation != expected {
		return ErrGeneration
	}
	if generation == math.MaxInt64 || len(entries) > maxExchangeEnvelopes {
		return ErrLimit
	}
	if data.Exchange == nil {
		if !data.emptyLegacy() {
			return ErrExchangeMode
		}
		data.Exchange = &ExchangeState{Binding: confirmed.Binding}
	}
	e := data.Exchange
	if sent < e.SentSequence || cursor < e.Cursor {
		return ErrExchange
	}
	e.Journal = append(e.Journal, entries...)
	e.SentSequence, e.Cursor = sent, cursor
	if _, err := e.replay(confirmed); err != nil {
		return err
	}
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return storageError(err)
	}
	return s.commit(tx)
}

// DisconnectExchange durably stops exchange while keeping the replica readable.
func (s *Store) DisconnectExchange(ctx context.Context, binding ExchangeBinding, expectedGeneration int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, _, err := s.load(ctx, tx)
	if err != nil {
		return storageError(err)
	}
	if identity != s.identity {
		return ErrAuthentication
	}
	exchange := data.Exchange
	if exchange == nil || exchange.Binding != binding {
		return ErrExchange
	}
	// A lost commit response leaves the caller with the preceding generation.
	if expectedGeneration != generation && (!exchange.Disconnected || expectedGeneration != generation-1) {
		return ErrGeneration
	}
	if exchange.Disconnected {
		return nil
	}
	if generation == math.MaxInt64 {
		return ErrLimit
	}
	exchange.Disconnected = true
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return storageError(err)
	}
	return s.commit(tx)
}
