package syncwire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"password-saver/internal/syncmerge"
)

const (
	maxReplayPending      = 64
	maxReplayPendingBytes = 256 << 10
)

// ErrReplayPendingLimit indicates that the unresolved envelopes exceed a replay quota.
var ErrReplayPendingLimit = errors.New("replay pending envelope quota exceeded")

// WriterHead records the last accepted sequence and envelope hash in the new epoch.
type WriterHead struct {
	Seq  uint64
	Hash [32]byte
}

// ReplayResult owns the restored snapshot, writer heads and exact unresolved bytes.
type ReplayResult struct {
	Snapshot []syncmerge.Record
	Heads    map[[16]byte]WriterHead
	Pending  [][]byte
}

// Replay restores an authenticated checkpoint and submits the journal in order.
// It retries waiting envelopes after progress and returns a zero result on error.
func Replay(checkpoint []byte, journal [][]byte, spaceID [16]byte, epoch uint64, epochKey []byte, signers map[[16]byte]ed25519.PublicKey) (ReplayResult, error) {
	receiver, err := RestoreCheckpoint(checkpoint, spaceID, epoch, epochKey, signers)
	if err != nil {
		return ReplayResult{}, err
	}
	queue := replayQueue{ids: make(map[string]struct{})}
	for i, wire := range journal {
		before := len(receiver.accepted)
		outcome := receiver.Receive(wire)
		switch outcome.Status {
		case syncmerge.Waiting:
			if err := queue.hold(i+1, wire, outcome.ID); err != nil {
				return ReplayResult{}, fmt.Errorf("replay envelope %d: %w", i+1, err)
			}
		case syncmerge.Applied:
			if len(receiver.accepted) > before {
				if err := queue.retry(receiver); err != nil {
					return ReplayResult{}, err
				}
			}
		default:
			return ReplayResult{}, fmt.Errorf("replay envelope %d: %w", i+1, outcome.Err)
		}
	}
	result := ReplayResult{Snapshot: receiver.Snapshot(), Heads: make(map[[16]byte]WriterHead)}
	for writer, chain := range receiver.chains {
		if chain.seq > 0 {
			result.Heads[writer] = WriterHead{Seq: chain.seq, Hash: chain.hash}
		}
	}
	for _, pending := range queue.envelopes {
		result.Pending = append(result.Pending, bytes.Clone(pending.wire))
	}
	return result, nil
}

type pendingEnvelope struct {
	position int
	wire     []byte
}

type replayQueue struct {
	envelopes []pendingEnvelope
	ids       map[string]struct{}
	size      int
}

func (q *replayQueue) hold(position int, wire []byte, id string) error {
	if _, duplicate := q.ids[id]; duplicate {
		return nil
	}
	if len(q.envelopes) >= maxReplayPending || len(wire) > maxReplayPendingBytes-q.size {
		return ErrReplayPendingLimit
	}
	q.envelopes = append(q.envelopes, pendingEnvelope{position: position, wire: wire})
	q.ids[id] = struct{}{}
	q.size += len(wire)
	return nil
}

func (q *replayQueue) retry(receiver *Receiver) error {
	for len(q.envelopes) > 0 {
		waiting := q.envelopes[:0]
		for _, pending := range q.envelopes {
			outcome := receiver.Receive(pending.wire)
			switch outcome.Status {
			case syncmerge.Waiting:
				waiting = append(waiting, pending)
			case syncmerge.Applied:
				delete(q.ids, outcome.ID)
				q.size -= len(pending.wire)
			default:
				return fmt.Errorf("retry envelope %d: %w", pending.position, outcome.Err)
			}
		}
		if len(waiting) == len(q.envelopes) {
			break
		}
		clear(q.envelopes[len(waiting):])
		q.envelopes = waiting
	}
	return nil
}
