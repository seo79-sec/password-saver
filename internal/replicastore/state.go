package replicastore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"

	"password-saver/internal/syncmerge"
)

const (
	maxIDBytes       = 128
	maxParents       = 32
	maxOperationSize = 64 << 10
	maxPending       = 64
	maxPendingBytes  = 256 << 10
	maxHistory       = 4096
	maxHistoryBytes  = 8 << 20
	maxStateSize     = 10 << 20
)

var ErrLimit = errors.New("replica storage limit reached")

type Source uint8

const (
	Incoming Source = iota
	Local
)

type OutboxEntry struct {
	Sequence  uint64
	Operation syncmerge.Operation
}

// View belongs to the caller and represents one committed generation.
type View struct {
	Records []syncmerge.Record
	History []syncmerge.Operation
	Pending []syncmerge.Operation
	Counter uint64
	Outbox  []OutboxEntry
}

type queued struct {
	Operation syncmerge.Operation
	Local     bool
}

// The history is appended in acceptance order, which is topological.
type state struct {
	History []syncmerge.Operation
	Pending []queued
	Counter uint64
	Outbox  []string // IDs in local acceptance order, sequence starts at 1

	Exchange *ExchangeState `json:",omitempty"`
}

func (s *state) emptyLegacy() bool {
	return len(s.History) == 0 && len(s.Pending) == 0 && s.Counter == 0 && len(s.Outbox) == 0
}

func checkOperation(op syncmerge.Operation) error {
	if len(op.Data) > maxOperationSize || len(op.Parents) > maxParents {
		return ErrLimit
	}
	ids := []string{op.ID, op.AuthorID, op.RecordID}
	for _, id := range append(ids, op.Parents...) {
		if len(id) > maxIDBytes {
			return ErrLimit
		}
		if !utf8.ValidString(id) {
			return syncmerge.ErrInvalidOperation
		}
	}
	data, err := json.Marshal(op)
	if err != nil {
		return err
	}
	defer clear(data)
	if len(data) > maxOperationSize {
		return ErrLimit
	}
	return nil
}

func (s *state) encode() ([]byte, error) {
	if s.Exchange != nil {
		if _, err := s.Exchange.validate(); err != nil {
			return nil, err
		}
	}
	if len(s.History) > maxHistory || len(s.Pending) > maxPending {
		return nil, ErrLimit
	}
	for _, part := range []struct {
		items any
		limit int
	}{{s.History, maxHistoryBytes}, {s.Pending, maxPendingBytes}} {
		data, err := json.Marshal(part.items)
		if err != nil {
			return nil, err
		}
		size := len(data)
		clear(data)
		if size > part.limit {
			return nil, ErrLimit
		}
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(data) > maxStateSize {
		clear(data)
		return nil, ErrLimit
	}
	return data, nil
}

func decodeState(data []byte) (*state, *syncmerge.Replica, error) {
	var s *state
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil || s == nil {
		return nil, nil, ErrCorrupt
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, ErrCorrupt
	}
	if len(s.History) > maxHistory || len(s.Pending) > maxPending || s.Counter != uint64(len(s.Outbox)) ||
		(s.Exchange != nil && !s.emptyLegacy()) {
		return nil, nil, ErrCorrupt
	}
	encoded, err := s.encode()
	clear(encoded)
	if err != nil {
		return nil, nil, ErrCorrupt
	}
	model := syncmerge.New(maxPending)
	known := make(map[string]bool, len(s.History)+len(s.Pending))
	for _, op := range s.History {
		if _, exists := known[op.ID]; exists || checkOperation(op) != nil || model.Apply(op).Status != syncmerge.Applied {
			return nil, nil, ErrCorrupt
		}
		known[op.ID] = true
	}
	for _, p := range s.Pending {
		op := p.Operation
		if _, exists := known[op.ID]; exists || checkOperation(op) != nil || model.Apply(op).Status != syncmerge.Waiting {
			return nil, nil, ErrCorrupt
		}
		known[op.ID] = false
	}
	queuedIDs := make(map[string]struct{}, len(s.Outbox))
	for _, id := range s.Outbox {
		if _, exists := queuedIDs[id]; exists || !known[id] {
			return nil, nil, ErrCorrupt
		}
		queuedIDs[id] = struct{}{}
	}
	return s, model, nil
}

func (s *state) apply(model *syncmerge.Replica, op syncmerge.Operation, source Source) (syncmerge.Result, bool, error) {
	if s.Exchange != nil {
		return syncmerge.Result{}, false, ErrExchangeMode
	}
	result := model.Apply(op)
	if result.Status == syncmerge.Rejected {
		return result, false, nil
	}
	for _, accepted := range s.History {
		if accepted.ID == op.ID {
			return result, false, nil
		}
	}
	for _, p := range s.Pending {
		if p.Operation.ID == op.ID {
			return result, false, nil
		}
	}
	if result.Status == syncmerge.Waiting {
		s.Pending = append(s.Pending, queued{Operation: op, Local: source == Local})
		return result, true, nil
	}

	s.accept(queued{Operation: op, Local: source == Local})
	// The merge core reports ready operations in dependency order. Save in
	// that order so replay starts with a complete history before any waiters.
	for _, outcome := range result.Resolved {
		i := slices.IndexFunc(s.Pending, func(p queued) bool { return p.Operation.ID == outcome.ID })
		if i < 0 {
			return syncmerge.Result{}, false, ErrCorrupt
		}
		p := s.Pending[i]
		s.Pending = slices.Delete(s.Pending, i, i+1)
		if outcome.Status == syncmerge.Applied {
			s.accept(p)
		}
	}
	return result, true, nil
}

func (s *state) accept(p queued) {
	s.History = append(s.History, p.Operation)
	if p.Local {
		s.Counter++
		s.Outbox = append(s.Outbox, p.Operation.ID)
	}
}

func (s *state) view(model *syncmerge.Replica) View {
	history := model.History()
	byID := make(map[string]syncmerge.Operation, len(history))
	for _, op := range history {
		byID[op.ID] = op
	}
	view := View{Records: model.Snapshot(), History: history, Counter: s.Counter}
	for _, p := range s.Pending {
		view.Pending = append(view.Pending, p.Operation)
	}
	for i, id := range s.Outbox {
		op := byID[id]
		op.Parents = slices.Clone(op.Parents)
		op.Data = slices.Clone(op.Data)
		view.Outbox = append(view.Outbox, OutboxEntry{Sequence: uint64(i) + 1, Operation: op})
	}
	return view
}
