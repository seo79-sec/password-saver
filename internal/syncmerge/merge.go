// Package syncmerge applies causally related record revisions in memory.
package syncmerge

import (
	"bytes"
	"errors"
	"maps"
	"slices"
)

type Action string

const (
	Put    Action = "put"
	Delete Action = "delete"
)

// Operation represents one complete version of a record. Parents belong to
// the same record. Their order is irrelevant, and each ID may occur only once.
type Operation struct {
	ID       string
	AuthorID string
	RecordID string
	Parents  []string
	Action   Action
	Data     []byte
}

type Status string

const (
	Applied  Status = "applied"
	Waiting  Status = "waiting"
	Rejected Status = "rejected"
)

var (
	ErrInvalidOperation = errors.New("invalid operation")
	ErrInvalidParent    = errors.New("empty, duplicate or self-referencing parent ID")
	ErrIDCollision      = errors.New("operation ID already has different content")
	ErrParentRecord     = errors.New("parent belongs to another record")
	ErrCycle            = errors.New("operation creates a dependency cycle")
	ErrPendingLimit     = errors.New("pending operation limit reached")
)

type Outcome struct {
	ID     string
	Status Status
	Err    error
}

// Result reports the submitted operation and any queued operations that
// became applied or rejected because a dependency was accepted.
type Result struct {
	Outcome
	Resolved []Outcome
}

// Record contains all maximal versions, including any deletion variants.
type Record struct {
	ID       string
	Versions []Operation
}

// Replica owns a single in-memory history. Callers must serialize access to
// the same Replica. Replicas created by New share no mutable data.
type Replica struct {
	maxPending uint
	accepted   map[string]Operation
	pending    map[string]Operation
	waiting    map[string]map[string]struct{} // unapplied parent ID -> pending child IDs
	heads      map[string]map[string]struct{} // record ID -> maximal operation IDs
}

// New creates a replica with a bounded queue. A zero limit accepts only
// operations whose dependencies are already present.
func New(maxPending uint) *Replica {
	return &Replica{
		maxPending: maxPending,
		accepted:   make(map[string]Operation),
		pending:    make(map[string]Operation),
		waiting:    make(map[string]map[string]struct{}),
		heads:      make(map[string]map[string]struct{}),
	}
}

// Apply submits an operation. An exact repeat returns its existing status.
func (r *Replica) Apply(op Operation) Result {
	if err := validateOperation(op); err != nil {
		return rejected(op.ID, err)
	}
	op.Parents = cloneSlice(op.Parents)
	slices.Sort(op.Parents)
	for i := 1; i < len(op.Parents); i++ {
		if op.Parents[i] == op.Parents[i-1] {
			return rejected(op.ID, ErrInvalidParent)
		}
	}

	if existing, ok := r.accepted[op.ID]; ok {
		return repeated(existing, op, Applied)
	}
	if existing, ok := r.pending[op.ID]; ok {
		return repeated(existing, op, Waiting)
	}

	missing, err := r.checkParents(op)
	if err != nil {
		return rejected(op.ID, err)
	}
	if missing {
		if r.closesCycle(op) {
			return rejected(op.ID, ErrCycle)
		}
		if uint(len(r.pending)) >= r.maxPending {
			return rejected(op.ID, ErrPendingLimit)
		}
		op.Data = cloneSlice(op.Data)
		r.enqueue(op)
		return Result{Outcome: Outcome{ID: op.ID, Status: Waiting}}
	}

	op.Data = cloneSlice(op.Data)
	r.accept(op)
	return Result{Outcome: Outcome{ID: op.ID, Status: Applied}, Resolved: r.resolve(op.ID)}
}

func validateOperation(op Operation) error {
	if op.ID == "" || op.AuthorID == "" || op.RecordID == "" ||
		(op.Action != Put && op.Action != Delete) || (op.Action == Delete && len(op.Data) != 0) {
		return ErrInvalidOperation
	}
	for _, parent := range op.Parents {
		if parent == "" || parent == op.ID {
			return ErrInvalidParent
		}
	}
	return nil
}

func repeated(existing, op Operation, status Status) Result {
	if existing.AuthorID != op.AuthorID || existing.RecordID != op.RecordID ||
		existing.Action != op.Action || !slices.Equal(existing.Parents, op.Parents) ||
		!bytes.Equal(existing.Data, op.Data) {
		return rejected(op.ID, ErrIDCollision)
	}
	return Result{Outcome: Outcome{ID: op.ID, Status: status}}
}

func rejected(id string, err error) Result {
	return Result{Outcome: Outcome{ID: id, Status: Rejected, Err: err}}
}

func (r *Replica) checkParents(op Operation) (missing bool, err error) {
	for _, id := range op.Parents {
		if parent, ok := r.accepted[id]; !ok {
			missing = true
		} else if parent.RecordID != op.RecordID {
			return false, ErrParentRecord
		}
	}
	return missing, nil
}

// Accepted operations cannot depend on a missing ID. Only waiting operations
// can form a path back to the ID being submitted.
func (r *Replica) closesCycle(op Operation) bool {
	stack := slices.Clone(op.Parents)
	visited := make(map[string]struct{})
	for len(stack) > 0 {
		last := len(stack) - 1
		id := stack[last]
		stack = stack[:last]
		if id == op.ID {
			return true
		}
		if _, ok := visited[id]; ok {
			continue
		}
		visited[id] = struct{}{}
		if parent, ok := r.pending[id]; ok {
			stack = append(stack, parent.Parents...)
		}
	}
	return false
}

func (r *Replica) enqueue(op Operation) {
	r.pending[op.ID] = op
	for _, id := range op.Parents {
		if _, known := r.accepted[id]; known {
			continue
		}
		if r.waiting[id] == nil {
			r.waiting[id] = make(map[string]struct{})
		}
		r.waiting[id][op.ID] = struct{}{}
	}
}

func (r *Replica) dequeue(op Operation) {
	delete(r.pending, op.ID)
	for _, id := range op.Parents {
		delete(r.waiting[id], op.ID)
		if len(r.waiting[id]) == 0 {
			delete(r.waiting, id)
		}
	}
}

func (r *Replica) accept(op Operation) {
	r.accepted[op.ID] = op
	heads := r.heads[op.RecordID]
	if heads == nil {
		heads = make(map[string]struct{})
		r.heads[op.RecordID] = heads
	}
	// Ancestors behind a direct parent ceased to be heads when their own
	// children were accepted. Only the direct parents can still be heads.
	for _, parent := range op.Parents {
		delete(heads, parent)
	}
	heads[op.ID] = struct{}{}
}

func (r *Replica) resolve(parentID string) []Outcome {
	var results []Outcome
	resolved := []string{parentID}
	for i := 0; i < len(resolved); i++ {
		parent := resolved[i]
		children := slices.Sorted(maps.Keys(r.waiting[parent]))
		delete(r.waiting, parent)
		for _, id := range children {
			op := r.pending[id]
			missing, err := r.checkParents(op)
			if missing {
				continue
			}
			r.dequeue(op)
			if err != nil {
				results = append(results, Outcome{ID: id, Status: Rejected, Err: err})
				continue
			}
			r.accept(op)
			results = append(results, Outcome{ID: id, Status: Applied})
			resolved = append(resolved, id)
		}
	}
	return results
}

// Snapshot returns a deep copy of all maximal versions, ordered by record
// then operation ID. It includes records whose only version is a deletion.
func (r *Replica) Snapshot() []Record {
	records := make([]Record, 0, len(r.heads))
	for _, id := range slices.Sorted(maps.Keys(r.heads)) {
		versions := make([]Operation, 0, len(r.heads[id]))
		for _, head := range slices.Sorted(maps.Keys(r.heads[id])) {
			versions = append(versions, cloneOperation(r.accepted[head]))
		}
		records = append(records, Record{ID: id, Versions: versions})
	}
	return records
}

// History returns a deep copy of all accepted operations, ordered by ID.
// Use a topological order to replay without waiting for dependencies.
func (r *Replica) History() []Operation {
	history := make([]Operation, 0, len(r.accepted))
	for _, id := range slices.Sorted(maps.Keys(r.accepted)) {
		history = append(history, cloneOperation(r.accepted[id]))
	}
	return history
}

func cloneOperation(op Operation) Operation {
	op.Parents = cloneSlice(op.Parents)
	op.Data = cloneSlice(op.Data)
	return op
}

func cloneSlice[S ~[]E, E any](values S) S {
	// Give empty and nil inputs the same representation in snapshots.
	if len(values) == 0 {
		return nil
	}
	return slices.Clone(values)
}
