package syncmerge

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func put(id, author, record, data string, parents ...string) Operation {
	return Operation{
		ID: id, AuthorID: author, RecordID: record,
		Parents: parents, Action: Put, Data: []byte(data),
	}
}

func remove(id, author, record string, parents ...string) Operation {
	return Operation{ID: id, AuthorID: author, RecordID: record, Parents: parents, Action: Delete}
}

func expectOutcome(t *testing.T, got Result, status Status, err error) {
	t.Helper()
	if got.Status != status || !errors.Is(got.Err, err) {
		t.Fatalf("Apply(%q) = %s, %v. Want %s, %v", got.ID, got.Status, got.Err, status, err)
	}
}

func expectRecords(t *testing.T, r *Replica, want ...Record) {
	t.Helper()
	if got := r.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot = %#v\nwant %#v", got, want)
	}
}

func TestIndependentRecordsWithSameName(t *testing.T) {
	r := New(2)
	a := put("a0", "alice", "a", "title=Same")
	b := put("b0", "bob", "b", "title=Same")
	aEdit := put("a1", "bob", "a", "title=Same login=Updated A", a.ID)
	bEdit := put("b1", "alice", "b", "title=Same login=Updated B", b.ID)
	for _, op := range []Operation{b, a, aEdit, bEdit} {
		expectOutcome(t, r.Apply(op), Applied, nil)
	}
	expectRecords(t, r,
		Record{ID: "a", Versions: []Operation{aEdit}},
		Record{ID: "b", Versions: []Operation{bEdit}})
}

func TestConflictsAndResolutionLeaveLateConcurrentVersion(t *testing.T) {
	r := New(4)
	root := put("root", "alice", "record", "title=Root login=base")
	a := put("a", "alice", root.RecordID, "title=Left login=left", root.ID)
	b := put("b", "bob", root.RecordID, "title=Right login=right", root.ID)
	late := put("late", "bob", root.RecordID, "title=Late login=third", root.ID)
	resolved := put("resolve", "alice", root.RecordID, "title=Resolved login=merged", a.ID, b.ID)

	for _, op := range []Operation{root, b, a} {
		expectOutcome(t, r.Apply(op), Applied, nil)
	}
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{a, b}})
	expectOutcome(t, r.Apply(resolved), Applied, nil)
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{resolved}})
	expectOutcome(t, r.Apply(late), Applied, nil)
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{late, resolved}})
}

func TestDeletionIsACausalVersionAndCanConflict(t *testing.T) {
	r := New(3)
	root := put("root", "alice", "record", "baseline")
	deleted := remove("delete", "bob", root.RecordID, root.ID)
	edit := put("edit", "alice", root.RecordID, "changed", root.ID)
	final := remove("final", "alice", root.RecordID, deleted.ID, edit.ID)
	for _, op := range []Operation{root, deleted} {
		expectOutcome(t, r.Apply(op), Applied, nil)
	}
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{deleted}})
	expectOutcome(t, r.Apply(edit), Applied, nil)
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{deleted, edit}})
	expectOutcome(t, r.Apply(final), Applied, nil)
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{final}})
	if want := []Operation{deleted, edit, final, root}; !reflect.DeepEqual(r.History(), want) {
		t.Fatal("resolving a conflict discarded versions or deletion history")
	}
}

func TestParentOrderAndExactRepeats(t *testing.T) {
	r := New(3)
	a := put("a", "alice", "record", "variant 1")
	b := put("b", "bob", a.RecordID, "variant 2")
	child := put("c", "bob", a.RecordID, "resolution", b.ID, a.ID)
	expectOutcome(t, r.Apply(child), Waiting, nil)

	reordered := child
	reordered.Parents = []string{a.ID, b.ID}
	expectOutcome(t, r.Apply(reordered), Waiting, nil)
	expectOutcome(t, r.Apply(a), Applied, nil)
	expectRecords(t, r, Record{ID: a.RecordID, Versions: []Operation{a}})
	result := r.Apply(b)
	expectOutcome(t, result, Applied, nil)
	if want := []Outcome{{ID: child.ID, Status: Applied}}; !reflect.DeepEqual(result.Resolved, want) {
		t.Fatalf("resolved = %+v, want %+v", result.Resolved, want)
	}
	expectOutcome(t, r.Apply(reordered), Applied, nil)
	expectRecords(t, r, Record{ID: a.RecordID, Versions: []Operation{reordered}})
	if len(r.History()) != 3 {
		t.Fatal("repeat produced extra history")
	}
}

func TestIDCollisionPreservesFirstDefinition(t *testing.T) {
	r := New(2)
	root := put("root", "alice", "record", "baseline")
	first := put("child", "alice", root.RecordID, "accepted data", root.ID)
	expectOutcome(t, r.Apply(first), Waiting, nil)
	collisions := []Operation{
		put(first.ID, "other author", first.RecordID, string(first.Data), root.ID),
		put(first.ID, first.AuthorID, "another record", string(first.Data), root.ID),
		put(first.ID, first.AuthorID, first.RecordID, "different bytes", root.ID),
		put(first.ID, first.AuthorID, first.RecordID, string(first.Data)),
		remove(first.ID, first.AuthorID, first.RecordID, root.ID),
	}
	for _, op := range collisions {
		expectOutcome(t, r.Apply(op), Rejected, ErrIDCollision)
	}
	expectOutcome(t, r.Apply(root), Applied, nil)
	for _, op := range collisions {
		expectOutcome(t, r.Apply(op), Rejected, ErrIDCollision)
	}
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{first}})
	if want := []Operation{first, root}; !reflect.DeepEqual(r.History(), want) {
		t.Fatal("a collision overwrote history")
	}
}

func TestRejectsInvalidOperationsWithoutChangingAcceptedState(t *testing.T) {
	r := New(3)
	root := put("root", "alice", "record", "keep this")
	expectOutcome(t, r.Apply(root), Applied, nil)
	badAction := put("bad-action", "bob", root.RecordID, "invalid")
	badAction.Action = "rename"
	badDelete := remove("bad-delete", "bob", root.RecordID, root.ID)
	badDelete.Data = []byte("unexpected deletion payload")
	for _, tc := range []struct {
		op   Operation
		want error
	}{
		{put("", "bob", root.RecordID, "missing ID"), ErrInvalidOperation},
		{put("no-author", "", root.RecordID, "missing author"), ErrInvalidOperation},
		{put("no-record", "bob", "", "missing record"), ErrInvalidOperation},
		{badAction, ErrInvalidOperation},
		{badDelete, ErrInvalidOperation},
		{put("self", "bob", root.RecordID, "self", "self"), ErrInvalidParent},
		{put("empty", "bob", root.RecordID, "empty parent", ""), ErrInvalidParent},
		{put("double", "bob", root.RecordID, "duplicate parent", root.ID, root.ID), ErrInvalidParent},
		{put("cross", "bob", "wrong", "wrong record", "still-missing", root.ID), ErrParentRecord},
	} {
		expectOutcome(t, r.Apply(tc.op), Rejected, tc.want)
		expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{root}})
	}
	if want := []Operation{root}; !reflect.DeepEqual(r.History(), want) {
		t.Fatal("rejection altered existing history")
	}
}

func TestReportsQueuedCrossRecordParentAndReleasesCapacity(t *testing.T) {
	r := New(1)
	parent := put("parent", "alice", "record-a", "known later")
	bad := put("bad", "bob", "record-b", "cross-record", parent.ID, "unseen")
	expectOutcome(t, r.Apply(bad), Waiting, nil)
	result := r.Apply(parent)
	expectOutcome(t, result, Applied, nil)
	if want := []Outcome{{ID: bad.ID, Status: Rejected, Err: ErrParentRecord}}; !reflect.DeepEqual(result.Resolved, want) {
		t.Fatalf("resolved = %+v, want %+v", result.Resolved, want)
	}
	expectRecords(t, r, Record{ID: parent.RecordID, Versions: []Operation{parent}})
	corrected := put(bad.ID, bad.AuthorID, parent.RecordID, "correct record", "dependency")
	expectOutcome(t, r.Apply(corrected), Waiting, nil)
	dependency := put("dependency", "alice", parent.RecordID, "new root")
	expectOutcome(t, r.Apply(dependency), Applied, nil)
	expectRecords(t, r, Record{ID: parent.RecordID, Versions: []Operation{corrected, parent}})
}

func TestCycleRejectionDoesNotReserveTheClosingID(t *testing.T) {
	for _, count := range []int{2, 3, 100} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := New(uint(count))
			const record = "record"
			id := func(i int) string { return fmt.Sprintf("op-%03d", i) }

			for i := 0; i < count-1; i++ {
				expectOutcome(t, r.Apply(put(id(i), "alice", record, "child", id(i+1))), Waiting, nil)
			}
			closing := put(id(count-1), "bob", record, "cycle", id(0))
			expectOutcome(t, r.Apply(closing), Rejected, ErrCycle)
			if len(r.Snapshot()) != 0 || len(r.History()) != 0 {
				t.Fatal("dependency cycle changed accepted state")
			}
			root := put(closing.ID, "bob", record, "valid root")
			result := r.Apply(root)
			expectOutcome(t, result, Applied, nil)
			if len(result.Resolved) != count-1 {
				t.Fatalf("resolved %d children, want %d", len(result.Resolved), count-1)
			}
			expectRecords(t, r, Record{ID: record, Versions: []Operation{put(id(0), "alice", record, "child", id(1))}})
		})
	}
}

func TestPendingLimitAllowsProgressAndRetry(t *testing.T) {
	r := New(1)
	root := put("root", "alice", "record", "root")
	first := put("first", "alice", root.RecordID, "first", root.ID)
	last := put("last", "bob", root.RecordID, "last", first.ID)
	expectOutcome(t, r.Apply(first), Waiting, nil)
	expectOutcome(t, r.Apply(first), Waiting, nil)
	expectOutcome(t, r.Apply(last), Rejected, ErrPendingLimit)

	result := r.Apply(root)
	expectOutcome(t, result, Applied, nil)
	if want := []Outcome{{ID: first.ID, Status: Applied}}; !reflect.DeepEqual(result.Resolved, want) {
		t.Fatalf("resolved = %+v, want %+v", result.Resolved, want)
	}
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{first}})
	expectOutcome(t, r.Apply(last), Applied, nil)
	expectRecords(t, r, Record{ID: root.RecordID, Versions: []Operation{last}})

	withoutQueue := New(0)
	expectOutcome(t, withoutQueue.Apply(first), Rejected, ErrPendingLimit)
	expectOutcome(t, withoutQueue.Apply(root), Applied, nil)
	expectOutcome(t, withoutQueue.Apply(first), Applied, nil)
}

func TestOwnsSlicesOnInputAndOutput(t *testing.T) {
	r := New(2)
	base := put("base", "alice", "record", "original")
	child := put("child", "bob", base.RecordID, "new data", base.ID)
	wantBase := put("base", "alice", "record", "original")
	wantChild := put("child", "bob", "record", "new data", "base")
	expectOutcome(t, r.Apply(child), Waiting, nil)

	child.Parents[0] = "another parent"
	child.Data[0] = '!'
	expectOutcome(t, r.Apply(base), Applied, nil)
	base.Data[0] = '?'
	expectRecords(t, r, Record{ID: wantBase.RecordID, Versions: []Operation{wantChild}})

	snapshot := r.Snapshot()
	snapshot[0].Versions[0].Parents[0] = "unknown"
	snapshot[0].Versions[0].Data[0] = '-'
	snapshot[0].Versions[0] = Operation{}
	snapshot[0].ID = "wrong record"
	history := r.History()
	history[0].Data[0] = '*'
	history[1].Parents[0] = "another parent"
	history[1].Data[0] = '+'
	history[1] = Operation{}
	expectRecords(t, r, Record{ID: wantBase.RecordID, Versions: []Operation{wantChild}})
	if want := []Operation{wantBase, wantChild}; !reflect.DeepEqual(r.History(), want) {
		t.Fatal("mutating slices changed accepted history")
	}

	empty := put("empty", "bob", wantBase.RecordID, "")
	expectOutcome(t, r.Apply(empty), Applied, nil)
	empty.Data, empty.Parents = nil, []string{}
	expectOutcome(t, r.Apply(empty), Applied, nil)
}

func TestConvergenceAcrossAllDeliveryOrdersAndRepeats(t *testing.T) {
	a := put("a-root", "alice", "record-a", "original A")
	b := put("b-root", "bob", "record-b", "original B")
	left := put("left", "alice", a.RecordID, "left variant", a.ID)
	right := put("right", "bob", a.RecordID, "right variant", a.ID)
	deleted := remove("delete", "alice", a.RecordID, a.ID)
	resolved := put("resolved", "alice", a.RecordID, "resolution of left and right", left.ID, right.ID)
	independent := put("b-edit", "bob", b.RecordID, "independent edit", b.ID)
	ops := []Operation{a, b, left, right, deleted, resolved, independent}

	wantRecords := []Record{
		{ID: a.RecordID, Versions: []Operation{deleted, resolved}},
		{ID: b.RecordID, Versions: []Operation{independent}},
	}
	wantHistory := []Operation{a, independent, b, deleted, left, resolved, right}
	reference := New(0)
	for _, op := range ops {
		expectOutcome(t, reference.Apply(op), Applied, nil)
	}
	expectRecords(t, reference, wantRecords...)

	orders := 0
	forEachOrder(slices.Clone(ops), 0, func(order []Operation) {
		replica := New(uint(len(ops)))
		for _, op := range order {
			result := replica.Apply(op)
			if result.Status != Applied && result.Status != Waiting {
				t.Fatalf("valid operation %q rejected: %v", op.ID, result.Err)
			}
			repeat := replica.Apply(op)
			if repeat.Status != result.Status || repeat.Err != nil || len(repeat.Resolved) != 0 {
				t.Fatalf("repeat of %q changed status or resolved operations: %+v", op.ID, repeat)
			}
		}
		for _, op := range order {
			expectOutcome(t, replica.Apply(op), Applied, nil)
		}
		if got := replica.Snapshot(); !reflect.DeepEqual(got, wantRecords) || !reflect.DeepEqual(got, reference.Snapshot()) {
			t.Fatalf("order %d produced %+v, want %+v", orders, got, wantRecords)
		}
		if got := replica.History(); !reflect.DeepEqual(got, wantHistory) {
			t.Fatalf("order %d produced incorrect history: %+v", orders, got)
		}
		orders++
	})
	if orders != 5040 {
		t.Fatalf("checked %d permutations, want 5040", orders)
	}
}

func forEachOrder(ops []Operation, from int, check func([]Operation)) {
	if from == len(ops) {
		check(ops)
		return
	}
	for i := from; i < len(ops); i++ {
		ops[from], ops[i] = ops[i], ops[from]
		forEachOrder(ops, from+1, check)
		ops[from], ops[i] = ops[i], ops[from]
	}
}

func ExampleReplica() {
	first, second := New(2), New(2)
	base := Operation{ID: "base", AuthorID: "alice", RecordID: "record", Action: Put, Data: []byte("original")}
	left := Operation{ID: "left", AuthorID: "alice", RecordID: "record", Parents: []string{base.ID}, Action: Put, Data: []byte("edit")}
	right := Operation{ID: "right", AuthorID: "bob", RecordID: "record", Parents: []string{base.ID}, Action: Delete}

	first.Apply(base)
	first.Apply(left)
	first.Apply(right)

	fmt.Println(second.Apply(right).Status)
	second.Apply(base)
	second.Apply(left)
	fmt.Println(reflect.DeepEqual(first.Snapshot(), second.Snapshot()))
	for _, version := range second.Snapshot()[0].Versions {
		fmt.Println(version.ID, version.Action)
	}
	// Output:
	// waiting
	// true
	// left put
	// right delete
}
