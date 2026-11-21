package replicastore

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"password-saver/internal/syncmerge"
)

var testKey = [KeySize]byte{1, 9, 8, 3} // Synthetic and confined to test binaries.

func put(id, record, text string, parents ...string) syncmerge.Operation {
	return syncmerge.Operation{ID: id, AuthorID: "synthetic-author", RecordID: record,
		Action: syncmerge.Put, Data: []byte(text), Parents: parents}
}

func erase(id, record string, parents ...string) syncmerge.Operation {
	op := put(id, record, "", parents...)
	op.Action = syncmerge.Delete
	return op
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replica space #тест%.sqlite")
	s, err := Create(t.Context(), path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func reopen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(t.Context(), path, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func apply(t *testing.T, s *Store, op syncmerge.Operation, source Source, status syncmerge.Status) syncmerge.Result {
	t.Helper()
	result, err := s.Apply(t.Context(), op, source)
	if err != nil || result.Status != status || result.Err != nil {
		t.Fatalf("apply: status=%q operation error=%v, store error=%v", result.Status, result.Err, err)
	}
	return result
}

func read(t *testing.T, s *Store) View {
	t.Helper()
	view, err := s.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func execSQL(t *testing.T, s *Store, statement string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(), statement, args...); err != nil {
		t.Fatal(err)
	}
}

func checkView(t *testing.T, s *Store, want View) {
	t.Helper()
	if got := read(t, s); !reflect.DeepEqual(got, want) {
		t.Fatal("committed replica contents differ")
	}
}

func TestConnectionStringPreservesNativeAbsolutePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replica space #тест%.sqlite")
	dsn, err := connectionString(path)
	if err != nil {
		t.Fatal(err)
	}
	rawPath, _, ok := strings.Cut(strings.TrimPrefix(dsn, "file:"), "?")
	got, err := url.PathUnescape(rawPath)
	if !ok || err != nil || got != filepath.ToSlash(path) {
		t.Fatalf("SQLite path = %q, expected %q, err=%v", got, filepath.ToSlash(path), err)
	}
}

func TestReopenRetainsConflictsDeletesWaitersAndOutbox(t *testing.T) {
	s, path := newStore(t)
	base := put("base", "entry", "initial")
	local := put("late-local", "entry", "later revision", "other")
	apply(t, s, base, Local, syncmerge.Applied)
	apply(t, s, put("edit", "entry", "concurrent update", "base"), Incoming, syncmerge.Applied)
	apply(t, s, erase("delete", "entry", "base"), Incoming, syncmerge.Applied)
	apply(t, s, local, Local, syncmerge.Waiting)
	want := read(t, s)
	if len(want.Records) != 1 || len(want.Records[0].Versions) != 2 ||
		want.Records[0].Versions[0].Action != syncmerge.Delete ||
		want.Records[0].Versions[1].Action != syncmerge.Put ||
		len(want.History) != 3 || len(want.Pending) != 1 || want.Counter != 1 ||
		len(want.Outbox) != 1 || want.Outbox[0].Operation.ID != base.ID {
		t.Fatal("expected both conflict versions and a waiter with no sequence yet")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, path)
	checkView(t, s, want)
	apply(t, s, local, Incoming, syncmerge.Waiting)
	apply(t, s, base, Local, syncmerge.Applied)
	checkView(t, s, want)

	// Check that callers can mutate a snapshot and their submitted buffers.
	mutable := read(t, s)
	mutable.Outbox[0].Operation.Data[0] = 'X'
	mutable.History[0].Data[0] = 'Y'
	mutable.Pending[0].Parents[0] = "alien"
	local.Data[0] = 'Z'
	local.Parents[0] = "alien"
	checkView(t, s, want)

	parent := put("other", "entry", "parent delivered after restart", "base")
	result := apply(t, s, parent, Incoming, syncmerge.Applied)
	if len(result.Resolved) != 1 || result.Resolved[0].ID != local.ID {
		t.Fatal("saved waiter was not resolved")
	}
	want = read(t, s)
	if want.Counter != 2 || len(want.Pending) != 0 || len(want.Records[0].Versions) != 3 ||
		len(want.Outbox) != 2 || want.Outbox[1].Sequence != 2 ||
		string(want.Outbox[1].Operation.Data) != "later revision" {
		t.Fatal("expected waiter to become an outgoing operation exactly once")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, path)
	apply(t, s, parent, Local, syncmerge.Applied) // First submission fixed its origin.
	checkView(t, s, want)
}

func TestRejectedWaiterRemoval(t *testing.T) {
	s, path := newStore(t)
	child := put("waiting", "first-record", "child", "parent")
	apply(t, s, child, Local, syncmerge.Waiting)
	parent := put("parent", "other-record", "parent")
	result := apply(t, s, parent, Incoming, syncmerge.Applied)
	if len(result.Resolved) != 1 || result.Resolved[0].Status != syncmerge.Rejected ||
		!errors.Is(result.Resolved[0].Err, syncmerge.ErrParentRecord) {
		t.Fatal("expected the wrong-record parent to reject the saved waiter")
	}
	view := read(t, reopen(t, path))
	if len(view.Pending) != 0 || len(view.History) != 1 || view.History[0].ID != parent.ID ||
		view.Counter != 0 || len(view.Outbox) != 0 {
		t.Fatal("a rejected waiter must disappear without entering history or the outbox")
	}
}

func TestFailedAndUnknownCommit(t *testing.T) {
	s, path := newStore(t)
	parent := put("parent", "entry", "parent")
	child := put("child", "entry", "child", parent.ID)
	apply(t, s, child, Local, syncmerge.Waiting)
	before := read(t, s)
	stop := errors.New("test interruption")
	s.beforeCommit = func() error { return stop }
	result, err := s.Apply(t.Context(), parent, Local)
	if !errors.Is(err, stop) || result.Status != "" {
		t.Fatalf("unsuccessful transaction reported success: %q, %v", result.Status, err)
	}
	checkView(t, s, before)
	checkView(t, reopen(t, path), before)

	s.beforeCommit = nil
	s.afterCommit = func() error { return stop }
	result, err = s.Apply(t.Context(), parent, Local)
	if !errors.Is(err, ErrCommitUnknown) || !errors.Is(err, stop) || result.Status != "" {
		t.Fatalf("expected uncertain acknowledgement, got %q, %v", result.Status, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, path)
	apply(t, s, parent, Local, syncmerge.Applied)
	apply(t, s, child, Local, syncmerge.Applied)
	got := read(t, s)
	if len(got.Pending) != 0 || len(got.History) != 2 || got.Counter != 2 ||
		len(got.Outbox) != 2 || got.Outbox[0].Operation.ID != parent.ID ||
		got.Outbox[1].Operation.ID != child.ID {
		t.Fatal("uncertain commit retry duplicated or lost a transition")
	}
}

func TestConcurrentWriters(t *testing.T) {
	first, path := newStore(t)
	second := reopen(t, path)
	before := read(t, second)
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	first.beforeCommit = func() error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() {
		result, err := first.Apply(t.Context(), put("first", "entry", "first"), Local)
		if err == nil && result.Status != syncmerge.Applied {
			err = errors.New("first transaction did not apply")
		}
		done <- err
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("first writer failed before reaching commit: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("first writer did not reach commit")
	}
	checkView(t, second, before)
	next := put("second", "other", "second")
	if result, err := second.Apply(t.Context(), next, Local); !errors.Is(err, ErrBusy) || result.Status != "" {
		t.Fatalf("second concurrent writer should return ErrBusy, got %q, %v", result.Status, err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	apply(t, second, next, Local, syncmerge.Applied)
	got := read(t, first)
	if len(got.History) != 2 || got.Counter != 2 || len(got.Outbox) != 2 || got.Outbox[1].Operation.ID != next.ID {
		t.Fatal("concurrent access lost a committed operation")
	}
}

func TestOpenFailsClosed(t *testing.T) {
	t.Run("wrong key", func(t *testing.T) {
		s, path := newStore(t)
		apply(t, s, put("saved", "entry", "value"), Local, syncmerge.Applied)
		want := read(t, s)
		if opened, err := Open(t.Context(), path, [KeySize]byte{7}); !errors.Is(err, ErrAuthentication) || opened != nil {
			t.Fatalf("wrong-key open: %v", err)
		}
		checkView(t, reopen(t, path), want)
	})
	for _, tc := range []struct {
		name, statement string
		want            error
	}{
		{"unknown schema", "PRAGMA user_version=9", ErrSchema},
		{"foreign trigger", "CREATE TRIGGER unexpected AFTER UPDATE ON replica BEGIN SELECT 1; END", ErrCorrupt},
		{"invalid envelope", "UPDATE replica SET envelope=x'aabb' WHERE id=1", ErrCorrupt},
		{"tag damaged", "UPDATE replica SET envelope=randomblob(length(envelope)) WHERE id=1", ErrAuthentication},
		{"generation replaced", "UPDATE replica SET generation=generation+1 WHERE id=1", ErrAuthentication},
		{"identity replaced", "UPDATE replica SET identity=randomblob(16) WHERE id=1", ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newStore(t)
			execSQL(t, s, tc.statement)
			before := rawRow(t, s.db)
			if opened, err := Open(t.Context(), path, testKey); !errors.Is(err, tc.want) || opened != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := rawRow(t, s.db); !bytes.Equal(got, before) {
				t.Fatal("failed open modified replica row")
			}
		})
	}
	t.Run("missing and unreadable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replica.sqlite")
		if _, err := Open(t.Context(), path, testKey); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("open of nonexistent file: %v", err)
		}
		damage := []byte("damaged database")
		if err := os.WriteFile(path, damage, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(t.Context(), path, testKey); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("open damaged SQLite file: %v", err)
		}
		if _, err := Create(t.Context(), path, testKey); !errors.Is(err, os.ErrExist) {
			t.Fatalf("create over existing file: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, damage) {
			t.Fatal("failed create/open modified input file")
		}
	})
}

func rawRow(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(t.Context(), "SELECT CAST(printf('%d/%s/%s', generation, hex(identity), hex(envelope)) AS BLOB) FROM replica").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLimitsPreserveCommittedData(t *testing.T) {
	s, _ := newStore(t)
	confirmed := put("stable", "stable", "committed")
	apply(t, s, confirmed, Local, syncmerge.Applied)
	for i := 0; i < maxPending; i++ {
		id := fmt.Sprintf("waiting-%02d", i)
		apply(t, s, put(id, "entry", "", "missing"), Incoming, syncmerge.Waiting)
	}
	want := read(t, s)
	over := put("extra", "entry", "", "missing")
	if result, err := s.Apply(t.Context(), over, Incoming); err != nil || result.Status != syncmerge.Rejected ||
		!errors.Is(result.Err, syncmerge.ErrPendingLimit) {
		t.Fatalf("expected pending count refusal: %q, %v, %v", result.Status, result.Err, err)
	}
	for _, op := range []syncmerge.Operation{
		put("oversize", "entry", strings.Repeat("x", maxOperationSize)),
		put("too-many-parents", "entry", "", make([]string, maxParents+1)...),
	} {
		if _, err := s.Apply(t.Context(), op, Incoming); !errors.Is(err, ErrLimit) {
			t.Fatalf("expected operation limit: %v", err)
		}
	}
	checkView(t, s, want)
}

func TestByteLimitsRollback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		wait  bool
	}{{"pending", maxPendingBytes, true}, {"history", maxHistoryBytes, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newStore(t)
			contents := strings.Repeat("p", 40<<10)
			data := &state{}
			example := put("id-000", "entry", contents)
			var item any = example
			if tc.wait {
				example.Parents = []string{"missing"}
				item = queued{Operation: example}
			}
			row, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			num := (tc.limit - 1) / (len(row) + 1)
			var over syncmerge.Operation
			for i := 0; i <= num; i++ {
				op := put(fmt.Sprintf("id-%03d", i), "entry", contents)
				if tc.wait {
					op.Parents = []string{"missing"}
				}
				if i == num {
					over = op
				} else if tc.wait {
					data.Pending = append(data.Pending, queued{Operation: op})
				} else {
					data.History = append(data.History, op)
				}
			}
			// Seed the almost-full state once so the test does not commit a
			// quadratic number of payload bytes.
			tx, err := s.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := s.write(t.Context(), tx, 2, data); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			want := read(t, s)
			if _, err := s.Apply(t.Context(), over, Incoming); !errors.Is(err, ErrLimit) {
				t.Fatalf("expected byte limit: %v", err)
			}
			checkView(t, reopen(t, path), want)
		})
	}
}

const syntheticMarker = "PS_SYNTHETIC_RECORD_NEVER_IN_SQLITE_6f4cc9dce3e045f8"

func TestDurabilityPragmasOnReopen(t *testing.T) {
	_, path := newStore(t)
	s := reopen(t, path)
	for query, want := range map[string]int{
		"PRAGMA synchronous":        2, // FULL
		"PRAGMA temp_store":         2, // MEMORY
		"PRAGMA trusted_schema":     0,
		"PRAGMA busy_timeout":       250,
		"PRAGMA wal_autocheckpoint": 256,
	} {
		var got int
		if err := s.db.QueryRowContext(t.Context(), query).Scan(&got); err != nil || got != want {
			t.Fatalf("%s: got %d, want %d, err=%v", query, got, want, err)
		}
	}
}

func TestPlaintextExcludedFromDatabaseAndSidecars(t *testing.T) {
	s, path := newStore(t)
	root := put(syntheticMarker, "entry", syntheticMarker)
	apply(t, s, root, Local, syncmerge.Applied)
	assertWAL(t, path)
	checkFiles(t, path)
	apply(t, s, put("update", "entry", syntheticMarker+"-update", root.ID), Local, syncmerge.Applied)
	checkFiles(t, path)
	apply(t, s, erase("tombstone", "entry", "update"), Local, syncmerge.Applied)
	checkFiles(t, path)
	var busy, pages, copied int
	if err := s.db.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &copied); err != nil || busy != 0 {
		t.Fatalf("checkpoint did not complete: %v, busy=%d", err, busy)
	}
	checkFiles(t, path)
}

func assertWAL(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path + "-wal")
	if err != nil || info.Size() == 0 {
		t.Fatalf("expected a nonempty WAL: %v", err)
	}
}

func checkFiles(t *testing.T, path string) {
	t.Helper()
	markers := []string{syntheticMarker, base64.StdEncoding.EncodeToString([]byte(syntheticMarker[:48]))}
	names, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), name.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range markers {
			if bytes.Contains(data, []byte(marker)) {
				t.Fatalf("found a plaintext test marker in %s", name.Name())
			}
		}
	}
}

func TestProcessTerminationAroundCommit(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			s, path := newStore(t)
			child := put("child", "entry", "waiting", "root")
			apply(t, s, child, Local, syncmerge.Waiting)
			before := read(t, s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			stopChild(t, path, phase)
			assertWAL(t, path)
			checkFiles(t, path)
			s = reopen(t, path)
			if phase == "before" {
				checkView(t, s, before)
			} else {
				got := read(t, s)
				if len(got.Pending) != 0 || len(got.History) != 2 || len(got.Records) != 1 ||
					got.Records[0].Versions[0].ID != child.ID || len(got.Outbox) != 2 ||
					got.Outbox[0].Operation.ID != "root" || got.Outbox[1].Operation.ID != child.ID || got.Counter != 2 {
					t.Fatal("process died after commit but the full transition was not recovered")
				}
			}
			apply(t, s, crashOperation(), Local, syncmerge.Applied)
			got := read(t, s)
			if got.Counter != 2 || len(got.History) != 2 || len(got.Pending) != 0 || len(got.Outbox) != 2 {
				t.Fatal("retry after a process interruption was not idempotent")
			}
			checkFiles(t, path)
		})
	}
}

func crashOperation() syncmerge.Operation {
	// Leave enough changed pages to exercise the WAL when the child spills.
	return put("root", "entry", strings.Repeat(syntheticMarker, 650))
}

func stopChild(t *testing.T, path, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestReplicaProcess$")
	cmd.Env = append(os.Environ(), "PS_REPLICA_CRASH_PHASE="+phase, "PS_REPLICA_CRASH_PATH="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if scanner.Text() == "replica at commit boundary" {
			if err := cmd.Process.Kill(); err != nil {
				_ = cmd.Wait()
				t.Fatal(err)
			}
			var exitErr *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exitErr) {
				t.Fatalf("expected killed process, got %v", err)
			}
			return
		}
	}
	waitErr := cmd.Wait()
	t.Fatalf("child did not reach commit boundary: %v, %v, %s", scanner.Err(), waitErr, stderr.String())
}

// TestReplicaProcess only runs the worker when explicitly started by its parent.
func TestReplicaProcess(t *testing.T) {
	phase := os.Getenv("PS_REPLICA_CRASH_PHASE")
	if phase == "" {
		return
	}
	s := reopen(t, os.Getenv("PS_REPLICA_CRASH_PATH"))
	execSQL(t, s, "PRAGMA cache_size=4")
	stop := func() error {
		fmt.Println("replica at commit boundary")
		time.Sleep(time.Minute) // The parent forcefully terminates this process.
		return errors.New("parent did not terminate child")
	}
	switch phase {
	case "before":
		s.beforeCommit = stop
	case "after":
		s.afterCommit = stop
	default:
		t.Fatal("invalid child phase")
	}
	apply(t, s, crashOperation(), Local, syncmerge.Applied)
}
