package syncrelay

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
)

func TestLogPages(t *testing.T) {
	const total = 135
	log := NewLog(total, 2*total)
	for i := 0; i < total; i++ {
		cursor, err := log.Append([]byte{0xff, byte(i)})
		if err != nil || cursor != uint64(i+1) {
			t.Fatalf("append %d: cursor %d, error %v", i, cursor, err)
		}
	}
	var after uint64
	for _, page := range []struct{ limit, want int }{{1000, 64}, {1, 1}, {64, 64}, {64, 6}, {64, 0}} {
		entries, err := log.List(after, page.limit)
		if err != nil || len(entries) != page.want {
			t.Fatalf("list after %d with limit %d: got %d entries, error %v", after, page.limit, len(entries), err)
		}
		for _, entry := range entries {
			if entry.Cursor != after+1 || !bytes.Equal(entry.Wire, []byte{0xff, byte(after)}) {
				t.Fatalf("entry after %d: %+v", after, entry)
			}
			after = entry.Cursor
		}
	}
	for _, invalid := range []uint64{total + 1, math.MaxUint64} {
		if _, err := log.List(invalid, 1); !errors.Is(err, ErrCursorOutOfRange) {
			t.Fatalf("list after %d: %v", invalid, err)
		}
	}
	if entries, err := log.List(0, 0); err != nil || len(entries) != 0 {
		t.Fatalf("zero limit: got %d entries, error %v", len(entries), err)
	}
}

func TestLogQuotaPreservesEntries(t *testing.T) {
	for _, test := range []struct {
		name                 string
		maxEntries, maxBytes int
	}{
		{"entry limit", 1, 100},
		{"byte limit", 10, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			log := NewLog(test.maxEntries, test.maxBytes)
			wire := []byte{0xff, 0x80}
			if cursor, err := log.Append(wire); err != nil || cursor != 1 {
				t.Fatalf("first append: cursor %d, error %v", cursor, err)
			}
			if cursor, err := log.Append([]byte{0x01}); !errors.Is(err, ErrQuotaExceeded) || cursor != 0 {
				t.Fatalf("over quota: cursor %d, error %v", cursor, err)
			}
			if cursor, err := log.Append(bytes.Clone(wire)); err != nil || cursor != 1 {
				t.Fatalf("repeat at quota: cursor %d, error %v", cursor, err)
			}
			entries, err := log.List(0, 64)
			if err != nil || !reflect.DeepEqual(entries, []Entry{{Cursor: 1, Wire: wire}}) {
				t.Fatalf("entries after quota refusal and repeat: %+v, error %v", entries, err)
			}
		})
	}
}

func TestLogRefusalsLeaveQuotaAndCursorAvailable(t *testing.T) {
	log := NewLog(3, 65_793)
	if _, err := log.Append(make([]byte, 65_793)); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatalf("oversized envelope: %v", err)
	}
	if cursor, err := log.Append(make([]byte, 65_792)); err != nil || cursor != 1 {
		t.Fatalf("envelope at size limit: cursor %d, error %v", cursor, err)
	}
	if _, err := log.Append([]byte{0, 1}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("over remaining byte quota: %v", err)
	}
	if cursor, err := log.Append([]byte{0}); err != nil || cursor != 2 {
		t.Fatalf("append within remaining quota: cursor %d, error %v", cursor, err)
	}
}

func TestLogConcurrentRepeat(t *testing.T) {
	log := NewLog(1, 8)
	wire := []byte("opaque")
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			<-start
			if cursor, err := log.Append(wire); err != nil || cursor != 1 {
				t.Errorf("concurrent append: cursor %d, error %v", cursor, err)
			}
			if entries, err := log.List(0, 64); err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Wire, wire) {
				t.Errorf("concurrent list: %+v, error %v", entries, err)
			}
		})
	}
	close(start)
	workers.Wait()
}

func TestLogCopiesBytes(t *testing.T) {
	log := NewLog(2, 8)
	wire := []byte{0xff, 0x12}
	want := bytes.Clone(wire)
	if cursor, err := log.Append(wire); err != nil || cursor != 1 {
		t.Fatalf("append: cursor %d, error %v", cursor, err)
	}
	wire[0] ^= 1
	page, err := log.List(0, 1)
	if err != nil || len(page) != 1 || !bytes.Equal(page[0].Wire, want) {
		t.Fatalf("after changing the input: %+v, error %v", page, err)
	}
	page[0].Wire[1] ^= 1
	page[0].Cursor = 2
	next, err := log.List(0, 1)
	if err != nil || !reflect.DeepEqual(next, []Entry{{Cursor: 1, Wire: want}}) {
		t.Fatalf("after changing the returned entry: %+v, error %v", next, err)
	}
	if cursor, err := log.Append(want); err != nil || cursor != 1 {
		t.Fatalf("repeat after caller mutations: cursor %d, error %v", cursor, err)
	}
}
