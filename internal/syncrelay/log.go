// Package syncrelay provides an in-memory log of opaque sync envelopes.
package syncrelay

import (
	"errors"
	"sync"
)

const (
	// MaxEnvelopeSize is the PasswordSaver v3 change envelope limit in bytes.
	MaxEnvelopeSize = 65_792
	// MaxPageSize is the maximum number of entries returned by List.
	MaxPageSize = 64
)

var (
	ErrEnvelopeTooLarge = errors.New("relay envelope exceeds size limit")
	ErrQuotaExceeded    = errors.New("relay log quota exceeded")
	ErrCursorOutOfRange = errors.New("relay cursor is past the end of the log")
)

// Entry contains a cursor and a caller-owned copy of the exact envelope bytes.
type Entry struct {
	Cursor uint64
	Wire   []byte
}

// Log stores envelopes for one space and supports concurrent callers.
type Log struct {
	mu         sync.RWMutex
	maxEntries int
	maxBytes   int
	totalBytes int
	entries    []string
	cursors    map[string]uint64
}

// NewLog sets quotas for distinct envelopes and their total byte length.
func NewLog(maxEntries, maxBytes int) *Log {
	return &Log{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		cursors:    make(map[string]uint64),
	}
}

// Append assigns consecutive cursors starting at 1. Exact repeats keep their
// cursor even when the log has reached a quota.
func (l *Log) Append(wire []byte) (uint64, error) {
	size := len(wire)
	if size > MaxEnvelopeSize {
		return 0, ErrEnvelopeTooLarge
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cursor, ok := l.cursors[string(wire)]; ok {
		return cursor, nil
	}
	if len(l.entries) >= l.maxEntries || size > l.maxBytes-l.totalBytes {
		return 0, ErrQuotaExceeded
	}
	// An immutable copy serves as both the stored envelope and its exact lookup key.
	stored := string(wire)
	l.entries = append(l.entries, stored)
	cursor := uint64(len(l.entries))
	l.cursors[stored] = cursor
	l.totalBytes += size
	return cursor, nil
}

// List returns entries in append order strictly after the given cursor.
// Cursor 0 starts at the beginning. A non-positive limit returns an empty page.
func (l *Log) List(after uint64, limit int) ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if after > uint64(len(l.entries)) {
		return nil, ErrCursorOutOfRange
	}
	start := int(after)
	count := min(max(limit, 0), MaxPageSize, len(l.entries)-start)
	page := make([]Entry, count)
	for i, wire := range l.entries[start : start+count] {
		page[i] = Entry{Cursor: after + uint64(i) + 1, Wire: []byte(wire)}
	}
	return page, nil
}
