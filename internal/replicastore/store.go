// Package replicastore persists one local syncmerge replica in an encrypted
// SQLite transaction. The caller supplies and manages a dedicated random key.
package replicastore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ncruces/go-sqlite3"
	_ "github.com/ncruces/go-sqlite3/driver"

	"password-saver/internal/syncmerge"
)

const (
	KeySize       = 32
	applicationID = 0x50535253
)

var (
	ErrAuthentication = errors.New("replica state authentication failed")
	ErrSchema         = errors.New("unsupported replica schema")
	ErrCorrupt        = errors.New("invalid replica database state")
	ErrBusy           = errors.New("replica database is busy")
	ErrCommitUnknown  = errors.New("replica commit outcome unknown; read or repeat the same operation")
	ErrClosed         = errors.New("replica store is closed")
)

const createSchema = `CREATE TABLE replica (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	identity BLOB NOT NULL CHECK (length(identity) = 16),
	generation INTEGER NOT NULL CHECK (generation > 0),
	envelope BLOB NOT NULL
) STRICT`

const readRow = `
SELECT CASE WHEN length(identity) = 16 THEN identity END, generation,
       CASE WHEN length(envelope) BETWEEN ? AND ? THEN envelope END
FROM replica WHERE id = 1
`

type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	identity [identitySize]byte
	key      [KeySize]byte

	// The tests inject an error or stop a child process at these boundaries.
	beforeCommit func() error
	afterCommit  func() error
}

// Create reserves a new file in an existing, private local directory.
// If initialization fails, the file is left for inspection.
func Create(ctx context.Context, path string, key [KeySize]byte) (*Store, error) {
	defer clear(key[:])
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dsn, err := connectionString(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	store, err := connect(dsn, key)
	if err != nil {
		return nil, err
	}
	if err := store.initialize(ctx); err != nil {
		store.Close()
		return nil, storageError(err)
	}
	return store, nil
}

// Open validates an existing replica and pins its identity to this handle.
func Open(ctx context.Context, path string, key [KeySize]byte) (*Store, error) {
	defer clear(key[:])
	dsn, err := connectionString(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrCorrupt
	}
	store, err := connect(dsn, key)
	if err != nil {
		return nil, err
	}
	if err := store.validate(ctx); err != nil {
		store.Close()
		return nil, storageError(err)
	}
	return store, nil
}

func connectionString(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: empty database path", ErrCorrupt)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.ToSlash(absolute)
	if strings.HasPrefix(absolute, "//") {
		return "", fmt.Errorf("%w: database requires a local path", ErrCorrupt)
	}
	query := url.Values{
		"mode":    {"rw"},
		"_txlock": {"immediate"},
		"_pragma": {"busy_timeout(250)", "synchronous(FULL)", "temp_store(MEMORY)", "trusted_schema(OFF)", "wal_autocheckpoint(256)"},
	}
	// The driver's Go VFS expects a drive path as C:/path, without
	// the slash an authority-style file URI adds before the volume.
	escapedPath := (&url.URL{Path: absolute}).EscapedPath()
	return "file:" + escapedPath + "?" + query.Encode(), nil
}

func connect(dsn string, key [KeySize]byte) (*Store, error) {
	defer clear(key[:])
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Store{db: db, key: key}, nil
}

func (s *Store) initialize(ctx context.Context) error {
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return err
	}
	if mode != "wal" {
		return fmt.Errorf("%w: WAL unavailable", ErrCorrupt)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, createSchema); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d; PRAGMA user_version=%d", applicationID, schemaVersion)); err != nil {
		return err
	}
	rand.Read(s.identity[:])
	encoded, err := (&state{}).encode()
	if err != nil {
		return err
	}
	defer clear(encoded)
	envelope, err := sealState(&s.key, s.identity, 1, encoded)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replica VALUES (1, ?, 1, ?)", s.identity[:], envelope); err != nil {
		return err
	}
	return s.commit(tx)
}

func (s *Store) validate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id, _, _, _, err := s.load(ctx, tx)
	if err != nil {
		return err
	}
	s.identity = id
	return nil
}

func (s *Store) load(ctx context.Context, tx *sql.Tx) ([identitySize]byte, int64, *state, *syncmerge.Replica, error) {
	var identity [identitySize]byte
	if err := checkSchema(ctx, tx); err != nil {
		return identity, 0, nil, nil, err
	}
	var identityBytes, envelope []byte
	var generation int64
	if err := tx.QueryRowContext(ctx, readRow, envelopeOverhead, maxStateSize+envelopeOverhead).
		Scan(&identityBytes, &generation, &envelope); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrCorrupt
		}
		return identity, 0, nil, nil, err
	}
	if len(identityBytes) != len(identity) || generation < 1 {
		return identity, 0, nil, nil, ErrCorrupt
	}
	copy(identity[:], identityBytes)
	plaintext, err := openState(&s.key, identity, generation, envelope)
	if err != nil {
		return identity, 0, nil, nil, err
	}
	defer clear(plaintext)
	data, model, err := decodeState(plaintext)
	return identity, generation, data, model, err
}

func checkSchema(ctx context.Context, tx *sql.Tx) error {
	var appID, version int
	if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if appID != applicationID || version != schemaVersion {
		return ErrSchema
	}
	var mode string
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if mode != "wal" {
		return fmt.Errorf("%w: expected WAL", ErrCorrupt)
	}
	// Schema v1 has one table and no triggers, views, or indexes. A
	// recognized header alone must not authorize SQLite to run foreign DDL.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema`).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrCorrupt
	}
	var ddl string
	err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='table' AND name='replica'`).Scan(&ddl)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && ddl != createSchema) {
		return ErrCorrupt
	}
	return err
}

// Apply persists the operation or its waiting status. A rejected operation
// with no storage error is reported through syncmerge.Result.
func (s *Store) Apply(ctx context.Context, op syncmerge.Operation, source Source) (syncmerge.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return syncmerge.Result{}, ErrClosed
	}
	if source != Incoming && source != Local {
		return syncmerge.Result{}, syncmerge.ErrInvalidOperation
	}
	if err := checkOperation(op); err != nil {
		return syncmerge.Result{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return syncmerge.Result{}, storageError(err)
	}
	defer tx.Rollback()
	identity, generation, data, model, err := s.load(ctx, tx)
	if err != nil {
		return syncmerge.Result{}, storageError(err)
	}
	if identity != s.identity {
		return syncmerge.Result{}, ErrAuthentication
	}
	result, changed, err := data.apply(model, op, source)
	if err != nil {
		return syncmerge.Result{}, err
	}
	if !changed {
		return result, nil
	}
	if generation == math.MaxInt64 {
		return syncmerge.Result{}, ErrLimit
	}
	if err := s.write(ctx, tx, generation+1, data); err != nil {
		return syncmerge.Result{}, storageError(err)
	}
	if err := s.commit(tx); err != nil {
		return syncmerge.Result{}, err
	}
	return result, nil
}

func (s *Store) write(ctx context.Context, tx *sql.Tx, generation int64, data *state) error {
	encoded, err := data.encode()
	if err != nil {
		return err
	}
	defer clear(encoded)
	envelope, err := sealState(&s.key, s.identity, generation, encoded)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE replica SET generation=?, envelope=? WHERE id=1", generation, envelope)
	return err
}

func (s *Store) commit(tx *sql.Tx) error {
	if s.beforeCommit != nil {
		if err := s.beforeCommit(); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(ErrCommitUnknown, storageError(err))
	}
	if s.afterCommit != nil {
		if err := s.afterCommit(); err != nil {
			return errors.Join(ErrCommitUnknown, err)
		}
	}
	return nil
}

// Identity returns the replica ID pinned to this handle.
func (s *Store) Identity() [identitySize]byte { return s.identity }

// Read returns the committed state as a detached snapshot.
func (s *Store) Read(ctx context.Context) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return View{}, ErrClosed
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return View{}, storageError(err)
	}
	defer tx.Rollback()
	identity, _, data, model, err := s.load(ctx, tx)
	if err != nil {
		return View{}, storageError(err)
	}
	if identity != s.identity {
		return View{}, ErrAuthentication
	}
	return data.view(model), nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	clear(s.key[:])
	return err
}

func storageError(err error) error {
	switch {
	case errors.Is(err, sqlite3.BUSY), errors.Is(err, sqlite3.LOCKED):
		return errors.Join(ErrBusy, err)
	case errors.Is(err, sqlite3.CORRUPT), errors.Is(err, sqlite3.NOTADB):
		return errors.Join(ErrCorrupt, err)
	default:
		return err
	}
}
