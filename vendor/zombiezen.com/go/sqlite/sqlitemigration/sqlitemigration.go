// Copyright 2021 Roxy Light
// SPDX-License-Identifier: ISC

// Package sqlitemigration provides a connection pool type that guarantees a
// series of SQL scripts has been run once successfully before making
// connections available to the application. This is frequently useful for
// ensuring tables are created.
package sqlitemigration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// Schema defines the migrations for the application.
type Schema struct {
	// Migrations is a list of SQL scripts to run.
	// Each script is wrapped in a transaction which is rolled back on any error.
	Migrations []string

	// MigrationOptions specifies options for each migration.
	// len(MigrationOptions) must not be greater than len(Migrations).
	MigrationOptions []*MigrationOptions

	// AppID is saved to the database file to identify the application.
	// It's an optional measure to prevent opening database files for a different application.
	// It must not change between runs of the same program.
	//
	// A common way of setting this is with a compile-time constant that was randomly generated.
	// `head -c 4 /dev/urandom | xxd -p` can generate such an ID.
	AppID int32

	// RepeatableMigration is a SQL script to run if any migrations ran.
	// The script is run as part of the final migration's transaction.
	RepeatableMigration string
}

// MigrationOptions holds optional parameters for a migration.
type MigrationOptions struct {
	// If DisableForeignKeys is true, then before starting the migration's
	// transaction, "PRAGMA foreign_keys = off;" will be executed. After the
	// migration's transaction completes, then the "PRAGMA foreign_keys" setting
	// will be restored to the value it was before executing
	// "PRAGMA foreign_keys = off;".
	DisableForeignKeys bool
}

// Options specifies optional behaviors for the pool.
type Options struct {
	// Flags is interpreted the same way as the argument to [sqlitex.PoolOptions].
	Flags sqlite.OpenFlags

	// PoolSize sets an explicit size to the pool. If less than 1, a reasonable
	// default is used.
	PoolSize int

	// OnStartMigrate is called after the pool has successfully opened a
	// connection to the database but before any migrations have been run.
	OnStartMigrate SignalFunc
	// OnReady is called after the pool has connected to the database and run any
	// necessary migrations.
	OnReady SignalFunc
	// OnError is called when the pool encounters errors while applying the
	// migration. This is typically used for logging errors.
	OnError ReportFunc

	// PrepareConn is called for each connection in the pool to set up functions
	// and other connection-specific state.
	PrepareConn ConnPrepareFunc
}

// Pool is a pool of SQLite connections.
type Pool struct {
	retry  chan struct{}
	opts   Options
	cancel context.CancelFunc

	ready <-chan struct{} // protects the following fields
	pool  *sqlitex.Pool
	err   error

	closedMu sync.RWMutex
	closed   bool
}

// NewPool opens a new pool of SQLite connections.
func NewPool(uri string, schema Schema, opts Options) *Pool {
	ready := make(chan struct{})
	retry := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{
		retry:  retry,
		opts:   opts,
		cancel: cancel,
		ready:  ready,
	}
	go func() {
		defer close(ready)
		defer cancel()
		p.pool, p.err = p.open(ctx, uri, schema)
		if p.err != nil {
			opts.OnError.call(p.err)
		}
	}()
	return p
}

// Close closes all connections in the Pool, potentially interrupting
// a migration.
func (p *Pool) Close() error {
	p.closedMu.Lock()
	if p.closed {
		p.closedMu.Unlock()
		return errors.New("close sqlite pool: already closed")
	}
	p.closed = true
	p.closedMu.Unlock()

	p.cancel()
	<-p.ready
	if p.pool == nil {
		return nil
	}
	return p.pool.Close()
}

// Get obtains an SQLite connection from the pool,
// waiting until the initial migration is complete.
// Get is identical to [Pool.Take].
//
// If no connection is available,
// Get will block until at least one connection is returned with [Pool.Put],
// or until either the Pool is closed or the context is canceled.
// If no connection can be obtained
// or an error occurs while preparing the connection,
// an error is returned.
//
// The provided context is also used to control the execution lifetime of the connection.
// See [sqlite.Conn.SetInterrupt] for details.
//
// Applications must ensure that all non-nil Conns returned from Get
// are returned to the same Pool with [Pool.Put].
func (p *Pool) Get(ctx context.Context) (*sqlite.Conn, error) {
	return p.Take(ctx)
}

// Take obtains an SQLite connection from the pool,
// waiting until the initial migration is complete.
//
// If no connection is available,
// Take will block until at least one connection is returned with [Pool.Put],
// or until either the Pool is closed or the context is canceled.
// If no connection can be obtained
// or an error occurs while preparing the connection,
// an error is returned.
//
// The provided context is also used to control the execution lifetime of the connection.
// See [sqlite.Conn.SetInterrupt] for details.
//
// Applications must ensure that all non-nil Conns returned from Take
// are returned to the same Pool with [Pool.Put].
func (p *Pool) Take(ctx context.Context) (*sqlite.Conn, error) {
	tick := time.NewTicker(5 * time.Second)
	for ready := false; !ready; {
		// Inform Pool.open to keep trying.
		select {
		case p.retry <- struct{}{}:
		default:
		}

		select {
		case <-tick.C:
			// Another try.
		case <-p.ready:
			ready = true
		case <-ctx.Done():
			tick.Stop()
			return nil, fmt.Errorf("get sqlite connection: %w", ctx.Err())
		}
	}
	tick.Stop()

	if p.err != nil {
		return nil, fmt.Errorf("get sqlite connection: %w", p.err)
	}
	conn, err := p.pool.Take(ctx)
	if err != nil {
		return nil, fmt.Errorf("get sqlite connection: %w", err)
	}
	return conn, nil
}

// Put puts an SQLite connection back into the pool.
// See sqlitex.Pool for details.
func (p *Pool) Put(conn *sqlite.Conn) {
	select {
	case <-p.ready:
	default:
		panic("Pool.Put before pool is ready")
	}
	if p.err != nil {
		panic("Pool.Put on failed pool")
	}
	p.pool.Put(conn)
}

// CheckHealth returns an error if the migration has not completed.
// Closed pools may report healthy.
func (p *Pool) CheckHealth() error {
	p.closedMu.RLock()
	closed := p.closed
	p.closedMu.RUnlock()
	if closed {
		return errors.New("sqlite pool health: closed")
	}

	select {
	case <-p.ready:
		if p.err != nil {
			return fmt.Errorf("sqlite pool health: %w", p.err)
		}
		return nil
	default:
		return errors.New("sqlite pool health: not ready")
	}
}

func (p *Pool) open(ctx context.Context, uri string, schema Schema) (*sqlitex.Pool, error) {
	for first := true; ; first = false {
		if !first {
			select {
			case <-p.retry:
			case <-ctx.Done():
				return nil, errors.New("closed before successful migration")
			}
		}

		pool, err := sqlitex.NewPool(uri, sqlitex.PoolOptions{
			Flags:       p.opts.Flags,
			PoolSize:    p.opts.PoolSize,
			PrepareConn: p.opts.PrepareConn,
		})
		if err != nil {
			p.opts.OnError.call(err)
			continue
		}

		conn, err := pool.Take(ctx)
		if isDone(err) {
			pool.Close()
			return nil, errors.New("closed before successful migration")
		}
		if err != nil {
			if closeErr := pool.Close(); closeErr != nil {
				p.opts.OnError.call(fmt.Errorf("close after failed connection preparation: %w", closeErr))
			}
			return nil, err
		}

		err = migrateDB(ctx, conn, schema, p.opts.OnStartMigrate)
		pool.Put(conn)
		if err != nil {
			if closeErr := pool.Close(); closeErr != nil {
				p.opts.OnError.call(fmt.Errorf("close after failed migration: %w", closeErr))
			}
			return nil, err
		}
		p.opts.OnReady.call()
		return pool, nil
	}
}

// Migrate performs any unapplied migrations in the schema on the database.
func Migrate(ctx context.Context, conn *sqlite.Conn, schema Schema) error {
	return migrateDB(ctx, conn, schema, nil)
}

func migrateDB(ctx context.Context, conn *sqlite.Conn, schema Schema, onStart SignalFunc) error {
	defer conn.SetInterrupt(conn.SetInterrupt(ctx.Done()))

	schemaVersion, err := ensureAppID(conn, schema.AppID)
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	onStart.call()

	var foreignKeysEnabled bool
	err = sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys;", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			foreignKeysEnabled = stmt.ColumnBool(0)
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	beginStmt, _, err := conn.PrepareTransient("BEGIN IMMEDIATE;")
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	defer beginStmt.Finalize()
	commitStmt, _, err := conn.PrepareTransient("COMMIT;")
	if err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	defer commitStmt.Finalize()
	for ; int(schemaVersion) < len(schema.Migrations); schemaVersion++ {
		migration := schema.Migrations[schemaVersion]
		disableFKs := foreignKeysEnabled &&
			int(schemaVersion) < len(schema.MigrationOptions) &&
			schema.MigrationOptions[schemaVersion] != nil &&
			schema.MigrationOptions[schemaVersion].DisableForeignKeys
		if disableFKs {
			// Do not try to optimize by preparing this PRAGMA statement ahead of time.
			if err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = off;", nil); err != nil {
				return fmt.Errorf("migrate database: disable foreign keys: %w", err)
			}
		}

		if err := stepAndReset(beginStmt); err != nil {
			return fmt.Errorf("migrate database: apply migrations[%d]: %w", schemaVersion, err)
		}
		actualSchemaVersion, err := userVersion(conn)
		if err != nil {
			rollback(conn)
			return fmt.Errorf("migrate database: %w", err)
		}
		if actualSchemaVersion != schemaVersion {
			// A different process migrated while we were not inside a transaction.
			rollback(conn)
			schemaVersion = actualSchemaVersion - 1
			continue
		}

		err = sqlitex.ExecScript(conn, fmt.Sprintf("%s;\nPRAGMA user_version = %d;\n", migration, schemaVersion+1))
		if err != nil {
			rollback(conn)
			return fmt.Errorf("migrate database: apply migrations[%d]: %w", schemaVersion, err)
		}
		if int(schemaVersion) == len(schema.Migrations)-1 && schema.RepeatableMigration != "" {
			if err := sqlitex.ExecScript(conn, schema.RepeatableMigration); err != nil {
				rollback(conn)
				return fmt.Errorf("migrate database: apply repeatable migration: %w", err)
			}
		}

		if err := stepAndReset(commitStmt); err != nil {
			rollback(conn)
			return fmt.Errorf("migrate database: apply migrations[%d]: %w", schemaVersion, err)
		}
		if disableFKs {
			if err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = on;", nil); err != nil {
				return fmt.Errorf("migrate database: reenable foreign keys: %w", err)
			}
		}
	}
	return nil
}

func userVersion(conn *sqlite.Conn) (int32, error) {
	var version int32
	err := sqlitex.ExecuteTransient(conn, "PRAGMA user_version;", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			version = stmt.ColumnInt32(0)
			return nil
		},
	})
	if err != nil {
		return 0, fmt.Errorf("get database user_version: %w", err)
	}
	return version, nil
}

func rollback(conn *sqlite.Conn) {
	if conn.AutocommitEnabled() {
		return
	}
	sqlitex.ExecuteTransient(conn, "ROLLBACK;", nil)
}

func ensureAppID(conn *sqlite.Conn, wantAppID int32) (schemaVersion int32, err error) {
	// This transaction will later be upgraded to a write transaction. If at the point of upgrading
	// to a write transaction, the database is locked, SQLite will fail immediately with
	// SQLITE_BUSY and the busy timeout will have no effect, causing the pool to fail.
	//
	// If we use an immediate transaction, telling SQLite this is a write transaction, SQLite
	// will attempt to lock the database immediately. If a lock cannot be acquired, the busy
	// timeout is used allowing the transaction to wait until it can get a lock, thus allowing the
	// pool to start successfully.
	end, err := sqlitex.ImmediateTransaction(conn)
	if err != nil {
		return 0, err
	}
	defer end(&err)

	var hasSchema bool
	err = sqlitex.ExecuteTransient(conn, "VALUES ((SELECT COUNT(*) FROM sqlite_master) > 0);", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			hasSchema = stmt.ColumnInt(0) != 0
			return nil
		},
	})
	if err != nil {
		return 0, err
	}
	var dbAppID int32
	err = sqlitex.ExecuteTransient(conn, "PRAGMA application_id;", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			dbAppID = stmt.ColumnInt32(0)
			return nil
		},
	})
	if err != nil {
		return 0, err
	}
	if dbAppID != wantAppID && !(dbAppID == 0 && !hasSchema) {
		return 0, fmt.Errorf("database application_id = %#x (expected %#x)", dbAppID, wantAppID)
	}
	schemaVersion, err = userVersion(conn)
	if err != nil {
		return 0, err
	}
	// Using Sprintf because PRAGMAs don't permit arbitrary expressions, and thus
	// don't permit using parameter substitution.
	err = sqlitex.ExecuteTransient(conn, fmt.Sprintf("PRAGMA application_id = %d;", wantAppID), nil)
	if err != nil {
		return 0, err
	}
	return schemaVersion, nil
}

// A SignalFunc is called at most once when a particular event in a Pool's
// lifecycle occurs.
type SignalFunc func()

func (f SignalFunc) call() {
	if f == nil {
		return
	}
	f()
}

// A ReportFunc is called for transient errors the pool encounters while
// running the migrations. It must be safe to call from multiple goroutines.
type ReportFunc func(error)

func (f ReportFunc) call(err error) {
	if f == nil {
		return
	}
	f(err)
}

// A ConnPrepareFunc is called for each connection in a pool
// to set up connection-specific state.
// It must be safe to call from multiple goroutines.
//
// If the ConnPrepareFunc returns an error,
// then it will be called the next time the connection is about to be used.
// Once ConnPrepareFunc returns nil for a given connection,
// it will not be called on that connection again.
type ConnPrepareFunc = sqlitex.ConnPrepareFunc

func stepAndReset(stmt *sqlite.Stmt) error {
	if _, err := stmt.Step(); err != nil {
		return err
	}
	return stmt.Reset()
}

// isDone reports whether an error indicates cancellation or deadline exceeded
// from a [context.Context]
func isDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
