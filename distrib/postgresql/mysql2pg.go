// migrate-mysql-to-postgres copies Ergo's history data from a MySQL database
// to a PostgreSQL database, reading connection details from an Ergo config file
// with both databases populated in `datastore` (neither database needs `enabled: true`
// to work.) It creates the PostgreSQL schema from scratch, then copies all data.
//
// WARNINGS:
// 1. This was tested with Ergo v2.18.0 only
// 2. It will destroy any preexisting data on the PostgreSQL side
// 3. It should not modify any data on the MySQL side, but make a backup first anyway
// 4. For best results, quiesce MySQL by stopping Ergo before running the migration
//
// Usage:
//
//	go run ./distrib/postgresql/mysql2pg -config /path/to/ircd.yaml
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"gopkg.in/yaml.v2"
)

const (
	maxTargetLength   = 64  // copied from irc/postgresql/config.go
	latestSchema      = "2" // copied from irc/postgresql/history.go
	latestMinorSchema = "2"
	batchSize         = 1000
)

// Minimal config structs matching the ergo YAML structure.
// Field names are lowercased by yaml.v2 when no tag is present.

type mysqlConfig struct {
	Host            string
	Port            int
	SocketPath      string `yaml:"socket-path"`
	User            string
	Password        string
	HistoryDatabase string `yaml:"history-database"`
}

type postgresConfig struct {
	Host            string
	Port            int
	SocketPath      string `yaml:"socket-path"`
	User            string
	Password        string
	HistoryDatabase string `yaml:"history-database"`
	URI             string `yaml:"uri"`
	SSLMode         string `yaml:"ssl-mode"`
}

type ergoConfig struct {
	Datastore struct {
		MySQL      mysqlConfig    `yaml:"mysql"`
		PostgreSQL postgresConfig `yaml:"postgresql"`
	}
}

// mysqlDSN builds a go-sql-driver/mysql DSN from config.
// Copied from irc/mysql/history.go (*MySQL).open().
func mysqlDSN(c mysqlConfig) string {
	var address string
	if c.SocketPath != "" {
		address = fmt.Sprintf("unix(%s)", c.SocketPath)
	} else {
		port := c.Port
		if port == 0 {
			port = 3306
		}
		address = fmt.Sprintf("tcp(%s:%d)", c.Host, port)
	}
	return fmt.Sprintf("%s:%s@%s/%s", c.User, c.Password, address, c.HistoryDatabase)
}

// postgresURI builds a libpq URI from config.
// Copied from irc/postgresql/history.go (*Config).buildURI().
func postgresURI(c postgresConfig) string {
	if c.URI != "" {
		return c.URI
	}
	u := &url.URL{
		Scheme: "postgresql",
		Path:   "/" + c.HistoryDatabase,
	}
	q := url.Values{}
	if c.SocketPath != "" {
		q.Set("host", c.SocketPath)
		if c.User != "" || c.Password != "" {
			u.User = url.UserPassword(c.User, c.Password)
		}
	} else {
		port := c.Port
		if port == 0 {
			port = 5432
		}
		host := c.Host
		if host == "" {
			host = "localhost"
		}
		u.Host = fmt.Sprintf("%s:%d", host, port)
		if c.User != "" || c.Password != "" {
			u.User = url.UserPassword(c.User, c.Password)
		}
	}
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()
	return u.String()
}

func main() {
	configPath := flag.String("config", "ircd.yaml", "path to ergo config file")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var config ergoConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	mysqlDB, err := sql.Open("mysql", mysqlDSN(config.Datastore.MySQL))
	if err != nil {
		log.Fatalf("open mysql: %v", err)
	}
	defer mysqlDB.Close()
	if err := mysqlDB.Ping(); err != nil {
		log.Fatalf("ping mysql: %v", err)
	}
	log.Println("connected to MySQL")

	pgDB, err := sql.Open("pgx", postgresURI(config.Datastore.PostgreSQL))
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer pgDB.Close()
	if err := pgDB.Ping(); err != nil {
		log.Fatalf("ping postgres: %v", err)
	}
	log.Println("connected to PostgreSQL")

	log.Println("setting up PostgreSQL schema")
	if err := setupSchema(pgDB); err != nil {
		log.Fatalf("setup schema: %v", err)
	}

	tables := []struct {
		name string
		fn   func(*sql.DB, *sql.DB) (int, error)
	}{
		{"history", copyHistory},
		{"sequence", copySequence},
		{"conversations", copyConversations},
		{"correspondents", copyCorrespondents},
		{"account_messages", copyAccountMessages},
		{"forget", copyForget},
	}
	for _, t := range tables {
		log.Printf("copying %s...", t.name)
		n, err := t.fn(mysqlDB, pgDB)
		if err != nil {
			log.Fatalf("copy %s: %v", t.name, err)
		}
		log.Printf("  %d rows", n)
	}

	log.Println("resetting sequences")
	if err := resetSequences(pgDB); err != nil {
		log.Fatalf("reset sequences: %v", err)
	}

	log.Println("done")
}

// setupSchema drops and recreates all tables and indexes.
// Table definitions and indexes are copied from irc/postgresql/history.go.
func setupSchema(db *sql.DB) error {
	drops := []string{
		"DROP TABLE IF EXISTS forget CASCADE",
		"DROP TABLE IF EXISTS account_messages CASCADE",
		"DROP TABLE IF EXISTS correspondents CASCADE",
		"DROP TABLE IF EXISTS conversations CASCADE",
		"DROP TABLE IF EXISTS sequence CASCADE",
		"DROP TABLE IF EXISTS history CASCADE",
		"DROP TABLE IF EXISTS metadata CASCADE",
	}
	for _, stmt := range drops {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}

	stmts := []string{
		`CREATE TABLE metadata (
			key_name VARCHAR(32) PRIMARY KEY,
			value VARCHAR(32) NOT NULL
		)`,

		`CREATE TABLE history (
			id BIGSERIAL PRIMARY KEY,
			data BYTEA NOT NULL,
			msgid BYTEA NOT NULL CHECK (octet_length(msgid) = 16)
		)`,
		`CREATE INDEX idx_history_msgid ON history (msgid)`,

		fmt.Sprintf(`CREATE TABLE sequence (
			history_id BIGINT NOT NULL PRIMARY KEY,
			target BYTEA NOT NULL CHECK (octet_length(target) <= %d),
			nanotime BIGINT NOT NULL CHECK (nanotime >= 0)
		)`, maxTargetLength),
		`CREATE INDEX idx_sequence_target_nanotime ON sequence (target, nanotime)`,

		fmt.Sprintf(`CREATE TABLE conversations (
			id BIGSERIAL PRIMARY KEY,
			target BYTEA NOT NULL CHECK (octet_length(target) <= %d),
			correspondent BYTEA NOT NULL CHECK (octet_length(correspondent) <= %d),
			nanotime BIGINT NOT NULL CHECK (nanotime >= 0),
			history_id BIGINT NOT NULL
		)`, maxTargetLength, maxTargetLength),
		`CREATE INDEX idx_conversations_target_correspondent_nanotime ON conversations (target, correspondent, nanotime)`,
		`CREATE INDEX idx_conversations_history_id ON conversations (history_id)`,

		fmt.Sprintf(`CREATE TABLE correspondents (
			id BIGSERIAL PRIMARY KEY,
			target BYTEA NOT NULL CHECK (octet_length(target) <= %d),
			correspondent BYTEA NOT NULL CHECK (octet_length(correspondent) <= %d),
			nanotime BIGINT NOT NULL CHECK (nanotime >= 0),
			UNIQUE (target, correspondent)
		)`, maxTargetLength, maxTargetLength),
		`CREATE INDEX idx_correspondents_target_nanotime ON correspondents (target, nanotime)`,
		`CREATE INDEX idx_correspondents_nanotime ON correspondents (nanotime)`,

		fmt.Sprintf(`CREATE TABLE account_messages (
			history_id BIGINT NOT NULL PRIMARY KEY,
			account BYTEA NOT NULL CHECK (octet_length(account) <= %d)
		)`, maxTargetLength),
		`CREATE INDEX idx_account_messages_account_history_id ON account_messages (account, history_id)`,

		fmt.Sprintf(`CREATE TABLE forget (
			id BIGSERIAL PRIMARY KEY,
			account BYTEA NOT NULL CHECK (octet_length(account) <= %d)
		)`, maxTargetLength),
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("exec: %w\nstatement: %s", err, stmt)
		}
	}

	_, err := db.Exec(
		`INSERT INTO metadata (key_name, value) VALUES ($1, $2), ($3, $4)`,
		"db.version", latestSchema, "db.minorversion", latestMinorSchema,
	)
	return err
}

func copyHistory(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT id, data, msgid FROM history WHERE id > ? ORDER BY id LIMIT ?",
		"INSERT INTO history (id, data, msgid) VALUES ($1, $2, $3)",
		3,
	)
}

func copySequence(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT history_id, target, nanotime FROM sequence WHERE history_id > ? ORDER BY history_id LIMIT ?",
		"INSERT INTO sequence (history_id, target, nanotime) VALUES ($1, $2, $3)",
		3,
	)
}

func copyConversations(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT id, target, correspondent, nanotime, history_id FROM conversations WHERE id > ? ORDER BY id LIMIT ?",
		"INSERT INTO conversations (id, target, correspondent, nanotime, history_id) VALUES ($1, $2, $3, $4, $5)",
		5,
	)
}

func copyCorrespondents(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT id, target, correspondent, nanotime FROM correspondents WHERE id > ? ORDER BY id LIMIT ?",
		"INSERT INTO correspondents (id, target, correspondent, nanotime) VALUES ($1, $2, $3, $4)",
		4,
	)
}

func copyAccountMessages(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT history_id, account FROM account_messages WHERE history_id > ? ORDER BY history_id LIMIT ?",
		"INSERT INTO account_messages (history_id, account) VALUES ($1, $2)",
		2,
	)
}

func copyForget(src, dst *sql.DB) (int, error) {
	return copyBatched(src, dst,
		"SELECT id, account FROM forget WHERE id > ? ORDER BY id LIMIT ?",
		"INSERT INTO forget (id, account) VALUES ($1, $2)",
		2,
	)
}

// copyBatched copies rows from src to dst in batches using keyset pagination on
// the first (primary key) column. srcQuery must accept (lastID int64, limit int)
// and return rows ordered by that column. One transaction is committed per batch.
func copyBatched(src, dst *sql.DB, srcQuery, dstInsert string, ncols int) (int, error) {
	vals := make([]any, ncols)
	ptrs := make([]any, ncols)
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	var lastID int64
	total := 0
	for {
		rows, err := src.Query(srcQuery, lastID, batchSize)
		if err != nil {
			return total, fmt.Errorf("query: %w", err)
		}

		tx, err := dst.Begin()
		if err != nil {
			rows.Close()
			return total, fmt.Errorf("begin tx: %w", err)
		}

		batchCount := 0
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				tx.Rollback()
				return total, fmt.Errorf("scan: %w", err)
			}
			// MySQL returns BIGINT UNSIGNED as uint64; convert to int64 for PostgreSQL.
			for i, v := range vals {
				if u, ok := v.(uint64); ok {
					vals[i] = int64(u)
				}
			}
			if _, err := tx.Exec(dstInsert, vals...); err != nil {
				rows.Close()
				tx.Rollback()
				return total, fmt.Errorf("insert: %w", err)
			}
			if id, ok := vals[0].(int64); ok {
				lastID = id
			}
			batchCount++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			tx.Rollback()
			return total, fmt.Errorf("rows: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return total, fmt.Errorf("commit: %w", err)
		}
		total += batchCount
		log.Printf("  %d rows copied so far", total)
		if batchCount < batchSize {
			break
		}
	}
	return total, nil
}

func resetSequences(db *sql.DB) error {
	seqs := []struct{ seq, table, col string }{
		{"history_id_seq", "history", "id"},
		{"conversations_id_seq", "conversations", "id"},
		{"correspondents_id_seq", "correspondents", "id"},
		{"forget_id_seq", "forget", "id"},
	}
	for _, s := range seqs {
		if _, err := db.Exec(fmt.Sprintf(
			"SELECT setval('%s', COALESCE((SELECT MAX(%s) FROM %s), 1))",
			s.seq, s.col, s.table,
		)); err != nil {
			return fmt.Errorf("reset %s: %w", s.seq, err)
		}
	}
	return nil
}
