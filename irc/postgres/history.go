//go:build postgres

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/utils"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Enabled is true when PostgreSQL support is compiled in
const Enabled = true

const (
	// latest schema of the db
	latestDbSchema   = "2"
	keySchemaVersion = "db.version"
	// minor version indicates rollback-safe upgrades, i.e.,
	// you can downgrade oragono and everything will work
	latestDbMinorVersion  = "2"
	keySchemaMinorVersion = "db.minorversion"
	cleanupRowLimit       = 50
	cleanupPauseTime      = 10 * time.Minute
)

type e struct{}

type PostgreSQL struct {
	db     *sql.DB
	logger *logger.Manager

	insertHistory        *sql.Stmt
	insertSequence       *sql.Stmt
	insertConversation   *sql.Stmt
	insertCorrespondent  *sql.Stmt
	insertAccountMessage *sql.Stmt

	stateMutex sync.Mutex
	config     Config

	wakeForgetter chan e

	timeout              atomic.Uint64
	trackAccountMessages atomic.Uint32
}

var _ history.Database = (*PostgreSQL)(nil)

func NewPostgreSQLDatabase(logger *logger.Manager, config Config) (*PostgreSQL, error) {
	var pg PostgreSQL

	pg.logger = logger
	pg.wakeForgetter = make(chan e, 1)
	pg.SetConfig(config)

	return &pg, pg.open()
}

func (pg *PostgreSQL) SetConfig(config Config) {
	pg.timeout.Store(uint64(config.Timeout))
	var trackAccountMessages uint32
	if config.TrackAccountMessages {
		trackAccountMessages = 1
	}
	pg.trackAccountMessages.Store(trackAccountMessages)
	pg.stateMutex.Lock()
	pg.config = config
	pg.stateMutex.Unlock()
}

func (pg *PostgreSQL) getExpireTime() (expireTime time.Duration) {
	pg.stateMutex.Lock()
	expireTime = pg.config.ExpireTime
	pg.stateMutex.Unlock()
	return
}

func (pg *PostgreSQL) open() (err error) {
	// Build PostgreSQL connection string
	var connString string
	if pg.config.SocketPath != "" {
		// PostgreSQL uses host parameter for Unix socket directory
		connString = fmt.Sprintf("host=%s user=%s password=%s dbname=%s",
			pg.config.SocketPath, pg.config.User, pg.config.Password, pg.config.HistoryDatabase)
	} else {
		// TCP connection
		port := pg.config.Port
		if port == 0 {
			port = 5432 // Default PostgreSQL port
		}
		sslMode := pg.config.SSLMode
		if sslMode == "" {
			sslMode = "disable"
		}
		connString = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			pg.config.Host, port, pg.config.User, pg.config.Password, pg.config.HistoryDatabase, sslMode)

		// Add SSL certificate paths if provided
		if pg.config.SSLCert != "" {
			connString += fmt.Sprintf(" sslcert=%s", pg.config.SSLCert)
		}
		if pg.config.SSLKey != "" {
			connString += fmt.Sprintf(" sslkey=%s", pg.config.SSLKey)
		}
		if pg.config.SSLRootCert != "" {
			connString += fmt.Sprintf(" sslrootcert=%s", pg.config.SSLRootCert)
		}
	}

	// Add optional PostgreSQL-specific parameters
	if pg.config.ApplicationName != "" {
		connString += fmt.Sprintf(" application_name=%s", pg.config.ApplicationName)
	}
	if pg.config.ConnectTimeout != 0 {
		connString += fmt.Sprintf(" connect_timeout=%d", int(pg.config.ConnectTimeout.Seconds()))
	}

	pg.db, err = sql.Open("pgx", connString)
	if err != nil {
		return err
	}

	if pg.config.MaxConns != 0 {
		pg.db.SetMaxOpenConns(pg.config.MaxConns)
		pg.db.SetMaxIdleConns(pg.config.MaxConns)
	}
	if pg.config.ConnMaxLifetime != 0 {
		pg.db.SetConnMaxLifetime(pg.config.ConnMaxLifetime)
	}

	err = pg.fixSchemas()
	if err != nil {
		return err
	}

	err = pg.prepareStatements()
	if err != nil {
		return err
	}

	go pg.cleanupLoop()
	go pg.forgetLoop()

	return nil
}

func (pg *PostgreSQL) fixSchemas() (err error) {
	_, err = pg.db.Exec(`CREATE TABLE IF NOT EXISTS metadata (
		key_name VARCHAR(32) PRIMARY KEY,
		value VARCHAR(32) NOT NULL
	);`)
	if err != nil {
		return err
	}

	var schema string
	err = pg.db.QueryRow(`SELECT value FROM metadata WHERE key_name = $1;`, keySchemaVersion).Scan(&schema)
	if err == sql.ErrNoRows {
		err = pg.createTables()
		if err != nil {
			return
		}
		_, err = pg.db.Exec(`INSERT INTO metadata (key_name, value) VALUES ($1, $2);`, keySchemaVersion, latestDbSchema)
		if err != nil {
			return
		}
		_, err = pg.db.Exec(`INSERT INTO metadata (key_name, value) VALUES ($1, $2);`, keySchemaMinorVersion, latestDbMinorVersion)
		if err != nil {
			return
		}
		return
	} else if err == nil && schema != latestDbSchema {
		// TODO figure out what to do about schema changes
		return fmt.Errorf("incompatible schema: got %s, expected %s", schema, latestDbSchema)
	} else if err != nil {
		return err
	}

	var minorVersion string
	err = pg.db.QueryRow(`SELECT value FROM metadata WHERE key_name = $1;`, keySchemaMinorVersion).Scan(&minorVersion)
	if err == sql.ErrNoRows {
		// XXX for now, the only minor version upgrade is the account tracking tables
		err = pg.createComplianceTables()
		if err != nil {
			return
		}
		err = pg.createCorrespondentsTable()
		if err != nil {
			return
		}
		_, err = pg.db.Exec(`INSERT INTO metadata (key_name, value) VALUES ($1, $2);`, keySchemaMinorVersion, latestDbMinorVersion)
		if err != nil {
			return
		}
	} else if err == nil && minorVersion == "1" {
		// upgrade from 2.1 to 2.2: create the correspondents table
		err = pg.createCorrespondentsTable()
		if err != nil {
			return
		}
		_, err = pg.db.Exec(`UPDATE metadata SET value = $1 WHERE key_name = $2;`, latestDbMinorVersion, keySchemaMinorVersion)
		if err != nil {
			return
		}
	} else if err == nil && minorVersion != latestDbMinorVersion {
		// TODO: if minorVersion < latestDbMinorVersion, upgrade,
		// if latestDbMinorVersion < minorVersion, ignore because backwards compatible
	}
	return
}

func (pg *PostgreSQL) createTables() (err error) {
	_, err = pg.db.Exec(`CREATE TABLE history (
		id BIGSERIAL PRIMARY KEY,
		data BYTEA NOT NULL,
		msgid BYTEA NOT NULL CHECK (octet_length(msgid) = 16)
	);`)
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_history_msgid ON history (msgid);`)
	if err != nil {
		return err
	}

	_, err = pg.db.Exec(fmt.Sprintf(`CREATE TABLE sequence (
		history_id BIGINT NOT NULL PRIMARY KEY,
		target BYTEA NOT NULL CHECK (octet_length(target) <= %[1]d),
		nanotime BIGINT NOT NULL CHECK (nanotime >= 0)
	);`, MaxTargetLength))
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_sequence_target_nanotime ON sequence (target, nanotime);`)
	if err != nil {
		return err
	}

	_, err = pg.db.Exec(fmt.Sprintf(`CREATE TABLE conversations (
		id BIGSERIAL PRIMARY KEY,
		target BYTEA NOT NULL CHECK (octet_length(target) <= %[1]d),
		correspondent BYTEA NOT NULL CHECK (octet_length(correspondent) <= %[1]d),
		nanotime BIGINT NOT NULL CHECK (nanotime >= 0),
		history_id BIGINT NOT NULL
	);`, MaxTargetLength))
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_conversations_target_correspondent_nanotime ON conversations (target, correspondent, nanotime);`)
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_conversations_history_id ON conversations (history_id);`)
	if err != nil {
		return err
	}

	err = pg.createCorrespondentsTable()
	if err != nil {
		return err
	}

	err = pg.createComplianceTables()
	if err != nil {
		return err
	}

	return nil
}

func (pg *PostgreSQL) createCorrespondentsTable() (err error) {
	_, err = pg.db.Exec(fmt.Sprintf(`CREATE TABLE correspondents (
		id BIGSERIAL PRIMARY KEY,
		target BYTEA NOT NULL CHECK (octet_length(target) <= %[1]d),
		correspondent BYTEA NOT NULL CHECK (octet_length(correspondent) <= %[1]d),
		nanotime BIGINT NOT NULL CHECK (nanotime >= 0),
		UNIQUE (target, correspondent)
	);`, MaxTargetLength))
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_correspondents_target_nanotime ON correspondents (target, nanotime);`)
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_correspondents_nanotime ON correspondents (nanotime);`)
	return
}

func (pg *PostgreSQL) createComplianceTables() (err error) {
	_, err = pg.db.Exec(fmt.Sprintf(`CREATE TABLE account_messages (
		history_id BIGINT NOT NULL PRIMARY KEY,
		account BYTEA NOT NULL CHECK (octet_length(account) <= %[1]d)
	);`, MaxTargetLength))
	if err != nil {
		return err
	}
	_, err = pg.db.Exec(`CREATE INDEX idx_account_messages_account_history_id ON account_messages (account, history_id);`)
	if err != nil {
		return err
	}

	_, err = pg.db.Exec(fmt.Sprintf(`CREATE TABLE forget (
		id BIGSERIAL PRIMARY KEY,
		account BYTEA NOT NULL CHECK (octet_length(account) <= %[1]d)
	);`, MaxTargetLength))
	if err != nil {
		return err
	}

	return nil
}

func (pg *PostgreSQL) cleanupLoop() {
	defer func() {
		if r := recover(); r != nil {
			pg.logger.Error("postgres",
				fmt.Sprintf("Panic in cleanup routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go pg.cleanupLoop()
		}
	}()

	for {
		expireTime := pg.getExpireTime()
		if expireTime != 0 {
			for {
				startTime := time.Now()
				rowsDeleted, err := pg.doCleanup(expireTime)
				elapsed := time.Now().Sub(startTime)
				pg.logError("error during row cleanup", err)
				// keep going as long as we're accomplishing significant work
				// (don't busy-wait on small numbers of rows expiring):
				if rowsDeleted < (cleanupRowLimit / 10) {
					break
				}
				// crude backpressure mechanism: if the database is slow,
				// give it time to process other queries
				time.Sleep(elapsed)
			}
		}
		time.Sleep(cleanupPauseTime)
	}
}

func (pg *PostgreSQL) doCleanup(age time.Duration) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	ids, maxNanotime, err := pg.selectCleanupIDs(ctx, age)
	if len(ids) == 0 {
		pg.logger.Debug("postgres", "found no rows to clean up")
		return
	}

	pg.logger.Debug("postgres", fmt.Sprintf("deleting %d history rows, max age %s", len(ids), utils.NanoToTimestamp(maxNanotime)))

	if maxNanotime != 0 {
		pg.deleteCorrespondents(ctx, maxNanotime)
	}

	return len(ids), pg.deleteHistoryIDs(ctx, ids)
}

func (pg *PostgreSQL) deleteHistoryIDs(ctx context.Context, ids []uint64) (err error) {
	// can't use ? binding for a variable number of arguments, build the IN clause manually
	var inBuf strings.Builder
	inBuf.WriteByte('(')
	for i, id := range ids {
		if i != 0 {
			inBuf.WriteRune(',')
		}
		fmt.Fprintf(&inBuf, "%d", id)
	}
	inBuf.WriteRune(')')
	inClause := inBuf.String()

	_, err = pg.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM conversations WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	_, err = pg.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM sequence WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	if pg.isTrackingAccountMessages() {
		_, err = pg.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM account_messages WHERE history_id in %s;`, inClause))
		if err != nil {
			return
		}
	}
	_, err = pg.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM history WHERE id in %s;`, inClause))
	if err != nil {
		return
	}

	return
}

func (pg *PostgreSQL) selectCleanupIDs(ctx context.Context, age time.Duration) (ids []uint64, maxNanotime int64, err error) {
	rows, err := pg.db.QueryContext(ctx, `
		SELECT history.id, sequence.nanotime, conversations.nanotime
		FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		LEFT JOIN conversations on history.id = conversations.history_id
		ORDER BY history.id LIMIT $1;`, cleanupRowLimit)
	if err != nil {
		return
	}
	defer rows.Close()

	idset := make(map[uint64]struct{}, cleanupRowLimit)
	threshold := time.Now().Add(-age).UnixNano()
	for rows.Next() {
		var id uint64
		var seqNano, convNano sql.NullInt64
		err = rows.Scan(&id, &seqNano, &convNano)
		if err != nil {
			return
		}
		nanotime := extractNanotime(seqNano, convNano)
		// returns 0 if not found; in that case the data is inconsistent
		// and we should delete the entry
		if nanotime < threshold {
			idset[id] = struct{}{}
			if nanotime > maxNanotime {
				maxNanotime = nanotime
			}
		}
	}
	ids = make([]uint64, len(idset))
	i := 0
	for id := range idset {
		ids[i] = id
		i++
	}
	return
}

func (pg *PostgreSQL) deleteCorrespondents(ctx context.Context, threshold int64) {
	result, err := pg.db.ExecContext(ctx, `DELETE FROM correspondents WHERE nanotime <= $1;`, threshold)
	if err != nil {
		pg.logError("error deleting correspondents", err)
	} else {
		count, err := result.RowsAffected()
		if !pg.logError("error deleting correspondents", err) {
			pg.logger.Debug("postgres", fmt.Sprintf("deleted %d correspondents entries", count))
		}
	}
}

// wait for forget queue items and process them one by one
func (pg *PostgreSQL) forgetLoop() {
	defer func() {
		if r := recover(); r != nil {
			pg.logger.Error("postgres",
				fmt.Sprintf("Panic in forget routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go pg.forgetLoop()
		}
	}()

	for {
		for {
			found, err := pg.doForget()
			pg.logError("error processing forget", err)
			if err != nil {
				time.Sleep(cleanupPauseTime)
			}
			if !found {
				break
			}
		}

		<-pg.wakeForgetter
	}
}

// dequeue an item from the forget queue and process it
func (pg *PostgreSQL) doForget() (found bool, err error) {
	id, account, err := func() (id int64, account string, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
		defer cancel()

		row := pg.db.QueryRowContext(ctx,
			`SELECT forget.id, forget.account FROM forget LIMIT 1;`)
		err = row.Scan(&id, &account)
		if err == sql.ErrNoRows {
			return 0, "", nil
		}
		return
	}()

	if err != nil || account == "" {
		return false, err
	}

	found = true

	var count int
	for {
		start := time.Now()
		count, err = pg.doForgetIteration(account)
		elapsed := time.Since(start)
		if err != nil {
			return true, err
		}
		if count == 0 {
			break
		}
		time.Sleep(elapsed)
	}

	pg.logger.Debug("postgres", "forget complete for account", account)

	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()
	_, err = pg.db.ExecContext(ctx, `DELETE FROM forget WHERE id = $1;`, id)
	return
}

func (pg *PostgreSQL) doForgetIteration(account string) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	rows, err := pg.db.QueryContext(ctx, `
		SELECT account_messages.history_id
		FROM account_messages
		WHERE account_messages.account = $1
		LIMIT $2;`, account, cleanupRowLimit)
	if err != nil {
		return
	}
	defer rows.Close()

	var ids []uint64
	for rows.Next() {
		var id uint64
		err = rows.Scan(&id)
		if err != nil {
			return
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return
	}

	pg.logger.Debug("postgres", fmt.Sprintf("deleting %d history rows from account %s", len(ids), account))
	err = pg.deleteHistoryIDs(ctx, ids)
	return len(ids), err
}

func (pg *PostgreSQL) prepareStatements() (err error) {
	pg.insertHistory, err = pg.db.Prepare(`INSERT INTO history
		(data, msgid) VALUES ($1, $2) RETURNING id;`)
	if err != nil {
		return
	}
	pg.insertSequence, err = pg.db.Prepare(`INSERT INTO sequence
		(target, nanotime, history_id) VALUES ($1, $2, $3);`)
	if err != nil {
		return
	}
	pg.insertConversation, err = pg.db.Prepare(`INSERT INTO conversations
		(target, correspondent, nanotime, history_id) VALUES ($1, $2, $3, $4);`)
	if err != nil {
		return
	}
	pg.insertCorrespondent, err = pg.db.Prepare(`INSERT INTO correspondents
		(target, correspondent, nanotime) VALUES ($1, $2, $3)
		ON CONFLICT (target, correspondent)
		DO UPDATE SET nanotime = GREATEST(correspondents.nanotime, $3);`)
	if err != nil {
		return
	}
	pg.insertAccountMessage, err = pg.db.Prepare(`INSERT INTO account_messages
		(history_id, account) VALUES ($1, $2);`)
	if err != nil {
		return
	}

	return
}

func (pg *PostgreSQL) getTimeout() time.Duration {
	return time.Duration(pg.timeout.Load())
}

func (pg *PostgreSQL) isTrackingAccountMessages() bool {
	return pg.trackAccountMessages.Load() != 0
}

func (pg *PostgreSQL) logError(context string, err error) (quit bool) {
	if err != nil {
		pg.logger.Error("postgres", context, err.Error())
		return true
	}
	return false
}

func (pg *PostgreSQL) Forget(account string) {
	if pg.db == nil || account == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	_, err := pg.db.ExecContext(ctx, `INSERT INTO forget (account) VALUES ($1);`, account)
	if pg.logError("can't insert into forget table", err) {
		return
	}

	// wake up the forget goroutine if it's blocked:
	select {
	case pg.wakeForgetter <- e{}:
	default:
	}
}

func (pg *PostgreSQL) AddChannelItem(target string, item history.Item, account string) (err error) {
	if pg.db == nil {
		return
	}

	if target == "" {
		return utils.ErrInvalidParams
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	id, err := pg.insertBase(ctx, item)
	if err != nil {
		return
	}

	err = pg.insertSequenceEntry(ctx, target, item.Message.Time.UnixNano(), id)
	if err != nil {
		return
	}

	err = pg.insertAccountMessageEntry(ctx, id, account)
	if err != nil {
		return
	}

	return
}

func (pg *PostgreSQL) insertSequenceEntry(ctx context.Context, target string, messageTime int64, id int64) (err error) {
	_, err = pg.insertSequence.ExecContext(ctx, target, messageTime, id)
	if err != nil {
		return fmt.Errorf("could not insert sequence entry: %w", err)
	}
	return
}

func (pg *PostgreSQL) insertConversationEntry(ctx context.Context, target, correspondent string, messageTime int64, id int64) (err error) {
	_, err = pg.insertConversation.ExecContext(ctx, target, correspondent, messageTime, id)
	if err != nil {
		return fmt.Errorf("could not insert conversations entry: %w", err)
	}
	return
}

func (pg *PostgreSQL) insertCorrespondentsEntry(ctx context.Context, target, correspondent string, messageTime int64, historyId int64) (err error) {
	_, err = pg.insertCorrespondent.ExecContext(ctx, target, correspondent, messageTime)
	if err != nil {
		return fmt.Errorf("could not insert correspondents entry: %w", err)
	}
	return
}

func (pg *PostgreSQL) insertBase(ctx context.Context, item history.Item) (id int64, err error) {
	value, err := history.MarshalItem(&item)
	if err != nil {
		return 0, fmt.Errorf("could not marshal item: %w", err)
	}

	msgidBytes, err := utils.DecodeSecretToken(item.Message.Msgid)
	if err != nil {
		return 0, fmt.Errorf("could not decode msgid: %w", err)
	}

	// Use RETURNING clause to get the ID in a single round-trip
	err = pg.insertHistory.QueryRowContext(ctx, value, msgidBytes).Scan(&id)
	if pg.logError("could not insert item", err) {
		return
	}

	return
}

func (pg *PostgreSQL) insertAccountMessageEntry(ctx context.Context, id int64, account string) (err error) {
	if account == "" || !pg.isTrackingAccountMessages() {
		return
	}
	_, err = pg.insertAccountMessage.ExecContext(ctx, id, account)
	if err != nil {
		return fmt.Errorf("could not insert account-message entry: %w", err)
	}
	return
}

func (pg *PostgreSQL) AddDirectMessage(sender, senderAccount, recipient, recipientAccount string, item history.Item) (err error) {
	if pg.db == nil {
		return
	}

	if senderAccount == "" && recipientAccount == "" {
		return
	}

	if sender == "" || recipient == "" {
		return utils.ErrInvalidParams
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	id, err := pg.insertBase(ctx, item)
	if err != nil {
		return
	}

	nanotime := item.Message.Time.UnixNano()

	if senderAccount != "" {
		err = pg.insertConversationEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
		err = pg.insertCorrespondentsEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
	}

	if recipientAccount != "" && sender != recipient {
		err = pg.insertConversationEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
		err = pg.insertCorrespondentsEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
	}

	err = pg.insertAccountMessageEntry(ctx, id, senderAccount)
	if err != nil {
		return
	}

	return
}

// note that accountName is the unfolded name
func (pg *PostgreSQL) DeleteMsgid(msgid, accountName string) (err error) {
	if pg.db == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	_, id, data, err := pg.lookupMsgid(ctx, msgid, true)
	if err != nil {
		if err == sql.ErrNoRows {
			return history.ErrNotFound
		}
		return
	}

	if accountName != "*" {
		var item history.Item
		err = history.UnmarshalItem(data, &item)
		// delete if the entry is corrupt
		if err == nil && item.AccountName != accountName {
			return history.ErrDisallowed
		}
	}

	err = pg.deleteHistoryIDs(ctx, []uint64{id})
	if err != nil {
		return fmt.Errorf("couldn't delete msgid: %w", err)
	}
	return
}

func (pg *PostgreSQL) Export(account string, writer io.Writer) {
	if pg.db == nil {
		return
	}

	var err error
	var lastSeen uint64
	for {
		rows := func() (count int) {
			ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
			defer cancel()

			rows, rowsErr := pg.db.QueryContext(ctx, `
				SELECT account_messages.history_id, history.data, sequence.target FROM account_messages
				INNER JOIN history ON history.id = account_messages.history_id
				INNER JOIN sequence ON account_messages.history_id = sequence.history_id
				WHERE account_messages.account = $1 AND account_messages.history_id > $2
				LIMIT $3`, account, lastSeen, cleanupRowLimit)
			if rowsErr != nil {
				err = rowsErr
				return
			}
			defer rows.Close()
			for rows.Next() {
				var id uint64
				var blob, jsonBlob []byte
				var target string
				var item history.Item
				err = rows.Scan(&id, &blob, &target)
				if err != nil {
					return
				}
				err = history.UnmarshalItem(blob, &item)
				if err != nil {
					return
				}
				item.CfCorrespondent = target
				jsonBlob, err = json.Marshal(item)
				if err != nil {
					return
				}
				count++
				if lastSeen < id {
					lastSeen = id
				}
				writer.Write(jsonBlob)
				writer.Write([]byte{'\n'})
			}
			return
		}()
		if rows == 0 || err != nil {
			break
		}
	}

	pg.logError("could not export history", err)
	return
}

func (pg *PostgreSQL) lookupMsgid(ctx context.Context, msgid string, includeData bool) (result time.Time, id uint64, data []byte, err error) {
	decoded, err := utils.DecodeSecretToken(msgid)
	if err != nil {
		// use sql.ErrNoRows internally for consistency, translate to history.ErrNotFound
		// at the package boundary if necessary
		err = sql.ErrNoRows
		return
	}
	cols := `sequence.nanotime, conversations.nanotime`
	if includeData {
		cols = `sequence.nanotime, conversations.nanotime, history.id, history.data`
	}
	row := pg.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		LEFT JOIN conversations ON history.id = conversations.history_id
		WHERE history.msgid = $1 LIMIT 1;`, cols), decoded)
	var nanoSeq, nanoConv sql.NullInt64
	if !includeData {
		err = row.Scan(&nanoSeq, &nanoConv)
	} else {
		err = row.Scan(&nanoSeq, &nanoConv, &id, &data)
	}
	if err != nil {
		if err != sql.ErrNoRows {
			err = fmt.Errorf("could not resolve msgid to time: %w", err)
		}
		return
	}
	nanotime := extractNanotime(nanoSeq, nanoConv)
	if nanotime == 0 {
		err = sql.ErrNoRows
		return
	}
	result = time.Unix(0, nanotime).UTC()
	return
}

func extractNanotime(seq, conv sql.NullInt64) (result int64) {
	if seq.Valid {
		return seq.Int64
	} else if conv.Valid {
		return conv.Int64
	}
	return
}

func (pg *PostgreSQL) selectItems(ctx context.Context, query string, args ...interface{}) (results []history.Item, err error) {
	rows, err := pg.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("could not select history items: %w", err)
	}

	defer rows.Close()

	for rows.Next() {
		var blob []byte
		var item history.Item
		err = rows.Scan(&blob)
		if err != nil {
			return nil, fmt.Errorf("could not scan history item: %w", err)
		}
		err = history.UnmarshalItem(blob, &item)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal history item: %w", err)
		}
		results = append(results, item)
	}
	return
}

func (pg *PostgreSQL) betweenTimestamps(ctx context.Context, target, correspondent string, after, before, cutoff time.Time, limit int) (results []history.Item, err error) {
	useSequence := correspondent == ""
	table := "sequence"
	if !useSequence {
		table = "conversations"
	}

	after, before, ascending := history.MinMaxAsc(after, before, cutoff)
	direction := "ASC"
	if !ascending {
		direction = "DESC"
	}

	var queryBuf strings.Builder

	args := make([]interface{}, 0, 6)
	paramNum := 1
	fmt.Fprintf(&queryBuf,
		"SELECT history.data from history INNER JOIN %[1]s ON history.id = %[1]s.history_id WHERE", table)
	if useSequence {
		fmt.Fprintf(&queryBuf, " sequence.target = $%d", paramNum)
		args = append(args, target)
		paramNum++
	} else {
		fmt.Fprintf(&queryBuf, " conversations.target = $%d AND conversations.correspondent = $%d", paramNum, paramNum+1)
		args = append(args, target)
		args = append(args, correspondent)
		paramNum += 2
	}
	if !after.IsZero() {
		fmt.Fprintf(&queryBuf, " AND %s.nanotime > $%d", table, paramNum)
		args = append(args, after.UnixNano())
		paramNum++
	}
	if !before.IsZero() {
		fmt.Fprintf(&queryBuf, " AND %s.nanotime < $%d", table, paramNum)
		args = append(args, before.UnixNano())
		paramNum++
	}
	fmt.Fprintf(&queryBuf, " ORDER BY %[1]s.nanotime %[2]s LIMIT $%[3]d;", table, direction, paramNum)
	args = append(args, limit)

	results, err = pg.selectItems(ctx, queryBuf.String(), args...)
	if err == nil && !ascending {
		slices.Reverse(results)
	}
	return
}

func (pg *PostgreSQL) listCorrespondentsInternal(ctx context.Context, target string, after, before, cutoff time.Time, limit int) (results []history.TargetListing, err error) {
	after, before, ascending := history.MinMaxAsc(after, before, cutoff)
	direction := "ASC"
	if !ascending {
		direction = "DESC"
	}

	var queryBuf strings.Builder
	args := make([]interface{}, 0, 4)
	paramNum := 1
	fmt.Fprintf(&queryBuf, `SELECT correspondents.correspondent, correspondents.nanotime from correspondents
		WHERE target = $%d`, paramNum)
	args = append(args, target)
	paramNum++
	if !after.IsZero() {
		fmt.Fprintf(&queryBuf, " AND correspondents.nanotime > $%d", paramNum)
		args = append(args, after.UnixNano())
		paramNum++
	}
	if !before.IsZero() {
		fmt.Fprintf(&queryBuf, " AND correspondents.nanotime < $%d", paramNum)
		args = append(args, before.UnixNano())
		paramNum++
	}
	fmt.Fprintf(&queryBuf, " ORDER BY correspondents.nanotime %s LIMIT $%d;", direction, paramNum)
	args = append(args, limit)
	query := queryBuf.String()

	rows, err := pg.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("could not query correspondents: %w", err)
	}
	defer rows.Close()
	var correspondent string
	var nanotime int64
	for rows.Next() {
		err = rows.Scan(&correspondent, &nanotime)
		if err != nil {
			return nil, fmt.Errorf("could not scan correspondents: %w", err)
		}
		results = append(results, history.TargetListing{
			CfName: correspondent,
			Time:   time.Unix(0, nanotime).UTC(),
		})
	}

	if !ascending {
		slices.Reverse(results)
	}

	return
}

func (pg *PostgreSQL) ListCorrespondents(cftarget string, start, end time.Time, limit int) (results []history.TargetListing, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	// TODO accept msgids here?

	results, err = pg.listCorrespondentsInternal(ctx, cftarget, start, end, time.Time{}, limit)
	if err != nil {
		return nil, fmt.Errorf("could not read correspondents: %w", err)
	}
	return
}

func (pg *PostgreSQL) ListChannels(cfchannels []string) (results []history.TargetListing, err error) {
	if pg.db == nil {
		return
	}

	if len(cfchannels) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), pg.getTimeout())
	defer cancel()

	var queryBuf strings.Builder
	args := make([]interface{}, 0, len(cfchannels))
	// PostgreSQL optimizes DISTINCT ON better than GROUP BY MAX for this pattern
	queryBuf.WriteString(`SELECT DISTINCT ON (sequence.target) sequence.target, sequence.nanotime
		FROM sequence
		WHERE sequence.target IN (`)
	for i, chname := range cfchannels {
		if i != 0 {
			queryBuf.WriteString(", ")
		}
		fmt.Fprintf(&queryBuf, "$%d", i+1)
		args = append(args, chname)
	}
	queryBuf.WriteString(`) ORDER BY sequence.target, sequence.nanotime DESC;`)

	rows, err := pg.db.QueryContext(ctx, queryBuf.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("could not query channel listings: %w", err)
	}
	defer rows.Close()

	var target string
	var nanotime int64
	for rows.Next() {
		err = rows.Scan(&target, &nanotime)
		if err != nil {
			return nil, fmt.Errorf("could not scan channel listings: %w", err)
		}
		results = append(results, history.TargetListing{
			CfName: target,
			Time:   time.Unix(0, nanotime).UTC(),
		})
	}
	return
}

func (pg *PostgreSQL) Close() (err error) {
	// closing the database will close our prepared statements as well
	if pg.db != nil {
		err = pg.db.Close()
	}
	pg.db = nil
	return
}

// implements history.Sequence, emulating a single history buffer (for a channel,
// a single user's DMs, or a DM conversation)
type postgreSQLHistorySequence struct {
	pg            *PostgreSQL
	target        string
	correspondent string
	cutoff        time.Time
}

func (s *postgreSQLHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.pg.getTimeout())
	defer cancel()

	startTime := start.Time
	if start.Msgid != "" {
		startTime, _, _, err = s.pg.lookupMsgid(ctx, start.Msgid, false)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}
	endTime := end.Time
	if end.Msgid != "" {
		endTime, _, _, err = s.pg.lookupMsgid(ctx, end.Msgid, false)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}

	results, err = s.pg.betweenTimestamps(ctx, s.target, s.correspondent, startTime, endTime, s.cutoff, limit)
	return results, err
}

func (s *postgreSQLHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (seq *postgreSQLHistorySequence) Cutoff() time.Time {
	return seq.cutoff
}

func (seq *postgreSQLHistorySequence) Ephemeral() bool {
	return false
}

func (pg *PostgreSQL) MakeSequence(target, correspondent string, cutoff time.Time) history.Sequence {
	return &postgreSQLHistorySequence{
		target:        target,
		correspondent: correspondent,
		pg:            pg,
		cutoff:        cutoff,
	}
}
