//go:build sqlite

// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package sqlite

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
	_ "modernc.org/sqlite"
)

const (
	// Enabled is true when SQLite support is compiled in
	Enabled = true

	// latest schema of the db
	latestDbSchema   = "2"
	keySchemaVersion = "db.version"
	// minor version indicates rollback-safe upgrades, i.e.,
	// you can downgrade oragono and everything will work
	latestDbMinorVersion  = "2"
	keySchemaMinorVersion = "db.minorversion"
	cleanupRowLimit       = 50
	cleanupPauseTime      = 10 * time.Minute

	defaultBusyTimeout = 10 * time.Second
)

type e struct{}

type SQLite struct {
	db     *sql.DB
	logger *logger.Manager

	insertHistory        *sql.Stmt
	insertSequence       *sql.Stmt
	insertConversation   *sql.Stmt
	insertCorrespondent  *sql.Stmt
	insertAccountMessage *sql.Stmt
	selectChannelTime    *sql.Stmt

	stateMutex sync.Mutex
	config     Config

	wakeForgetter chan e

	trackAccountMessages atomic.Uint32
}

var _ history.Database = (*SQLite)(nil)

func NewSQLiteDatabase(logger *logger.Manager, config Config) (*SQLite, error) {
	var sqlite SQLite

	sqlite.logger = logger
	sqlite.wakeForgetter = make(chan e, 1)
	sqlite.SetConfig(config)

	return &sqlite, sqlite.open()
}

func (s *SQLite) SetConfig(config Config) {
	var trackAccountMessages uint32
	if config.TrackAccountMessages {
		trackAccountMessages = 1
	}
	s.trackAccountMessages.Store(trackAccountMessages)
	s.stateMutex.Lock()
	s.config = config
	s.stateMutex.Unlock()
}

func (s *SQLite) getExpireTime() (expireTime time.Duration) {
	s.stateMutex.Lock()
	expireTime = s.config.ExpireTime
	s.stateMutex.Unlock()
	return
}

func (s *SQLite) open() (err error) {
	busyTimeout := s.config.BusyTimeout
	if busyTimeout <= 0 {
		busyTimeout = defaultBusyTimeout
	}
	busyTimeoutMs := int(busyTimeout.Milliseconds())

	dbPath := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", s.config.DatabasePath, busyTimeoutMs)

	s.logger.Debug("sqlite", "Opening SQLite DB at", dbPath)

	s.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	if s.config.MaxConns != 0 {
		// TODO figure out how to accommodate multiple concurrent readers?
		s.db.SetMaxOpenConns(s.config.MaxConns)
	}

	err = s.fixSchemas()
	if err != nil {
		return err
	}

	err = s.prepareStatements()
	if err != nil {
		return err
	}

	go s.cleanupLoop()
	go s.forgetLoop()

	return nil
}

func (s *SQLite) fixSchemas() (err error) {
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS metadata (
		key_name TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`)
	if err != nil {
		return err
	}

	var schema string
	err = s.db.QueryRow(`SELECT value FROM metadata WHERE key_name = ?;`, keySchemaVersion).Scan(&schema)
	if err == sql.ErrNoRows {
		err = s.createTables()
		if err != nil {
			return
		}
		_, err = s.db.Exec(`INSERT INTO metadata (key_name, value) VALUES (?, ?);`, keySchemaVersion, latestDbSchema)
		if err != nil {
			return
		}
		_, err = s.db.Exec(`INSERT INTO metadata (key_name, value) VALUES (?, ?);`, keySchemaMinorVersion, latestDbMinorVersion)
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
	err = s.db.QueryRow(`SELECT value FROM metadata WHERE key_name = ?;`, keySchemaMinorVersion).Scan(&minorVersion)
	if err == sql.ErrNoRows {
		// impossible
	} else if err == nil && minorVersion != latestDbMinorVersion {
		// TODO: if minorVersion < latestDbMinorVersion, upgrade,
		// if latestDbMinorVersion < minorVersion, ignore because backwards compatible
	} else if err != nil {
		return
	}
	return
}

func (s *SQLite) createTables() (err error) {
	_, err = s.db.Exec(`CREATE TABLE history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		data BLOB NOT NULL,
		msgid TEXT NOT NULL
	);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_history_msgid ON history(msgid);`)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`CREATE TABLE sequence (
		history_id INTEGER NOT NULL PRIMARY KEY,
		target TEXT NOT NULL,
		nanotime INTEGER NOT NULL
	);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_sequence_target_nanotime ON sequence(target, nanotime);`)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`CREATE TABLE conversations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		correspondent TEXT NOT NULL,
		nanotime INTEGER NOT NULL,
		history_id INTEGER NOT NULL
	);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_conversations_target_correspondent_nanotime ON conversations(target, correspondent, nanotime);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_conversations_history_id ON conversations(history_id);`)
	if err != nil {
		return err
	}

	err = s.createCorrespondentsTable()
	if err != nil {
		return err
	}

	err = s.createComplianceTables()
	if err != nil {
		return err
	}

	return nil
}

func (s *SQLite) createCorrespondentsTable() (err error) {
	_, err = s.db.Exec(`CREATE TABLE correspondents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		correspondent TEXT NOT NULL,
		nanotime INTEGER NOT NULL,
		UNIQUE(target, correspondent)
	);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_correspondents_target_nanotime ON correspondents(target, nanotime);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_correspondents_nanotime ON correspondents(nanotime);`)
	return
}

func (s *SQLite) createComplianceTables() (err error) {
	_, err = s.db.Exec(`CREATE TABLE account_messages (
		history_id INTEGER NOT NULL PRIMARY KEY,
		account TEXT NOT NULL
	);`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`CREATE INDEX idx_account_messages_account_history_id ON account_messages(account, history_id);`)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`CREATE TABLE forget (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account TEXT NOT NULL
	);`)
	if err != nil {
		return err
	}

	return nil
}

func (s *SQLite) cleanupLoop() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("sqlite",
				fmt.Sprintf("Panic in cleanup routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go s.cleanupLoop()
		}
	}()

	for {
		expireTime := s.getExpireTime()
		if expireTime != 0 {
			for {
				startTime := time.Now()
				rowsDeleted, err := s.doCleanup(expireTime)
				elapsed := time.Now().Sub(startTime)
				s.logError("error during row cleanup", err)
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

func (s *SQLite) doCleanup(age time.Duration) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	ids, maxNanotime, err := s.selectCleanupIDs(ctx, age)
	if len(ids) == 0 {
		s.logger.Debug("sqlite", "found no rows to clean up")
		return
	}

	s.logger.Debug("sqlite", fmt.Sprintf("deleting %d history rows, max age %s", len(ids), utils.NanoToTimestamp(maxNanotime)))

	if maxNanotime != 0 {
		s.deleteCorrespondents(ctx, maxNanotime)
	}

	return len(ids), s.deleteHistoryIDs(ctx, ids)
}

func (s *SQLite) deleteHistoryIDs(ctx context.Context, ids []uint64) (err error) {
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

	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM conversations WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM sequence WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	if s.isTrackingAccountMessages() {
		_, err = s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM account_messages WHERE history_id in %s;`, inClause))
		if err != nil {
			return
		}
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM history WHERE id in %s;`, inClause))
	if err != nil {
		return
	}

	return
}

func (s *SQLite) selectCleanupIDs(ctx context.Context, age time.Duration) (ids []uint64, maxNanotime int64, err error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT history.id, sequence.nanotime, conversations.nanotime
		FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		LEFT JOIN conversations on history.id = conversations.history_id
		ORDER BY history.id LIMIT ?;`, cleanupRowLimit)
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

func (s *SQLite) deleteCorrespondents(ctx context.Context, threshold int64) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM correspondents WHERE nanotime <= (?);`, threshold)
	if err != nil {
		s.logError("error deleting correspondents", err)
	} else {
		count, err := result.RowsAffected()
		if !s.logError("error deleting correspondents", err) {
			s.logger.Debug("sqlite", fmt.Sprintf("deleted %d correspondents entries", count))
		}
	}
}

// wait for forget queue items and process them one by one
func (s *SQLite) forgetLoop() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("sqlite",
				fmt.Sprintf("Panic in forget routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go s.forgetLoop()
		}
	}()

	for {
		for {
			found, err := s.doForget()
			s.logError("error processing forget", err)
			if err != nil {
				time.Sleep(cleanupPauseTime)
			}
			if !found {
				break
			}
		}

		<-s.wakeForgetter
	}
}

// dequeue an item from the forget queue and process it
func (s *SQLite) doForget() (found bool, err error) {
	id, account, err := func() (id int64, account string, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
		defer cancel()

		row := s.db.QueryRowContext(ctx,
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
		count, err = s.doForgetIteration(account)
		elapsed := time.Since(start)
		if err != nil {
			return true, err
		}
		if count == 0 {
			break
		}
		time.Sleep(elapsed)
	}

	s.logger.Debug("sqlite", "forget complete for account", account)

	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `DELETE FROM forget where id = ?;`, id)
	return
}

func (s *SQLite) doForgetIteration(account string) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT account_messages.history_id
		FROM account_messages
		WHERE account_messages.account = ?
		LIMIT ?;`, account, cleanupRowLimit)
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

	s.logger.Debug("sqlite", fmt.Sprintf("deleting %d history rows from account %s", len(ids), account))
	err = s.deleteHistoryIDs(ctx, ids)
	return len(ids), err
}

func (s *SQLite) prepareStatements() (err error) {
	s.insertHistory, err = s.db.Prepare(`INSERT INTO history
		(data, msgid) VALUES (?, ?);`)
	if err != nil {
		return
	}
	s.insertSequence, err = s.db.Prepare(`INSERT INTO sequence
		(target, nanotime, history_id) VALUES (?, ?, ?);`)
	if err != nil {
		return
	}
	s.insertConversation, err = s.db.Prepare(`INSERT INTO conversations
		(target, correspondent, nanotime, history_id) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return
	}
	s.insertCorrespondent, err = s.db.Prepare(`INSERT INTO correspondents
		(target, correspondent, nanotime) VALUES (?, ?, ?)
		ON CONFLICT(target, correspondent) DO UPDATE SET nanotime = MAX(nanotime, excluded.nanotime);`)
	if err != nil {
		return
	}
	s.insertAccountMessage, err = s.db.Prepare(`INSERT INTO account_messages
		(history_id, account) VALUES (?, ?);`)
	if err != nil {
		return
	}
	s.selectChannelTime, err = s.db.Prepare(`SELECT nanotime FROM sequence
		WHERE target = ? ORDER BY nanotime DESC LIMIT 1;`)
	if err != nil {
		return
	}

	return
}

func (s *SQLite) isTrackingAccountMessages() bool {
	return s.trackAccountMessages.Load() != 0
}

func (s *SQLite) logError(context string, err error) (quit bool) {
	if err != nil {
		s.logger.Error("sqlite", context, err.Error())
		return true
	}
	return false
}

func (s *SQLite) Forget(account string) {
	if s.db == nil || account == "" {
		return
	}

	ctx := context.Background()

	_, err := s.db.ExecContext(ctx, `INSERT INTO forget (account) VALUES (?);`, account)
	if s.logError("can't insert into forget table", err) {
		return
	}

	// wake up the forget goroutine if it's blocked:
	select {
	case s.wakeForgetter <- e{}:
	default:
	}
}

func (s *SQLite) AddChannelItem(target string, item history.Item, account string) (err error) {
	if s.db == nil {
		return
	}

	if target == "" {
		return utils.ErrInvalidParams
	}

	ctx := context.Background()

	id, err := s.insertBase(ctx, item)
	if err != nil {
		return
	}

	err = s.insertSequenceEntry(ctx, target, item.Message.Time.UnixNano(), id)
	if err != nil {
		return
	}

	err = s.insertAccountMessageEntry(ctx, id, account)
	if err != nil {
		return
	}

	return
}

func (s *SQLite) insertSequenceEntry(ctx context.Context, target string, messageTime int64, id int64) (err error) {
	_, err = s.insertSequence.ExecContext(ctx, target, messageTime, id)
	if err != nil {
		return fmt.Errorf("could not insert sequence entry: %w", err)
	}
	return
}

func (s *SQLite) insertConversationEntry(ctx context.Context, target, correspondent string, messageTime int64, id int64) (err error) {
	_, err = s.insertConversation.ExecContext(ctx, target, correspondent, messageTime, id)
	if err != nil {
		return fmt.Errorf("could not insert conversations entry: %w", err)
	}
	return
}

func (s *SQLite) insertCorrespondentsEntry(ctx context.Context, target, correspondent string, messageTime int64, historyId int64) (err error) {
	_, err = s.insertCorrespondent.ExecContext(ctx, target, correspondent, messageTime)
	if err != nil {
		return fmt.Errorf("could not insert correspondents entry: %w", err)
	}
	return
}

func (s *SQLite) insertBase(ctx context.Context, item history.Item) (id int64, err error) {
	value, err := history.MarshalItem(&item)
	if err != nil {
		return 0, fmt.Errorf("could not marshal item: %w", err)
	}

	// Use msgid as-is (it's already ASCII text)
	result, err := s.insertHistory.ExecContext(ctx, value, item.Message.Msgid)
	if err != nil {
		return 0, fmt.Errorf("could not insert item: %w", err)
	}
	id, err = result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("could not insert item: %w", err)
	}

	return
}

func (s *SQLite) insertAccountMessageEntry(ctx context.Context, id int64, account string) (err error) {
	if account == "" || !s.isTrackingAccountMessages() {
		return
	}
	_, err = s.insertAccountMessage.ExecContext(ctx, id, account)
	if err != nil {
		return fmt.Errorf("could not insert account-message entry: %w", err)
	}
	return
}

func (s *SQLite) AddDirectMessage(sender, senderAccount, recipient, recipientAccount string, item history.Item) (err error) {
	if s.db == nil {
		return
	}

	if senderAccount == "" && recipientAccount == "" {
		return
	}

	if sender == "" || recipient == "" {
		return utils.ErrInvalidParams
	}

	ctx := context.Background()

	id, err := s.insertBase(ctx, item)
	if err != nil {
		return
	}

	nanotime := item.Message.Time.UnixNano()

	if senderAccount != "" {
		err = s.insertConversationEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
		err = s.insertCorrespondentsEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
	}

	if recipientAccount != "" && sender != recipient {
		err = s.insertConversationEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
		err = s.insertCorrespondentsEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
	}

	err = s.insertAccountMessageEntry(ctx, id, senderAccount)
	if err != nil {
		return
	}

	return
}

// note that accountName is the unfolded name
func (s *SQLite) DeleteMsgid(msgid, accountName string) (err error) {
	if s.db == nil {
		return nil
	}

	ctx := context.Background()

	_, id, data, err := s.lookupMsgid(ctx, msgid, true)
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

	err = s.deleteHistoryIDs(ctx, []uint64{id})
	if err != nil {
		return fmt.Errorf("couldn't delete msgid: %w", err)
	}
	return
}

func (s *SQLite) Export(account string, writer io.Writer) {
	if s.db == nil {
		return
	}

	var err error
	var lastSeen uint64
	for {
		rows := func() (count int) {
			ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
			defer cancel()

			rows, rowsErr := s.db.QueryContext(ctx, `
				SELECT account_messages.history_id, history.data, sequence.target FROM account_messages
				INNER JOIN history ON history.id = account_messages.history_id
				INNER JOIN sequence ON account_messages.history_id = sequence.history_id
				WHERE account_messages.account = ? AND account_messages.history_id > ?
				LIMIT ?`, account, lastSeen, cleanupRowLimit)
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

	s.logError("could not export history", err)
	return
}

func (s *SQLite) lookupMsgid(ctx context.Context, msgid string, includeData bool) (result time.Time, id uint64, data []byte, err error) {
	// msgid is already ASCII text, no need to decode
	cols := `sequence.nanotime, conversations.nanotime`
	if includeData {
		cols = `sequence.nanotime, conversations.nanotime, history.id, history.data`
	}
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		LEFT JOIN conversations ON history.id = conversations.history_id
		WHERE history.msgid = ? LIMIT 1;`, cols), msgid)
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

func (s *SQLite) selectItems(ctx context.Context, query string, args ...interface{}) (results []history.Item, err error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *SQLite) betweenTimestamps(ctx context.Context, target, correspondent string, after, before, cutoff time.Time, limit int) (results []history.Item, err error) {
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
	fmt.Fprintf(&queryBuf,
		"SELECT history.data from history INNER JOIN %[1]s ON history.id = %[1]s.history_id WHERE", table)
	if useSequence {
		fmt.Fprintf(&queryBuf, " sequence.target = ?")
		args = append(args, target)
	} else {
		fmt.Fprintf(&queryBuf, " conversations.target = ? AND conversations.correspondent = ?")
		args = append(args, target)
		args = append(args, correspondent)
	}
	if !after.IsZero() {
		fmt.Fprintf(&queryBuf, " AND %s.nanotime > ?", table)
		args = append(args, after.UnixNano())
	}
	if !before.IsZero() {
		fmt.Fprintf(&queryBuf, " AND %s.nanotime < ?", table)
		args = append(args, before.UnixNano())
	}
	fmt.Fprintf(&queryBuf, " ORDER BY %[1]s.nanotime %[2]s LIMIT ?;", table, direction)
	args = append(args, limit)

	results, err = s.selectItems(ctx, queryBuf.String(), args...)
	if err == nil && !ascending {
		slices.Reverse(results)
	}
	return
}

func (s *SQLite) listCorrespondentsInternal(ctx context.Context, target string, after, before, cutoff time.Time, limit int) (results []history.TargetListing, err error) {
	after, before, ascending := history.MinMaxAsc(after, before, cutoff)
	direction := "ASC"
	if !ascending {
		direction = "DESC"
	}

	var queryBuf strings.Builder
	args := make([]interface{}, 0, 4)
	queryBuf.WriteString(`SELECT correspondents.correspondent, correspondents.nanotime from correspondents
		WHERE target = ?`)
	args = append(args, target)
	if !after.IsZero() {
		queryBuf.WriteString(" AND correspondents.nanotime > ?")
		args = append(args, after.UnixNano())
	}
	if !before.IsZero() {
		queryBuf.WriteString(" AND correspondents.nanotime < ?")
		args = append(args, before.UnixNano())
	}
	fmt.Fprintf(&queryBuf, " ORDER BY correspondents.nanotime %s LIMIT ?;", direction)
	args = append(args, limit)
	query := queryBuf.String()

	rows, err := s.db.QueryContext(ctx, query, args...)
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

func (s *SQLite) ListCorrespondents(cftarget string, start, end time.Time, limit int) (results []history.TargetListing, err error) {
	ctx := context.Background()

	// TODO accept msgids here?

	results, err = s.listCorrespondentsInternal(ctx, cftarget, start, end, time.Time{}, limit)
	if err != nil {
		return nil, fmt.Errorf("could not read correspondents: %w", err)
	}
	return
}

func (s *SQLite) ListChannels(cfchannels []string) (results []history.TargetListing, err error) {
	if s.db == nil {
		return
	}

	if len(cfchannels) == 0 {
		return
	}

	ctx := context.Background()

	// SQLite does not support loose index scan (unlike MySQL), so the GROUP BY approach
	// would require scanning all messages. Instead, we query each channel individually
	// using ORDER BY DESC LIMIT 1, which allows SQLite to use the (target, nanotime) index
	// to efficiently seek to the latest message per channel in O(log n) time.
	results = make([]history.TargetListing, 0, len(cfchannels))
	for _, chname := range cfchannels {
		var nanotime int64
		err = s.selectChannelTime.QueryRowContext(ctx, chname).Scan(&nanotime)
		if err == sql.ErrNoRows {
			continue // channel has no messages, skip it
		}
		if err != nil {
			return nil, fmt.Errorf("could not query channel listing: %w", err)
		}
		results = append(results, history.TargetListing{
			CfName: chname,
			Time:   time.Unix(0, nanotime).UTC(),
		})
	}
	return
}

func (s *SQLite) Close() (err error) {
	// closing the database will close our prepared statements as well
	if s.db != nil {
		err = s.db.Close()
	}
	s.db = nil
	return
}

// implements history.Sequence, emulating a single history buffer (for a channel,
// a single user's DMs, or a DM conversation)
type sqliteHistorySequence struct {
	sqlite        *SQLite
	target        string
	correspondent string
	cutoff        time.Time
}

func (s *sqliteHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, err error) {
	ctx := context.Background()

	startTime := start.Time
	if start.Msgid != "" {
		startTime, _, _, err = s.sqlite.lookupMsgid(ctx, start.Msgid, false)
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
		endTime, _, _, err = s.sqlite.lookupMsgid(ctx, end.Msgid, false)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}

	results, err = s.sqlite.betweenTimestamps(ctx, s.target, s.correspondent, startTime, endTime, s.cutoff, limit)
	return results, err
}

func (s *sqliteHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (seq *sqliteHistorySequence) Cutoff() time.Time {
	return seq.cutoff
}

func (seq *sqliteHistorySequence) Ephemeral() bool {
	return false
}

func (s *SQLite) MakeSequence(target, correspondent string, cutoff time.Time) history.Sequence {
	return &sqliteHistorySequence{
		target:        target,
		correspondent: correspondent,
		sqlite:        s,
		cutoff:        cutoff,
	}
}
