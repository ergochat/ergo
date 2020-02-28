// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/utils"
)

const (
	// maximum length in bytes of any message target (nickname or channel name) in its
	// canonicalized (i.e., casefolded) state:
	MaxTargetLength = 64

	// latest schema of the db
	latestDbSchema   = "2"
	keySchemaVersion = "db.version"
	cleanupRowLimit  = 50
	cleanupPauseTime = 10 * time.Minute
)

type MySQL struct {
	timeout int64
	db      *sql.DB
	logger  *logger.Manager

	insertHistory      *sql.Stmt
	insertSequence     *sql.Stmt
	insertConversation *sql.Stmt

	stateMutex sync.Mutex
	config     Config
}

func (mysql *MySQL) Initialize(logger *logger.Manager, config Config) {
	mysql.logger = logger
	mysql.SetConfig(config)
}

func (mysql *MySQL) SetConfig(config Config) {
	atomic.StoreInt64(&mysql.timeout, int64(config.Timeout))
	mysql.stateMutex.Lock()
	mysql.config = config
	mysql.stateMutex.Unlock()
}

func (mysql *MySQL) getExpireTime() (expireTime time.Duration) {
	mysql.stateMutex.Lock()
	expireTime = mysql.config.ExpireTime
	mysql.stateMutex.Unlock()
	return
}

func (m *MySQL) Open() (err error) {
	var address string
	if m.config.Port != 0 {
		address = fmt.Sprintf("tcp(%s:%d)", m.config.Host, m.config.Port)
	}

	m.db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@%s/%s", m.config.User, m.config.Password, address, m.config.HistoryDatabase))
	if err != nil {
		return err
	}

	err = m.fixSchemas()
	if err != nil {
		return err
	}

	err = m.prepareStatements()
	if err != nil {
		return err
	}

	go m.cleanupLoop()

	return nil
}

func (mysql *MySQL) fixSchemas() (err error) {
	_, err = mysql.db.Exec(`CREATE TABLE IF NOT EXISTS metadata (
		key_name VARCHAR(32) primary key,
		value VARCHAR(32) NOT NULL
	) CHARSET=ascii COLLATE=ascii_bin;`)
	if err != nil {
		return err
	}

	var schema string
	err = mysql.db.QueryRow(`select value from metadata where key_name = ?;`, keySchemaVersion).Scan(&schema)
	if err == sql.ErrNoRows {
		err = mysql.createTables()
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`insert into metadata (key_name, value) values (?, ?);`, keySchemaVersion, latestDbSchema)
		if err != nil {
			return
		}
	} else if err == nil && schema != latestDbSchema {
		// TODO figure out what to do about schema changes
		return &utils.IncompatibleSchemaError{CurrentVersion: schema, RequiredVersion: latestDbSchema}
	} else {
		return err
	}

	return nil
}

func (mysql *MySQL) createTables() (err error) {
	_, err = mysql.db.Exec(`CREATE TABLE history (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		data BLOB NOT NULL,
		msgid BINARY(16) NOT NULL,
		KEY (msgid(4))
	) CHARSET=ascii COLLATE=ascii_bin;`)
	if err != nil {
		return err
	}

	_, err = mysql.db.Exec(fmt.Sprintf(`CREATE TABLE sequence (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		target VARBINARY(%[1]d) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		history_id BIGINT NOT NULL,
		KEY (target, nanotime),
		KEY (history_id)
	) CHARSET=ascii COLLATE=ascii_bin;`, MaxTargetLength))
	if err != nil {
		return err
	}

	_, err = mysql.db.Exec(fmt.Sprintf(`CREATE TABLE conversations (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		target VARBINARY(%[1]d) NOT NULL,
		correspondent VARBINARY(%[1]d) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		history_id BIGINT NOT NULL,
		KEY (target, correspondent, nanotime),
		KEY (history_id)
	) CHARSET=ascii COLLATE=ascii_bin;`, MaxTargetLength))
	if err != nil {
		return err
	}

	return nil
}

func (mysql *MySQL) cleanupLoop() {
	defer func() {
		if r := recover(); r != nil {
			mysql.logger.Error("mysql",
				fmt.Sprintf("Panic in cleanup routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go mysql.cleanupLoop()
		}
	}()

	for {
		expireTime := mysql.getExpireTime()
		if expireTime != 0 {
			for {
				startTime := time.Now()
				rowsDeleted, err := mysql.doCleanup(expireTime)
				elapsed := time.Now().Sub(startTime)
				mysql.logError("error during row cleanup", err)
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

func (mysql *MySQL) doCleanup(age time.Duration) (count int, err error) {
	ids, maxNanotime, err := mysql.selectCleanupIDs(age)
	if len(ids) == 0 {
		mysql.logger.Debug("mysql", "found no rows to clean up")
		return
	}

	mysql.logger.Debug("mysql", fmt.Sprintf("deleting %d history rows, max age %s", len(ids), utils.NanoToTimestamp(maxNanotime)))

	// can't use ? binding for a variable number of arguments, build the IN clause manually
	var inBuf bytes.Buffer
	inBuf.WriteByte('(')
	for i, id := range ids {
		if i != 0 {
			inBuf.WriteRune(',')
		}
		fmt.Fprintf(&inBuf, "%d", id)
	}
	inBuf.WriteRune(')')

	_, err = mysql.db.Exec(fmt.Sprintf(`DELETE FROM conversations WHERE history_id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}
	_, err = mysql.db.Exec(fmt.Sprintf(`DELETE FROM sequence WHERE history_id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}
	_, err = mysql.db.Exec(fmt.Sprintf(`DELETE FROM history WHERE id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}

	count = len(ids)
	return
}

func (mysql *MySQL) selectCleanupIDs(age time.Duration) (ids []uint64, maxNanotime int64, err error) {
	rows, err := mysql.db.Query(`
		SELECT history.id, sequence.nanotime
		FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		ORDER BY history.id LIMIT ?;`, cleanupRowLimit)
	if err != nil {
		return
	}
	defer rows.Close()

	// a history ID may have 0-2 rows in sequence: 1 for a channel entry,
	// 2 for a DM, 0 if the data is inconsistent. therefore, deduplicate
	// and delete anything that doesn't have a sequence entry:
	idset := make(map[uint64]struct{}, cleanupRowLimit)
	threshold := time.Now().Add(-age).UnixNano()
	for rows.Next() {
		var id uint64
		var nanotime sql.NullInt64
		err = rows.Scan(&id, &nanotime)
		if err != nil {
			return
		}
		if !nanotime.Valid || nanotime.Int64 < threshold {
			idset[id] = struct{}{}
			if nanotime.Valid && nanotime.Int64 > maxNanotime {
				maxNanotime = nanotime.Int64
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

func (mysql *MySQL) prepareStatements() (err error) {
	mysql.insertHistory, err = mysql.db.Prepare(`INSERT INTO history
		(data, msgid) VALUES (?, ?);`)
	if err != nil {
		return
	}
	mysql.insertSequence, err = mysql.db.Prepare(`INSERT INTO sequence
		(target, nanotime, history_id) VALUES (?, ?, ?);`)
	if err != nil {
		return
	}
	mysql.insertConversation, err = mysql.db.Prepare(`INSERT INTO conversations
		(target, correspondent, nanotime, history_id) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return
	}

	return
}

func (mysql *MySQL) getTimeout() time.Duration {
	return time.Duration(atomic.LoadInt64(&mysql.timeout))
}

func (mysql *MySQL) logError(context string, err error) (quit bool) {
	if err != nil {
		mysql.logger.Error("mysql", context, err.Error())
		return true
	}
	return false
}

func (mysql *MySQL) AddChannelItem(target string, item history.Item) (err error) {
	if mysql.db == nil {
		return
	}

	if target == "" {
		return utils.ErrInvalidParams
	}

	ctx, cancel := context.WithTimeout(context.Background(), mysql.getTimeout())
	defer cancel()

	id, err := mysql.insertBase(ctx, item)
	if err != nil {
		return
	}

	err = mysql.insertSequenceEntry(ctx, target, item.Message.Time.UnixNano(), id)
	return
}

func (mysql *MySQL) insertSequenceEntry(ctx context.Context, target string, messageTime int64, id int64) (err error) {
	_, err = mysql.insertSequence.ExecContext(ctx, target, messageTime, id)
	mysql.logError("could not insert sequence entry", err)
	return
}

func (mysql *MySQL) insertConversationEntry(ctx context.Context, target, correspondent string, messageTime int64, id int64) (err error) {
	_, err = mysql.insertConversation.ExecContext(ctx, target, correspondent, messageTime, id)
	mysql.logError("could not insert conversations entry", err)
	return
}

func (mysql *MySQL) insertBase(ctx context.Context, item history.Item) (id int64, err error) {
	value, err := marshalItem(&item)
	if mysql.logError("could not marshal item", err) {
		return
	}

	msgidBytes, err := decodeMsgid(item.Message.Msgid)
	if mysql.logError("could not decode msgid", err) {
		return
	}

	result, err := mysql.insertHistory.ExecContext(ctx, value, msgidBytes)
	if mysql.logError("could not insert item", err) {
		return
	}
	id, err = result.LastInsertId()
	if mysql.logError("could not insert item", err) {
		return
	}

	return
}

func (mysql *MySQL) AddDirectMessage(sender, senderAccount, recipient, recipientAccount string, item history.Item) (err error) {
	if mysql.db == nil {
		return
	}

	if senderAccount == "" && recipientAccount == "" {
		return
	}

	if sender == "" || recipient == "" {
		return utils.ErrInvalidParams
	}

	ctx, cancel := context.WithTimeout(context.Background(), mysql.getTimeout())
	defer cancel()

	id, err := mysql.insertBase(ctx, item)
	if err != nil {
		return
	}

	nanotime := item.Message.Time.UnixNano()

	if senderAccount != "" {
		err = mysql.insertSequenceEntry(ctx, senderAccount, nanotime, id)
		if err != nil {
			return
		}
		err = mysql.insertConversationEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
	}

	if recipientAccount != "" && sender != recipient {
		err = mysql.insertSequenceEntry(ctx, recipientAccount, nanotime, id)
		if err != nil {
			return
		}
		err = mysql.insertConversationEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
	}

	return
}

func (mysql *MySQL) msgidToTime(ctx context.Context, msgid string) (result time.Time, err error) {
	// in theory, we could optimize out a roundtrip to the database by using a subquery instead:
	// sequence.nanotime > (
	//     SELECT sequence.nanotime FROM sequence, history
	//     WHERE sequence.history_id = history.id AND history.msgid = ?
	//     LIMIT 1)
	// however, this doesn't handle the BETWEEN case with one or two msgids, where we
	// don't initially know whether the interval is going forwards or backwards. to simplify
	// the logic,  resolve msgids to timestamps "manually" in all cases, using a separate query.
	decoded, err := decodeMsgid(msgid)
	if err != nil {
		return
	}
	row := mysql.db.QueryRowContext(ctx, `
		SELECT sequence.nanotime FROM sequence
		INNER JOIN history ON history.id = sequence.history_id
		WHERE history.msgid = ? LIMIT 1;`, decoded)
	var nanotime int64
	err = row.Scan(&nanotime)
	if mysql.logError("could not resolve msgid to time", err) {
		return
	}
	result = time.Unix(0, nanotime).UTC()
	return
}

func (mysql *MySQL) selectItems(ctx context.Context, query string, args ...interface{}) (results []history.Item, err error) {
	rows, err := mysql.db.QueryContext(ctx, query, args...)
	if mysql.logError("could not select history items", err) {
		return
	}

	defer rows.Close()

	for rows.Next() {
		var blob []byte
		var item history.Item
		err = rows.Scan(&blob)
		if mysql.logError("could not scan history item", err) {
			return
		}
		err = unmarshalItem(blob, &item)
		if mysql.logError("could not unmarshal history item", err) {
			return
		}
		results = append(results, item)
	}
	return
}

func (mysql *MySQL) betweenTimestamps(ctx context.Context, target, correspondent string, after, before, cutoff time.Time, limit int) (results []history.Item, err error) {
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

	var queryBuf bytes.Buffer

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

	results, err = mysql.selectItems(ctx, queryBuf.String(), args...)
	if err == nil && !ascending {
		history.Reverse(results)
	}
	return
}

func (mysql *MySQL) Close() {
	// closing the database will close our prepared statements as well
	if mysql.db != nil {
		mysql.db.Close()
	}
	mysql.db = nil
}

// implements history.Sequence, emulating a single history buffer (for a channel,
// a single user's DMs, or a DM conversation)
type mySQLHistorySequence struct {
	mysql         *MySQL
	target        string
	correspondent string
	cutoff        time.Time
}

func (s *mySQLHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, complete bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.mysql.getTimeout())
	defer cancel()

	startTime := start.Time
	if start.Msgid != "" {
		startTime, err = s.mysql.msgidToTime(ctx, start.Msgid)
		if err != nil {
			return nil, false, err
		}
	}
	endTime := end.Time
	if end.Msgid != "" {
		endTime, err = s.mysql.msgidToTime(ctx, end.Msgid)
		if err != nil {
			return nil, false, err
		}
	}

	results, err = s.mysql.betweenTimestamps(ctx, s.target, s.correspondent, startTime, endTime, s.cutoff, limit)
	return results, (err == nil), err
}

func (s *mySQLHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (mysql *MySQL) MakeSequence(target, correspondent string, cutoff time.Time) history.Sequence {
	return &mySQLHistorySequence{
		target:        target,
		correspondent: correspondent,
		mysql:         mysql,
		cutoff:        cutoff,
	}
}
