// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/utils"
)

var (
	ErrDisallowed = errors.New("disallowed")
)

const (
	// maximum length in bytes of any message target (nickname or channel name) in its
	// canonicalized (i.e., casefolded) state:
	MaxTargetLength = 64

	// latest schema of the db
	latestDbSchema   = "2"
	keySchemaVersion = "db.version"
	// minor version indicates rollback-safe upgrades, i.e.,
	// you can downgrade oragono and everything will work
	latestDbMinorVersion  = "1"
	keySchemaMinorVersion = "db.minorversion"
	cleanupRowLimit       = 50
	cleanupPauseTime      = 10 * time.Minute
)

type e struct{}

type MySQL struct {
	timeout              int64
	trackAccountMessages uint32
	db                   *sql.DB
	logger               *logger.Manager

	insertHistory        *sql.Stmt
	insertSequence       *sql.Stmt
	insertConversation   *sql.Stmt
	insertAccountMessage *sql.Stmt

	stateMutex sync.Mutex
	config     Config

	wakeForgetter chan e
}

func (mysql *MySQL) Initialize(logger *logger.Manager, config Config) {
	mysql.logger = logger
	mysql.wakeForgetter = make(chan e, 1)
	mysql.SetConfig(config)
}

func (mysql *MySQL) SetConfig(config Config) {
	atomic.StoreInt64(&mysql.timeout, int64(config.Timeout))
	var trackAccountMessages uint32
	if config.TrackAccountMessages {
		trackAccountMessages = 1
	}
	atomic.StoreUint32(&mysql.trackAccountMessages, trackAccountMessages)
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
	if m.config.SocketPath != "" {
		address = fmt.Sprintf("unix(%s)", m.config.SocketPath)
	} else if m.config.Port != 0 {
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
	go m.forgetLoop()

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
		_, err = mysql.db.Exec(`insert into metadata (key_name, value) values (?, ?);`, keySchemaMinorVersion, latestDbMinorVersion)
		if err != nil {
			return
		}
		return
	} else if err == nil && schema != latestDbSchema {
		// TODO figure out what to do about schema changes
		return &utils.IncompatibleSchemaError{CurrentVersion: schema, RequiredVersion: latestDbSchema}
	} else if err != nil {
		return err
	}

	var minorVersion string
	err = mysql.db.QueryRow(`select value from metadata where key_name = ?;`, keySchemaMinorVersion).Scan(&minorVersion)
	if err == sql.ErrNoRows {
		// XXX for now, the only minor version upgrade is the account tracking tables
		err = mysql.createComplianceTables()
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`insert into metadata (key_name, value) values (?, ?);`, keySchemaMinorVersion, latestDbMinorVersion)
		if err != nil {
			return
		}
	} else if err == nil && minorVersion != latestDbMinorVersion {
		// TODO: if minorVersion < latestDbMinorVersion, upgrade,
		// if latestDbMinorVersion < minorVersion, ignore because backwards compatible
	}
	return
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

	err = mysql.createComplianceTables()
	if err != nil {
		return err
	}

	return nil
}

func (mysql *MySQL) createComplianceTables() (err error) {
	_, err = mysql.db.Exec(fmt.Sprintf(`CREATE TABLE account_messages (
		history_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
		account VARBINARY(%[1]d) NOT NULL,
		KEY (account, history_id)
	) CHARSET=ascii COLLATE=ascii_bin;`, MaxTargetLength))
	if err != nil {
		return err
	}

	_, err = mysql.db.Exec(fmt.Sprintf(`CREATE TABLE forget (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		account VARBINARY(%[1]d) NOT NULL
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
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	ids, maxNanotime, err := mysql.selectCleanupIDs(ctx, age)
	if len(ids) == 0 {
		mysql.logger.Debug("mysql", "found no rows to clean up")
		return
	}

	mysql.logger.Debug("mysql", fmt.Sprintf("deleting %d history rows, max age %s", len(ids), utils.NanoToTimestamp(maxNanotime)))

	return len(ids), mysql.deleteHistoryIDs(ctx, ids)
}

func (mysql *MySQL) deleteHistoryIDs(ctx context.Context, ids []uint64) (err error) {
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

	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM conversations WHERE history_id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}
	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM sequence WHERE history_id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}
	if mysql.isTrackingAccountMessages() {
		_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM account_messages WHERE history_id in %s;`, inBuf.Bytes()))
		if err != nil {
			return
		}
	}
	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM history WHERE id in %s;`, inBuf.Bytes()))
	if err != nil {
		return
	}

	return
}

func (mysql *MySQL) selectCleanupIDs(ctx context.Context, age time.Duration) (ids []uint64, maxNanotime int64, err error) {
	rows, err := mysql.db.QueryContext(ctx, `
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

// wait for forget queue items and process them one by one
func (mysql *MySQL) forgetLoop() {
	defer func() {
		if r := recover(); r != nil {
			mysql.logger.Error("mysql",
				fmt.Sprintf("Panic in forget routine: %v\n%s", r, debug.Stack()))
			time.Sleep(cleanupPauseTime)
			go mysql.forgetLoop()
		}
	}()

	for {
		for {
			found, err := mysql.doForget()
			mysql.logError("error processing forget", err)
			if err != nil {
				time.Sleep(cleanupPauseTime)
			}
			if !found {
				break
			}
		}

		<-mysql.wakeForgetter
	}
}

// dequeue an item from the forget queue and process it
func (mysql *MySQL) doForget() (found bool, err error) {
	id, account, err := func() (id int64, account string, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
		defer cancel()

		row := mysql.db.QueryRowContext(ctx,
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
		count, err = mysql.doForgetIteration(account)
		elapsed := time.Since(start)
		if err != nil {
			return true, err
		}
		if count == 0 {
			break
		}
		time.Sleep(elapsed)
	}

	mysql.logger.Debug("mysql", "forget complete for account", account)

	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()
	_, err = mysql.db.ExecContext(ctx, `DELETE FROM forget where id = ?;`, id)
	return
}

func (mysql *MySQL) doForgetIteration(account string) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
	defer cancel()

	rows, err := mysql.db.QueryContext(ctx, `
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

	mysql.logger.Debug("mysql", fmt.Sprintf("deleting %d history rows from account %s", len(ids), account))
	err = mysql.deleteHistoryIDs(ctx, ids)
	return len(ids), err
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
	mysql.insertAccountMessage, err = mysql.db.Prepare(`INSERT INTO account_messages
		(history_id, account) VALUES (?, ?);`)
	if err != nil {
		return
	}

	return
}

func (mysql *MySQL) getTimeout() time.Duration {
	return time.Duration(atomic.LoadInt64(&mysql.timeout))
}

func (mysql *MySQL) isTrackingAccountMessages() bool {
	return atomic.LoadUint32(&mysql.trackAccountMessages) != 0
}

func (mysql *MySQL) logError(context string, err error) (quit bool) {
	if err != nil {
		mysql.logger.Error("mysql", context, err.Error())
		return true
	}
	return false
}

func (mysql *MySQL) Forget(account string) {
	if mysql.db == nil || account == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), mysql.getTimeout())
	defer cancel()

	_, err := mysql.db.ExecContext(ctx, `INSERT INTO forget (account) VALUES (?);`, account)
	if mysql.logError("can't insert into forget table", err) {
		return
	}

	// wake up the forget goroutine if it's blocked:
	select {
	case mysql.wakeForgetter <- e{}:
	default:
	}
}

func (mysql *MySQL) AddChannelItem(target string, item history.Item, account string) (err error) {
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
	if err != nil {
		return
	}

	err = mysql.insertAccountMessageEntry(ctx, id, account)
	if err != nil {
		return
	}

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

func (mysql *MySQL) insertAccountMessageEntry(ctx context.Context, id int64, account string) (err error) {
	if account == "" || !mysql.isTrackingAccountMessages() {
		return
	}
	_, err = mysql.insertAccountMessage.ExecContext(ctx, id, account)
	mysql.logError("could not insert account-message entry", err)
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

	err = mysql.insertAccountMessageEntry(ctx, id, senderAccount)
	if err != nil {
		return
	}

	return
}

// note that accountName is the unfolded name
func (mysql *MySQL) DeleteMsgid(msgid, accountName string) (err error) {
	if mysql.db == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), mysql.getTimeout())
	defer cancel()

	_, id, data, err := mysql.lookupMsgid(ctx, msgid, true)
	if err != nil {
		return
	}

	if accountName != "*" {
		var item history.Item
		err = unmarshalItem(data, &item)
		// delete if the entry is corrupt
		if err == nil && item.AccountName != accountName {
			return ErrDisallowed
		}
	}

	err = mysql.deleteHistoryIDs(ctx, []uint64{id})
	mysql.logError("couldn't delete msgid", err)
	return
}

func (mysql *MySQL) Export(account string, writer io.Writer) {
	if mysql.db == nil {
		return
	}

	var err error
	var lastSeen uint64
	for {
		rows := func() (count int) {
			ctx, cancel := context.WithTimeout(context.Background(), cleanupPauseTime)
			defer cancel()

			rows, rowsErr := mysql.db.QueryContext(ctx, `
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
				err = unmarshalItem(blob, &item)
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

	mysql.logError("could not export history", err)
	return
}

func (mysql *MySQL) lookupMsgid(ctx context.Context, msgid string, includeData bool) (result time.Time, id uint64, data []byte, err error) {
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
	cols := `sequence.nanotime`
	if includeData {
		cols = `sequence.nanotime, sequence.history_id, history.data`
	}
	row := mysql.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s FROM sequence
		INNER JOIN history ON history.id = sequence.history_id
		WHERE history.msgid = ? LIMIT 1;`, cols), decoded)
	var nanotime int64
	if !includeData {
		err = row.Scan(&nanotime)
	} else {
		err = row.Scan(&nanotime, &id, &data)
	}
	if err != sql.ErrNoRows {
		mysql.logError("could not resolve msgid to time", err)
	}
	if err != nil {
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
		startTime, _, _, err = s.mysql.lookupMsgid(ctx, start.Msgid, false)
		if err != nil {
			return nil, false, err
		}
	}
	endTime := end.Time
	if end.Msgid != "" {
		endTime, _, _, err = s.mysql.lookupMsgid(ctx, end.Msgid, false)
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
