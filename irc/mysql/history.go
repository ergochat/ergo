// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	_ "github.com/go-sql-driver/mysql"
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
	latestDbMinorVersion  = "2"
	keySchemaMinorVersion = "db.minorversion"
	cleanupRowLimit       = 50
	cleanupPauseTime      = 10 * time.Minute
)

type e struct{}

type MySQL struct {
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

var _ history.Database = (*MySQL)(nil)

func NewMySQLDatabase(logger *logger.Manager, config Config) (*MySQL, error) {
	var mysql MySQL

	mysql.logger = logger
	mysql.wakeForgetter = make(chan e, 1)
	mysql.SetConfig(config)

	return &mysql, mysql.open()
}

func (mysql *MySQL) SetConfig(config Config) {
	mysql.timeout.Store(uint64(config.Timeout))
	var trackAccountMessages uint32
	if config.TrackAccountMessages {
		trackAccountMessages = 1
	}
	mysql.trackAccountMessages.Store(trackAccountMessages)
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

func (m *MySQL) open() (err error) {
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

	if m.config.MaxConns != 0 {
		m.db.SetMaxOpenConns(m.config.MaxConns)
		m.db.SetMaxIdleConns(m.config.MaxConns)
	}
	if m.config.ConnMaxLifetime != 0 {
		m.db.SetConnMaxLifetime(m.config.ConnMaxLifetime)
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
		key_name VARCHAR(32) PRIMARY KEY,
		value VARCHAR(32) NOT NULL
	) CHARSET=ascii COLLATE=ascii_bin;`)
	if err != nil {
		return err
	}

	var schema string
	err = mysql.db.QueryRow(`SELECT value FROM metadata WHERE key_name = ?;`, keySchemaVersion).Scan(&schema)
	if err == sql.ErrNoRows {
		err = mysql.createTables()
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`INSERT INTO metadata (key_name, value) VALUES (?, ?);`, keySchemaVersion, latestDbSchema)
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`INSERT INTO metadata (key_name, value) VALUES (?, ?);`, keySchemaMinorVersion, latestDbMinorVersion)
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
	err = mysql.db.QueryRow(`SELECT value FROM metadata WHERE key_name = ?;`, keySchemaMinorVersion).Scan(&minorVersion)
	if err == sql.ErrNoRows {
		// XXX for now, the only minor version upgrade is the account tracking tables
		err = mysql.createComplianceTables()
		if err != nil {
			return
		}
		err = mysql.createCorrespondentsTable()
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`INSERT INTO metadata (key_name, value) VALUES (?, ?);`, keySchemaMinorVersion, latestDbMinorVersion)
		if err != nil {
			return
		}
	} else if err == nil && minorVersion == "1" {
		// upgrade from 2.1 to 2.2: create the correspondents table
		err = mysql.createCorrespondentsTable()
		if err != nil {
			return
		}
		_, err = mysql.db.Exec(`UPDATE metadata SET value = ? WHERE key_name = ?;`, latestDbMinorVersion, keySchemaMinorVersion)
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
		history_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
		target VARBINARY(%[1]d) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		KEY (target, nanotime)
	) CHARSET=ascii COLLATE=ascii_bin;`, MaxTargetLength))
	if err != nil {
		return err
	}
	/* XXX: this table used to be:
	CREATE TABLE sequence (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		target VARBINARY(%[1]d) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		history_id BIGINT NOT NULL,
		KEY (target, nanotime),
		KEY (history_id)
	) CHARSET=ascii COLLATE=ascii_bin;
	Some users may still be using the old schema.
	*/

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

	err = mysql.createCorrespondentsTable()
	if err != nil {
		return err
	}

	err = mysql.createComplianceTables()
	if err != nil {
		return err
	}

	return nil
}

func (mysql *MySQL) createCorrespondentsTable() (err error) {
	_, err = mysql.db.Exec(fmt.Sprintf(`CREATE TABLE correspondents (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		target VARBINARY(%[1]d) NOT NULL,
		correspondent VARBINARY(%[1]d) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		UNIQUE KEY (target, correspondent),
		KEY (target, nanotime),
		KEY (nanotime)
	) CHARSET=ascii COLLATE=ascii_bin;`, MaxTargetLength))
	return
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

	if maxNanotime != 0 {
		mysql.deleteCorrespondents(ctx, maxNanotime)
	}

	return len(ids), mysql.deleteHistoryIDs(ctx, ids)
}

func (mysql *MySQL) deleteHistoryIDs(ctx context.Context, ids []uint64) (err error) {
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

	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM conversations WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM sequence WHERE history_id in %s;`, inClause))
	if err != nil {
		return
	}
	if mysql.isTrackingAccountMessages() {
		_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM account_messages WHERE history_id in %s;`, inClause))
		if err != nil {
			return
		}
	}
	_, err = mysql.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM history WHERE id in %s;`, inClause))
	if err != nil {
		return
	}

	return
}

func (mysql *MySQL) selectCleanupIDs(ctx context.Context, age time.Duration) (ids []uint64, maxNanotime int64, err error) {
	rows, err := mysql.db.QueryContext(ctx, `
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

func (mysql *MySQL) deleteCorrespondents(ctx context.Context, threshold int64) {
	result, err := mysql.db.ExecContext(ctx, `DELETE FROM correspondents WHERE nanotime <= (?);`, threshold)
	if err != nil {
		mysql.logError("error deleting correspondents", err)
	} else {
		count, err := result.RowsAffected()
		if !mysql.logError("error deleting correspondents", err) {
			mysql.logger.Debug(fmt.Sprintf("deleted %d correspondents entries", count))
		}
	}
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
	mysql.insertCorrespondent, err = mysql.db.Prepare(`INSERT INTO correspondents
		(target, correspondent, nanotime) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE nanotime = GREATEST(nanotime, ?);`)
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
	return time.Duration(mysql.timeout.Load())
}

func (mysql *MySQL) isTrackingAccountMessages() bool {
	return mysql.trackAccountMessages.Load() != 0
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

func (mysql *MySQL) insertCorrespondentsEntry(ctx context.Context, target, correspondent string, messageTime int64, historyId int64) (err error) {
	_, err = mysql.insertCorrespondent.ExecContext(ctx, target, correspondent, messageTime, messageTime)
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
		err = mysql.insertConversationEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
		err = mysql.insertCorrespondentsEntry(ctx, senderAccount, recipient, nanotime, id)
		if err != nil {
			return
		}
	}

	if recipientAccount != "" && sender != recipient {
		err = mysql.insertConversationEntry(ctx, recipientAccount, sender, nanotime, id)
		if err != nil {
			return
		}
		err = mysql.insertCorrespondentsEntry(ctx, recipientAccount, sender, nanotime, id)
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
	decoded, err := decodeMsgid(msgid)
	if err != nil {
		return
	}
	cols := `sequence.nanotime, conversations.nanotime`
	if includeData {
		cols = `sequence.nanotime, conversations.nanotime, history.id, history.data`
	}
	row := mysql.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT %s FROM history
		LEFT JOIN sequence ON history.id = sequence.history_id
		LEFT JOIN conversations ON history.id = conversations.history_id
		WHERE history.msgid = ? LIMIT 1;`, cols), decoded)
	var nanoSeq, nanoConv sql.NullInt64
	if !includeData {
		err = row.Scan(&nanoSeq, &nanoConv)
	} else {
		err = row.Scan(&nanoSeq, &nanoConv, &id, &data)
	}
	if err != sql.ErrNoRows {
		mysql.logError("could not resolve msgid to time", err)
	}
	if err != nil {
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

	results, err = mysql.selectItems(ctx, queryBuf.String(), args...)
	if err == nil && !ascending {
		slices.Reverse(results)
	}
	return
}

func (mysql *MySQL) listCorrespondentsInternal(ctx context.Context, target string, after, before, cutoff time.Time, limit int) (results []history.TargetListing, err error) {
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

	rows, err := mysql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	var correspondent string
	var nanotime int64
	for rows.Next() {
		err = rows.Scan(&correspondent, &nanotime)
		if err != nil {
			return
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

func (mysql *MySQL) ListChannels(cfchannels []string) (results []history.TargetListing, err error) {
	if mysql.db == nil {
		return
	}

	if len(cfchannels) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), mysql.getTimeout())
	defer cancel()

	var queryBuf strings.Builder
	args := make([]interface{}, 0, len(results))
	// https://dev.mysql.com/doc/refman/8.0/en/group-by-optimization.html
	// this should be a "loose index scan"
	queryBuf.WriteString(`SELECT sequence.target, MAX(sequence.nanotime) FROM sequence
		WHERE sequence.target IN (`)
	for i, chname := range cfchannels {
		if i != 0 {
			queryBuf.WriteString(", ")
		}
		queryBuf.WriteByte('?')
		args = append(args, chname)
	}
	queryBuf.WriteString(") GROUP BY sequence.target;")

	rows, err := mysql.db.QueryContext(ctx, queryBuf.String(), args...)
	if mysql.logError("could not query channel listings", err) {
		return
	}
	defer rows.Close()

	var target string
	var nanotime int64
	for rows.Next() {
		err = rows.Scan(&target, &nanotime)
		if mysql.logError("could not scan channel listings", err) {
			return
		}
		results = append(results, history.TargetListing{
			CfName: target,
			Time:   time.Unix(0, nanotime).UTC(),
		})
	}
	return
}

func (mysql *MySQL) Close() error {
	// closing the database will close our prepared statements as well
	if mysql.db != nil {
		mysql.db.Close()
	}
	mysql.db = nil
	return nil
}

// implements history.Sequence, emulating a single history buffer (for a channel,
// a single user's DMs, or a DM conversation)
type mySQLHistorySequence struct {
	mysql         *MySQL
	target        string
	correspondent string
	cutoff        time.Time
}

func (s *mySQLHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.mysql.getTimeout())
	defer cancel()

	startTime := start.Time
	if start.Msgid != "" {
		startTime, _, _, err = s.mysql.lookupMsgid(ctx, start.Msgid, false)
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
		endTime, _, _, err = s.mysql.lookupMsgid(ctx, end.Msgid, false)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}

	results, err = s.mysql.betweenTimestamps(ctx, s.target, s.correspondent, startTime, endTime, s.cutoff, limit)
	return results, err
}

func (s *mySQLHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (seq *mySQLHistorySequence) ListCorrespondents(start, end history.Selector, limit int) (results []history.TargetListing, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), seq.mysql.getTimeout())
	defer cancel()

	// TODO accept msgids here?
	startTime := start.Time
	endTime := end.Time

	results, err = seq.mysql.listCorrespondentsInternal(ctx, seq.target, startTime, endTime, seq.cutoff, limit)
	seq.mysql.logError("could not read correspondents", err)
	return
}

func (seq *mySQLHistorySequence) Cutoff() time.Time {
	return seq.cutoff
}

func (seq *mySQLHistorySequence) Ephemeral() bool {
	return false
}

func (mysql *MySQL) MakeSequence(target, correspondent string, cutoff time.Time) history.Sequence {
	return &mySQLHistorySequence{
		target:        target,
		correspondent: correspondent,
		mysql:         mysql,
		cutoff:        cutoff,
	}
}
