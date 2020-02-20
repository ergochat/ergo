package mysql

import (
	"bytes"
	"database/sql"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/utils"
)

const (
	// latest schema of the db
	latestDbSchema   = "1"
	keySchemaVersion = "db.version"
	cleanupRowLimit  = 50
	cleanupPauseTime = 10 * time.Minute
)

type MySQL struct {
	db     *sql.DB
	logger *logger.Manager

	insertHistory      *sql.Stmt
	insertSequence     *sql.Stmt
	insertConversation *sql.Stmt

	stateMutex sync.Mutex
	expireTime time.Duration
}

func (mysql *MySQL) Initialize(logger *logger.Manager, expireTime time.Duration) {
	mysql.logger = logger
	mysql.expireTime = expireTime
}

func (mysql *MySQL) SetExpireTime(expireTime time.Duration) {
	mysql.stateMutex.Lock()
	mysql.expireTime = expireTime
	mysql.stateMutex.Unlock()
}

func (mysql *MySQL) getExpireTime() (expireTime time.Duration) {
	mysql.stateMutex.Lock()
	expireTime = mysql.expireTime
	mysql.stateMutex.Unlock()
	return
}

func (mysql *MySQL) Open(username, password, host string, port int, database string) (err error) {
	// TODO: timeouts!
	var address string
	if port != 0 {
		address = fmt.Sprintf("tcp(%s:%d)", host, port)
	}

	mysql.db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@%s/%s", username, password, address, database))
	if err != nil {
		return err
	}

	err = mysql.fixSchemas()
	if err != nil {
		return err
	}

	err = mysql.prepareStatements()
	if err != nil {
		return err
	}

	go mysql.cleanupLoop()

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

	_, err = mysql.db.Exec(`CREATE TABLE sequence (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		target VARBINARY(64) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		history_id BIGINT NOT NULL,
		KEY (target, nanotime),
		KEY (history_id)
	) CHARSET=ascii COLLATE=ascii_bin;`)
	if err != nil {
		return err
	}

	_, err = mysql.db.Exec(`CREATE TABLE conversations (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
		lower_target VARBINARY(64) NOT NULL,
		upper_target VARBINARY(64) NOT NULL,
		nanotime BIGINT UNSIGNED NOT NULL,
		history_id BIGINT NOT NULL,
		KEY (lower_target, upper_target, nanotime),
		KEY (history_id)
	) CHARSET=ascii COLLATE=ascii_bin;`)
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
		(lower_target, upper_target, nanotime, history_id) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return
	}

	return
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

	id, err := mysql.insertBase(item)
	if err != nil {
		return
	}

	err = mysql.insertSequenceEntry(target, item.Message.Time, id)
	return
}

func (mysql *MySQL) insertSequenceEntry(target string, messageTime time.Time, id int64) (err error) {
	_, err = mysql.insertSequence.Exec(target, messageTime.UnixNano(), id)
	mysql.logError("could not insert sequence entry", err)
	return
}

func (mysql *MySQL) insertConversationEntry(sender, recipient string, messageTime time.Time, id int64) (err error) {
	lower, higher := stringMinMax(sender, recipient)
	_, err = mysql.insertConversation.Exec(lower, higher, messageTime.UnixNano(), id)
	mysql.logError("could not insert conversations entry", err)
	return
}

func (mysql *MySQL) insertBase(item history.Item) (id int64, err error) {
	value, err := marshalItem(&item)
	if mysql.logError("could not marshal item", err) {
		return
	}

	msgidBytes, err := decodeMsgid(item.Message.Msgid)
	if mysql.logError("could not decode msgid", err) {
		return
	}

	result, err := mysql.insertHistory.Exec(value, msgidBytes)
	if mysql.logError("could not insert item", err) {
		return
	}
	id, err = result.LastInsertId()
	if mysql.logError("could not insert item", err) {
		return
	}

	return
}

func stringMinMax(first, second string) (min, max string) {
	if first < second {
		return first, second
	} else {
		return second, first
	}
}

func (mysql *MySQL) AddDirectMessage(sender, recipient string, senderPersistent, recipientPersistent bool, item history.Item) (err error) {
	if mysql.db == nil {
		return
	}

	if !(senderPersistent || recipientPersistent) {
		return
	}

	if sender == "" || recipient == "" {
		return utils.ErrInvalidParams
	}

	id, err := mysql.insertBase(item)
	if err != nil {
		return
	}

	if senderPersistent {
		mysql.insertSequenceEntry(sender, item.Message.Time, id)
		if err != nil {
			return
		}
	}

	if recipientPersistent && sender != recipient {
		err = mysql.insertSequenceEntry(recipient, item.Message.Time, id)
		if err != nil {
			return
		}
	}

	err = mysql.insertConversationEntry(sender, recipient, item.Message.Time, id)

	return
}

func (mysql *MySQL) msgidToTime(msgid string) (result time.Time, err error) {
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
	row := mysql.db.QueryRow(`
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

func (mysql *MySQL) selectItems(query string, args ...interface{}) (results []history.Item, err error) {
	rows, err := mysql.db.Query(query, args...)
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

func (mysql *MySQL) BetweenTimestamps(sender, recipient string, after, before, cutoff time.Time, limit int) (results []history.Item, err error) {
	useSequence := true
	var lowerTarget, upperTarget string
	if sender != "" {
		lowerTarget, upperTarget = stringMinMax(sender, recipient)
		useSequence = false
	}

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
		args = append(args, recipient)
	} else {
		fmt.Fprintf(&queryBuf, " conversations.lower_target = ? AND conversations.upper_target = ?")
		args = append(args, lowerTarget)
		args = append(args, upperTarget)
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

	results, err = mysql.selectItems(queryBuf.String(), args...)
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
	mysql     *MySQL
	sender    string
	recipient string
	cutoff    time.Time
}

func (s *mySQLHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, complete bool, err error) {
	startTime := start.Time
	if start.Msgid != "" {
		startTime, err = s.mysql.msgidToTime(start.Msgid)
		if err != nil {
			return nil, false, err
		}
	}
	endTime := end.Time
	if end.Msgid != "" {
		endTime, err = s.mysql.msgidToTime(end.Msgid)
		if err != nil {
			return nil, false, err
		}
	}

	results, err = s.mysql.BetweenTimestamps(s.sender, s.recipient, startTime, endTime, s.cutoff, limit)
	return results, (err == nil), err
}

func (s *mySQLHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (mysql *MySQL) MakeSequence(sender, recipient string, cutoff time.Time) history.Sequence {
	return &mySQLHistorySequence{
		sender:    sender,
		recipient: recipient,
		mysql:     mysql,
		cutoff:    cutoff,
	}
}
