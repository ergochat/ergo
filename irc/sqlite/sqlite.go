package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/utils"
)

type Sqlite struct {
	sync.Mutex
	filename             string
	pool                 *sqlitex.Pool
	log                  *logger.Manager
	timeout              time.Duration
	maxConns             int
	trackAccountMessages bool
	cleanupRowLimit      int
	cleanupExpiry        time.Duration
	cleanupPauseTime     time.Duration
	// Trigger forgot loop iteration
	wakeForgetter chan bool
}

// Assert interface implementation
var _ history.Database = (*Sqlite)(nil)

// New creates a new history store using Sqlite.
func New(logger *logger.Manager, config history.Config) (*Sqlite, error) {
	var err error
	out := &Sqlite{
		log:              logger,
		cleanupRowLimit:  50,
		cleanupPauseTime: 10 * time.Minute,
		wakeForgetter:    make(chan bool, 1),
	}
	out.setConfigUnlocked(config)
	if err := out.open(); err != nil {
		return nil, err
	}

	return out, err
}

func (db *Sqlite) SetConfig(config history.Config) {
	db.Close()
	db.Lock()
	defer db.Unlock()
	db.setConfigUnlocked(config)
	if err := db.open(); err != nil {
		db.log.Error("sqlite", "failed to open", err.Error())
	}
}

func (db *Sqlite) setConfigUnlocked(config history.Config) {
	if config.Type != "sqlite" {
		panic("invalid type for sqlite config")
	}
	db.filename = config.Path
	db.timeout = config.Timeout
	db.maxConns = config.MaxConns
	db.timeout = config.Timeout
	db.trackAccountMessages = config.TrackAccountMessages
	db.cleanupExpiry = config.ExpireTime
}

func (db *Sqlite) open() error {
	var err error
	db.pool, err = sqlitex.NewPool(db.filename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenCreate | sqlite.OpenURI,
		PoolSize: db.maxConns,
		PrepareConn: func(conn *sqlite.Conn) error {
			// Enable foreign keys. See https://sqlite.org/foreignkeys.html
			return sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON;", nil)
		},
	})
	if err != nil {
		return fmt.Errorf("failed to init database: %w", err)
	}
	conn, _ := db.pool.Take(context.TODO())
	defer db.pool.Put(conn)

	pragmas := []string{
		// See https://litestream.io/tips/#synchronous-pragma
		"PRAGMA synchronous = NORMAL;",
		// See https://litestream.io/tips/#synchronous-pragma
		"PRAGMA busy_timeout = 5000;",
	}
	for _, p := range pragmas {
		db.log.Debug("executing pragma", "pragma", p)
		err = sqlitex.ExecuteTransient(conn, strings.TrimSpace(p), nil)
		if err != nil {
			return err
		}
	}
	versionStart, versionEnd, err := migrate(conn, migrationSrcs)
	if err != nil {
		return fmt.Errorf("failed migrate database: %w", err)
	}
	if versionStart != versionEnd {
		db.log.Warning("sqlite",
			fmt.Sprintf("migration from version %d to %d", versionStart, versionEnd))
	}
	db.log.Info("sqlite", "starting cleanup loop")
	go db.cleanupLoop()
	db.log.Info("sqlite", "starting forget loop")
	go db.forgetLoop()
	return nil
}

var errNoRows = errors.New("sql: no rows in result set")

func (db *Sqlite) Close() error {
	return db.pool.Close()
}

func (db *Sqlite) AddChannelItem(target string, item history.Item, account string) error {
	if target == "" {
		return utils.ErrInvalidParams
	}

	var err error
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)
	// Wrap in savepoint
	defer sqlitex.Save(conn)(&err)

	id, err := db.insertBase(conn, item)
	if err != nil {
		return err
	}

	const sql = `insert into sequence (target, nanotime, history_id) values (?, ?, ?);`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{
			target,
			item.Message.Time.UnixNano(),
			id,
		},
	})
	if err != nil {
		return err
	}

	if err = db.insertAccountMessage(conn, id, account); err != nil {
		return err
	}
	return nil
}

func (db *Sqlite) AddDirectMessage(sndr, sndrAcc, rcpt, rcptAcc string, item history.Item) error {
	if sndrAcc == "" && rcptAcc == "" {
		return nil
	}
	if sndr == "" || rcpt == "" {
		return utils.ErrInvalidParams
	}
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)
	defer sqlitex.Save(conn)(&err)

	id, err := db.insertBase(conn, item)
	if err != nil {
		return err
	}

	nanotime := item.Message.Time.UnixNano()
	if sndrAcc != "" {
		if err = db.insertConversation(conn, sndrAcc, rcpt, nanotime, id); err != nil {
			return err
		}
		if err = db.insertCorrespondent(
			conn, sndrAcc, rcpt, nanotime, id); err != nil {
			return err
		}
	}
	if rcptAcc != "" && sndr != rcpt {
		if err = db.insertConversation(conn, rcptAcc, sndr, nanotime, id); err != nil {
			return err
		}
		if err = db.insertCorrespondent(
			conn, rcptAcc, sndr, nanotime, id); err != nil {
			return err
		}
	}
	if err = db.insertAccountMessage(conn, id, sndrAcc); err != nil {
		return err
	}
	return nil
}

func (db *Sqlite) insertBase(conn *sqlite.Conn, item history.Item) (id int64, err error) {
	value, err := history.MarshalItem(&item)
	if err != nil {
		return 0, fmt.Errorf("could not marshal item: %w", err)
	}

	msgidBytes, err := utils.DecodeSecretToken(item.Message.Msgid)
	if err != nil {
		return 0, fmt.Errorf("could not decode msgid: %w", err)
	}

	const sql = `insert into history (data, msgid) values (?, ?) returning id;`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{value, msgidBytes},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id = stmt.ColumnInt64(0)
			return nil
		},
	})
	if err != nil {
		return 0, fmt.Errorf("could not insert item: %w", err)
	}
	return
}

func (db *Sqlite) insertAccountMessage(conn *sqlite.Conn, id int64, account string) (err error) {
	if account == "" || !db.trackAccountMessages {
		return
	}
	const sql = `insert into account_messages
	(history_id, account)
	values (?, ?)`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{id, account},
	})
	if err != nil {
		return fmt.Errorf("could not insert account-message entry: %w", err)
	}
	return nil
}

func (db *Sqlite) insertConversation(conn *sqlite.Conn, target, correspondent string, mTime, id int64) (err error) {
	const sql = `insert into conversations
	(target, correspondent, nanotime, history_id)
	values (?, ?, ?, ?)`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{target, correspondent, mTime, id},
	})
	if err != nil {
		return fmt.Errorf("could not insert conversations entry: %w", err)
	}
	return
}
func (db *Sqlite) insertCorrespondent(conn *sqlite.Conn, target, correspondent string, mTime, _ int64) error {
	var err error
	const sql = `insert into correspondents
	(target, correspondent, nanotime)
	values (?, ?, ?) on conflict (id) do update
	nanotime = max(nanotime, ?)`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{target, correspondent, mTime},
	})
	if err != nil {
		return fmt.Errorf("could not insert correspondents entry: %w", err)
	}
	return nil
}

func (db *Sqlite) DeleteMsgid(msgid, accName string) error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)
	defer sqlitex.Save(conn)(&err)

	_, id, data, err := db.lookupMsgid(conn, msgid, true)
	if err != nil {
		if err == errNoRows {
			return history.ErrNotFound
		}
		return err
	}

	if accName != "*" {
		var item history.Item
		err = history.UnmarshalItem(data, &item)
		// delete if the entry is corrupt
		if err == nil && item.AccountName != accName {
			return history.ErrDisallowed
		}
	}

	err = db.deleteHistoryIDs(conn, []uint64{id})
	if err != nil {
		return fmt.Errorf("couldn't delete msgid: %w", err)
	}
	return nil
}

func (db *Sqlite) lookupMsgid(conn *sqlite.Conn, msgid string, includeData bool) (
	result time.Time, id uint64, data []byte, err error,
) {
	decoded, err := utils.DecodeSecretToken(msgid)
	if err != nil {
		err = errNoRows
		return
	}
	cols := "s.nanotime as snano, c.nanotime as cnano"
	if includeData {
		cols = cols + ", h.id, h.data"
	}
	sql := fmt.Sprintf(`select %s from history h
		left join sequence s on h.id = s.history_id
		left join conversations c on h.id = c.history_id
		where h.msgid = ? limit 1`, cols)

	var nanoTime int64

	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{decoded},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			switch {
			case !stmt.IsNull("snano"):
				nanoTime = stmt.GetInt64("snano")
			case !stmt.IsNull("cnano"):
				nanoTime = stmt.GetInt64("cnano")
			}
			if includeData {
				id = uint64(stmt.GetInt64("id"))
				_ = stmt.GetBytes("data", data)
			}
			return nil
		},
	})
	if err != nil {
		err = fmt.Errorf("could not resolve msgid to time: %w", err)
		return
	}
	if id == 0 {
		err = errNoRows
		return
	}
	if nanoTime == 0 {
		err = errNoRows
		return
	}
	result = time.Unix(0, nanoTime).UTC()
	return
}

func (db *Sqlite) deleteHistoryIDs(conn *sqlite.Conn, ids []uint64) error {
	if len(ids) == 0 {
		return nil
	}
	var err error
	// build the IN clause manually
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

	sqlConv := fmt.Sprintf("delete from conversations where history_id in %s", inClause)
	if err = sqlitex.Execute(conn, sqlConv, nil); err != nil {
		return err
	}

	sqlSeq := fmt.Sprintf("delete from sequence where history_id in %s", inClause)
	if err = sqlitex.Execute(conn, sqlSeq, nil); err != nil {
		return err
	}
	if db.trackAccountMessages {
		sqlAccMsg := fmt.Sprintf("delete from account_messages where history_id in %s", inClause)
		if err = sqlitex.Execute(conn, sqlAccMsg, nil); err != nil {
			return err
		}
	}
	sqlHist := fmt.Sprintf("delete from history where id in %s", inClause)
	if err = sqlitex.Execute(conn, sqlHist, nil); err != nil {
		return err
	}
	return nil
}

func (db *Sqlite) ListChannels(channels []string) (results []history.TargetListing, err error) {
	if len(channels) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)

	var sql strings.Builder
	args := make([]any, 0, len(results))
	sql.WriteString(`select s.target, max(s.nanotime) as nanotime from sequence s
	where s.target in (`)
	for i, s := range channels {
		if i != 0 {
			sql.WriteString(", ")
		}
		sql.WriteByte('?')
		args = append(args, s)
	}
	sql.WriteString(") group by s.target;")
	err = sqlitex.Execute(conn, sql.String(), &sqlitex.ExecOptions{
		Args: args,
		ResultFunc: func(stmt *sqlite.Stmt) error {
			nt := stmt.GetInt64("nanotime")
			results = append(results, history.TargetListing{
				CfName: stmt.GetText("target"),
				Time:   time.Unix(0, nt).UTC(),
			})
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not query channel listings: %w", err)
	}
	return
}

func (db *Sqlite) ListCorrespondents(
	target string,
	start, end time.Time, limit int,
) ([]history.TargetListing, error) {
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)

	after, before, ascending := history.MinMaxAsc(start, end, time.Time{})
	direction := "asc"
	if !ascending {
		direction = "desc"
	}

	var sql strings.Builder
	args := make([]any, 0, 4)
	sql.WriteString("select correspondent, nanotime from correspondents where target = ?")
	args = append(args, target)
	if !after.IsZero() {
		sql.WriteString(" and nanotime > ?")
		args = append(args, after.UnixNano())
	}
	if !before.IsZero() {
		sql.WriteString(" and nanotime < ?")
		args = append(args, before.UnixNano())
	}
	fmt.Fprintf(&sql, " order by nanotime %s limit ?;", direction)
	args = append(args, limit)
	var results []history.TargetListing
	err := sqlitex.Execute(conn, sql.String(), &sqlitex.ExecOptions{
		Args: args,
		ResultFunc: func(stmt *sqlite.Stmt) error {
			nt := stmt.GetInt64("nanotime")
			results = append(results, history.TargetListing{
				CfName: stmt.GetText("correspondent"),
				Time:   time.Unix(0, nt).UTC(),
			})
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not query channel listings: %w", err)
	}
	return results, nil
}

func (db *Sqlite) cleanupLoop() {
	for {
		_, err := db.doCleanup(db.cleanupExpiry)
		if err != nil {
			db.log.Error("sqlite", "error during row cleanup", err.Error())
		}
		time.Sleep(db.cleanupPauseTime)
	}
}

func (db *Sqlite) Forget(account string) {
	if account == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	var err error
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)

	const sql = "insert into forget (account) values (?)"
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{account},
	})
	if err != nil {
		db.log.Error("sqlite",
			fmt.Sprintf("could not query channel listings: %s", err))
	}
	// trigger forget processing before cleanupPauseTime
	select {
	case db.wakeForgetter <- true:
	default:
	}
}

func (db *Sqlite) doCleanup(age time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	var err error
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)

	var maxNanotime int64

	var ids []uint64
	threshold := time.Now().Add(-age).UnixNano()

	const sql = `select h.id, s.nanotime as snano, c.nanotime as cnano
	from history h
	left join sequence s on h.id = s.history_id
	left join conversations c on h.id = c.history_id
	order by h.id limit ?`
	err = sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
		Args: []any{db.cleanupRowLimit},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := uint64(stmt.GetInt64("id"))
			var nanoTime int64
			switch {
			case !stmt.IsNull("snano"):
				nanoTime = stmt.GetInt64("snano")
			case !stmt.IsNull("cnano"):
				nanoTime = stmt.GetInt64("cnano")
			}
			if nanoTime < threshold {
				ids = append(ids, id)
				maxNanotime = max(maxNanotime, nanoTime)
			}
			return nil
		},
	})
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		db.log.Debug("sqlite", "found no rows to clean up")
		return 0, nil
	}
	if maxNanotime != 0 {
		const sqlC = "delete from correspondents where nanotime <= ?"
		err = sqlitex.Execute(conn, sqlC, &sqlitex.ExecOptions{
			Args: []any{maxNanotime},
		})
		if err != nil {
			db.log.Error("sqlite", "error deleting correspondents", err.Error())
		} else {
			db.log.Debug("sqlite", fmt.Sprintf("deleted %d correspondents entries", conn.Changes()))
		}
	}
	return len(ids), db.deleteHistoryIDs(conn, ids)
}

func (db *Sqlite) forgetLoop() {
	for {
		for {
			found, err := db.doForget()
			if err != nil {
				db.log.Error("sqlite", "error processing forget", err.Error())
				time.Sleep(db.cleanupPauseTime)
			}
			if !found {
				break
			}
		}
		<-db.wakeForgetter
	}
}

func (db *Sqlite) doForget() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	var err error
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)
	//defer sqlitex.Save(conn)(&err)

	var (
		forgetID uint64
		account  string
	)
	const sqlF = "select forget.id, forget.account from forget limit 1"
	err = sqlitex.Execute(conn, sqlF, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			forgetID = uint64(stmt.GetInt64("id"))
			account = stmt.GetText("account")
			return nil
		},
	})
	if err != nil || account == "" {
		return false, err
	}

	var done bool
	for !done {
		const sqlH = "select history_id from account_messages where account = ? limit ?"
		var historyIDs []uint64
		err = sqlitex.Execute(conn, sqlH, &sqlitex.ExecOptions{
			Args: []any{account, db.cleanupRowLimit},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				historyIDs = append(historyIDs, uint64(stmt.GetInt64("history_id")))
				account = stmt.GetText("account")
				return nil
			},
		})
		if err != nil {
			return false, err
		}
		done = len(historyIDs) == 0
		if err = db.deleteHistoryIDs(conn, historyIDs); err != nil {
			return true, fmt.Errorf("couldn't delete msgid: %w", err)
		}
	}
	db.log.Debug("sqlite", "forget complete for account", account)

	const sqlD = "delete from forget where id = ?"
	err = sqlitex.Execute(conn, sqlD, &sqlitex.ExecOptions{
		Args: []any{forgetID},
	})
	return true, err
}

func (db *Sqlite) Export(account string, w io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), db.timeout)
	defer cancel()
	conn, _ := db.pool.Take(ctx)
	defer db.pool.Put(conn)

	var lastSeen uint64

	const sql = `select am.history_id as id, h.data, s.target
	from account_messages am
	inner join history h on h.id = am.history_id
	inner join sequence s on am.history_id = s.history_id
	where am.account = ? and am.history_id > ?
	limit ?`

	for {
		var count int
		err := sqlitex.Execute(conn, sql, &sqlitex.ExecOptions{
			Args: []any{account, lastSeen, db.cleanupRowLimit},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id := uint64(stmt.GetInt64("id"))
				target := stmt.GetText("target")
				var blob []byte
				_ = stmt.GetBytes("data", blob)
				var item history.Item
				if err := history.UnmarshalItem(blob, &item); err != nil {
					return err
				}
				item.CfCorrespondent = target
				jsonBlob, err := json.Marshal(item)
				if err != nil {
					return err
				}
				count++
				if lastSeen < id {
					lastSeen = id
				}
				w.Write(jsonBlob)
				w.Write([]byte{'\n'})
				return nil
			},
		})
		if err != nil {
			db.log.Error("sqlite",
				fmt.Sprintf("could not export history: %s", err))
		}
		if count == 0 {
			break
		}
	}
}

func (db *Sqlite) MakeSequence(target, correspondent string, cutoff time.Time) history.Sequence {
	return &sqliteHistorySequence{
		target:        target,
		correspondent: correspondent,
		db:            db,
		cutoff:        cutoff,
	}
}

// implements history.Sequence, emulating a single history buffer (for a channel,
// a single user's DMs, or a DM conversation)
type sqliteHistorySequence struct {
	db            *Sqlite
	target        string
	correspondent string
	cutoff        time.Time
}

func (s *sqliteHistorySequence) Between(start, end history.Selector, limit int) (results []history.Item, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.db.timeout)
	defer cancel()
	conn, _ := s.db.pool.Take(ctx)
	defer s.db.pool.Put(conn)

	startTime := start.Time
	if start.Msgid != "" {
		startTime, _, _, err = s.db.lookupMsgid(conn, start.Msgid, false)
		if err != nil {
			if err == errNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}
	endTime := end.Time
	if end.Msgid != "" {
		endTime, _, _, err = s.db.lookupMsgid(conn, end.Msgid, false)
		if err != nil {
			if err == errNoRows {
				return nil, nil
			} else {
				return nil, err
			}
		}
	}

	return s.db.betweenTimestamps(conn, s.target, s.correspondent, startTime, endTime, s.cutoff, limit)
}

func (db *Sqlite) betweenTimestamps(
	conn *sqlite.Conn, target, correspondent string,
	after, before, cutoff time.Time, limit int,
) ([]history.Item, error) {
	useSequence := correspondent == ""
	table := "sequence"
	if !useSequence {
		table = "conversations"
	}

	after, before, ascending := history.MinMaxAsc(after, before, cutoff)
	direction := "asc"
	if !ascending {
		direction = "desc"
	}

	var sql strings.Builder

	args := make([]any, 0, 6)
	fmt.Fprintf(&sql,
		"select history.data from history inner join %[1]s on history.id = %[1]s.history_id where", table)
	if useSequence {
		fmt.Fprintf(&sql, " sequence.target = ?")
		args = append(args, target)
	} else {
		fmt.Fprintf(&sql, " conversations.target = ? and conversations.correspondent = ?")
		args = append(args, target)
		args = append(args, correspondent)
	}
	if !after.IsZero() {
		fmt.Fprintf(&sql, " and %s.nanotime > ?", table)
		args = append(args, after.UnixNano())
	}
	if !before.IsZero() {
		fmt.Fprintf(&sql, " and %s.nanotime < ?", table)
		args = append(args, before.UnixNano())
	}
	fmt.Fprintf(&sql, " order by %[1]s.nanotime %[2]s limit ?;", table, direction)
	args = append(args, limit)

	var out []history.Item
	err := sqlitex.Execute(conn, sql.String(), &sqlitex.ExecOptions{
		Args: args,
		ResultFunc: func(stmt *sqlite.Stmt) error {
			// Load an Item
			var b []byte
			_ = stmt.GetBytes("data", b)
			var item history.Item
			if err := history.UnmarshalItem(b, &item); err != nil {
				return fmt.Errorf("could not unmarshal history item: %w", err)
			}
			out = append(out, item)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if !ascending {
		slices.Reverse(out)
	}
	return out, nil
}

func (s *sqliteHistorySequence) Around(start history.Selector, limit int) (results []history.Item, err error) {
	return history.GenericAround(s, start, limit)
}

func (seq *sqliteHistorySequence) Cutoff() time.Time { return seq.cutoff }
func (seq *sqliteHistorySequence) Ephemeral() bool   { return false }
