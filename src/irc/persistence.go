package irc

import (
	"database/sql"
	//"fmt"
	"bufio"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Database struct {
	*sql.DB
}

type Transaction struct {
	*sql.Tx
}

type RowId uint64

type Queryable interface {
	Exec(string, ...interface{}) (sql.Result, error)
	Query(string, ...interface{}) (*sql.Rows, error)
	QueryRow(string, ...interface{}) *sql.Row
}

type TransactionFunc func(Queryable) bool

//
// general
//

func NewDatabase() *Database {
	db, err := sql.Open("sqlite3", "ergonomadic.db")
	if err != nil {
		panic("cannot open database")
	}
	return &Database{db}
}

func NewTransaction(tx *sql.Tx) *Transaction {
	return &Transaction{tx}
}

func readLines(filename string) <-chan string {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(file)
	lines := make(chan string)
	go func(lines chan<- string) {
		defer file.Close()
		defer close(lines)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			lines <- line
		}
	}(lines)
	return lines
}

func (db *Database) execSqlFile(filename string) {
	db.Transact(func(q Queryable) bool {
		for line := range readLines(filepath.Join("sql", filename)) {
			log.Println(line)
			q.Exec(line)
		}
		return true
	})
}

func (db *Database) InitTables() {
	db.execSqlFile("init.sql")
}

func (db *Database) DropTables() {
	db.execSqlFile("drop.sql")
}

func (db *Database) Transact(txf TransactionFunc) {
	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}
	if txf(tx) {
		tx.Commit()
	} else {
		tx.Rollback()
	}
}

//
// data
//

type UserRow struct {
	id   RowId
	nick string
	hash []byte
}

type ChannelRow struct {
	id   RowId
	name string
}

// user

func FindUserByNick(q Queryable, nick string) (ur *UserRow) {
	ur = new(UserRow)
	row := q.QueryRow("SELECT * FROM user LIMIT 1 WHERE nick = ?", nick)
	err := row.Scan(&ur.id, &ur.nick, &ur.hash)
	if err != nil {
		ur = nil
	}
	return
}

func FindUserIdByNick(q Queryable, nick string) (rowId RowId, err error) {
	row := q.QueryRow("SELECT id FROM user WHERE nick = ?", nick)
	err = row.Scan(&rowId)
	return
}

func FindChannelByName(q Queryable, name string) (cr *ChannelRow) {
	cr = new(ChannelRow)
	row := q.QueryRow("SELECT * FROM channel LIMIT 1 WHERE name = ?", name)
	err := row.Scan(&(cr.id), &(cr.name))
	if err != nil {
		cr = nil
	}
	return
}

func InsertUser(q Queryable, user *User) (err error) {
	_, err = q.Exec("INSERT INTO user (nick, hash) VALUES (?, ?)",
		user.nick, user.hash)
	return
}

func UpdateUser(q Queryable, user *User) (err error) {
	_, err = q.Exec("UPDATE user SET nick = ?, hash = ? WHERE id = ?",
		user.nick, user.hash, *(user.id))
	return
}

// user-channel

func DeleteAllUserChannels(q Queryable, rowId RowId) (err error) {
	_, err = q.Exec("DELETE FROM user_channel WHERE user_id = ?", rowId)
	return
}

func DeleteOtherUserChannels(q Queryable, userId RowId, channelIds []RowId) (err error) {
	_, err = q.Exec(`DELETE FROM user_channel WHERE
user_id = ? AND channel_id NOT IN ?`, userId, channelIds)
	return
}

func InsertUserChannels(q Queryable, userId RowId, channelIds []RowId) (err error) {
	ins := "INSERT OR IGNORE INTO user_channel (user_id, channel_id) VALUES "
	vals := strings.Repeat("(?, ?), ", len(channelIds))
	vals = vals[0 : len(vals)-2]
	args := make([]interface{}, 2*len(channelIds))
	var i = 0
	for channelId := range channelIds {
		args[i] = userId
		args[i+1] = channelId
		i += 2
	}
	_, err = q.Exec(ins+vals, args)
	return
}

// channel

func FindChannelIdByName(q Queryable, name string) (channelId RowId, err error) {
	row := q.QueryRow("SELECT id FROM channel WHERE name = ?", name)
	err = row.Scan(&channelId)
	return
}

func FindChannelsForUser(q Queryable, userId RowId) (crs []ChannelRow) {
	rows, err := q.Query(`SELECT * FROM channel WHERE id IN
(SELECT channel_id from user_channel WHERE user_id = ?)`, userId)
	if err != nil {
		panic(err)
	}
	crs = make([]ChannelRow, 0)
	for rows.Next() {
		cr := ChannelRow{}
		if err := rows.Scan(&(cr.id), &(cr.name)); err != nil {
			panic(err)
		}
		crs = append(crs, cr)
	}
	return
}

func InsertChannel(q Queryable, channel *Channel) (err error) {
	_, err = q.Exec("INSERT INTO channel (name) VALUES (?)", channel.name)
	return
}

func UpdateChannel(q Queryable, channel *Channel) (err error) {
	_, err = q.Exec("UPDATE channel SET name = ? WHERE id = ?",
		channel.name, *(channel.id))
	return
}
