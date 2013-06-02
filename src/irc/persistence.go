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

type RowId uint64

type Queryable interface {
	Exec(string, ...interface{}) (sql.Result, error)
	Query(string, ...interface{}) (*sql.Rows, error)
	QueryRow(string, ...interface{}) *sql.Row
}

type Savable interface {
	Save(q Queryable) bool
}

//
// general
//

func NewDatabase() (db *sql.DB) {
	db, err := sql.Open("sqlite3", "ergonomadic.db")
	if err != nil {
		log.Fatalln("cannot open database")
	}
	return
}

func readLines(filename string) <-chan string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	reader := bufio.NewReader(file)
	lines := make(chan string)
	go func(lines chan<- string) {
		defer file.Close()
		defer close(lines)
		for {
			line, err := reader.ReadString(';')
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

func ExecSqlFile(db *sql.DB, filename string) {
	Transact(db, func(q Queryable) bool {
		for line := range readLines(filepath.Join("sql", filename)) {
			log.Println(line)
			_, err := q.Exec(line)
			if err != nil {
				log.Fatalln(err)
			}
		}
		return true
	})
}

func Transact(db *sql.DB, txf func(Queryable) bool) {
	tx, err := db.Begin()
	if err != nil {
		log.Panicln(err)
	}
	if txf(tx) {
		tx.Commit()
	} else {
		tx.Rollback()
	}
}

func Save(db *sql.DB, s Savable) {
	Transact(db, s.Save)
}

//
// general purpose sql
//

func FindId(q Queryable, sql string, args ...interface{}) (rowId RowId, err error) {
	row := q.QueryRow(sql, args...)
	err = row.Scan(&rowId)
	return
}

func Count(q Queryable, sql string, args ...interface{}) (count uint, err error) {
	row := q.QueryRow(sql, args...)
	err = row.Scan(&count)
	return
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

func FindAllUsers(q Queryable) (urs []UserRow, err error) {
	var rows *sql.Rows
	rows, err = q.Query("SELECT id, nick, hash FROM user")
	if err != nil {
		return
	}
	urs = make([]UserRow, 0)
	for rows.Next() {
		ur := UserRow{}
		err = rows.Scan(&(ur.id), &(ur.nick), &(ur.hash))
		if err != nil {
			return
		}
		urs = append(urs, ur)
	}
	return
}

func FindUserByNick(q Queryable, nick string) (ur *UserRow, err error) {
	ur = &UserRow{}
	row := q.QueryRow("SELECT id, nick, hash FROM user LIMIT 1 WHERE nick = ?",
		nick)
	err = row.Scan(&(ur.id), &(ur.nick), &(ur.hash))
	return
}

func FindUserIdByNick(q Queryable, nick string) (RowId, error) {
	return FindId(q, "SELECT id FROM user WHERE nick = ?", nick)
}

func FindChannelByName(q Queryable, name string) (cr *ChannelRow) {
	cr = new(ChannelRow)
	row := q.QueryRow("SELECT id, name FROM channel LIMIT 1 WHERE name = ?", name)
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

func DeleteUser(q Queryable, user *User) (err error) {
	_, err = q.Exec("DELETE FROM user WHERE id = ?", *(user.id))
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

func FindChannelIdByName(q Queryable, name string) (RowId, error) {
	return FindId(q, "SELECT id FROM channel WHERE name = ?", name)
}

func FindChannelsForUser(q Queryable, userId RowId) (crs []ChannelRow, err error) {
	query := ` FROM channel WHERE id IN
(SELECT channel_id from user_channel WHERE user_id = ?)`
	count, err := Count(q, "SELECT COUNT(id)"+query, userId)
	if err != nil {
		return
	}
	rows, err := q.Query("SELECT id, name"+query, userId)
	if err != nil {
		return
	}
	crs = make([]ChannelRow, count)
	var i = 0
	for rows.Next() {
		cr := ChannelRow{}
		err = rows.Scan(&(cr.id), &(cr.name))
		if err != nil {
			return
		}
		crs[i] = cr
		i++
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

func DeleteChannel(q Queryable, channel *Channel) (err error) {
	_, err = q.Exec("DELETE FROM channel WHERE id = ?", *(channel.id))
	return
}
