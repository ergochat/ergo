package irc

import (
	"database/sql"
	"errors"
	"log"
	"strings"
)

type ClientLookupSet struct {
	byNick map[string]*Client
	db     *ClientDB
}

func NewClientLookupSet() *ClientLookupSet {
	return &ClientLookupSet{
		byNick: make(map[string]*Client),
		db:     NewClientDB(),
	}
}

var (
	ErrNickMissing      = errors.New("nick missing")
	ErrNicknameInUse    = errors.New("nickname in use")
	ErrNicknameMismatch = errors.New("nickname mismatch")
)

func (clients *ClientLookupSet) Get(nick string) *Client {
	return clients.byNick[strings.ToLower(nick)]
}

func (clients *ClientLookupSet) Add(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != nil {
		return ErrNicknameInUse
	}
	clients.byNick[strings.ToLower(client.nick)] = client
	clients.db.Add(client)
	return nil
}

func (clients *ClientLookupSet) Remove(client *Client) error {
	if !client.HasNick() {
		return ErrNickMissing
	}
	if clients.Get(client.nick) != client {
		return ErrNicknameMismatch
	}
	delete(clients.byNick, strings.ToLower(client.nick))
	clients.db.Remove(client)
	return nil
}

func ExpandUserHost(userhost string) (expanded string) {
	expanded = userhost
	// fill in missing wildcards for nicks
	if !strings.Contains(expanded, "!") {
		expanded += "!*"
	}
	if !strings.Contains(expanded, "@") {
		expanded += "@*"
	}
	return
}

func (clients *ClientLookupSet) FindAll(userhost string) (set ClientSet) {
	userhost = ExpandUserHost(userhost)
	set = make(ClientSet)
	rows, err := clients.db.db.Query(
		`SELECT nickname FROM client
           WHERE userhost LIKE ? ESCAPE '\'`,
		QuoteLike(userhost))
	if err != nil {
		return
	}
	for rows.Next() {
		var nickname string
		err := rows.Scan(&nickname)
		if err != nil {
			return
		}
		client := clients.Get(nickname)
		if client != nil {
			set.Add(client)
		}
	}
	return
}

func (clients *ClientLookupSet) Find(userhost string) *Client {
	userhost = ExpandUserHost(userhost)
	row := clients.db.db.QueryRow(
		`SELECT nickname FROM client
           WHERE userhost LIKE ? ESCAPE \
           LIMIT 1`,
		QuoteLike(userhost))
	var nickname string
	err := row.Scan(&nickname)
	if err != nil {
		log.Println("ClientLookupSet.Find: ", err)
		return nil
	}
	return clients.Get(nickname)
}

//
// client db
//

type ClientDB struct {
	db *sql.DB
}

func NewClientDB() *ClientDB {
	db := &ClientDB{
		db: OpenDB(":memory:"),
	}
	_, err := db.db.Exec(`
        CREATE TABLE client (
          nickname TEXT NOT NULL UNIQUE,
          userhost TEXT NOT NULL)`)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.db.Exec(`
        CREATE UNIQUE INDEX nickname_index ON client (nickname)`)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func (db *ClientDB) Add(client *Client) {
	_, err := db.db.Exec(`INSERT INTO client (nickname, userhost) VALUES (?, ?)`,
		client.Nick(), client.UserHost())
	if err != nil {
		log.Println(err)
	}
}

func (db *ClientDB) Remove(client *Client) {
	_, err := db.db.Exec(`DELETE FROM client WHERE nickname = ?`,
		client.Nick())
	if err != nil {
		log.Println(err)
	}
}

func QuoteLike(userhost string) (like string) {
	like = userhost
	// escape escape char
	like = strings.Replace(like, `\`, `\\`, -1)
	// escape meta-many
	like = strings.Replace(like, `%`, `\%`, -1)
	// escape meta-one
	like = strings.Replace(like, `_`, `\_`, -1)
	// swap meta-many
	like = strings.Replace(like, `*`, `%`, -1)
	// swap meta-one
	like = strings.Replace(like, `?`, `_`, -1)
	return
}
