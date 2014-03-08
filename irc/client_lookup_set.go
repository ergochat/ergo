package irc

import (
	"database/sql"
	"errors"
	"log"
	"regexp"
	"strings"
)

var (
	ErrNickMissing      = errors.New("nick missing")
	ErrNicknameInUse    = errors.New("nickname in use")
	ErrNicknameMismatch = errors.New("nickname mismatch")
	wildMaskExpr        = regexp.MustCompile(`\*|\?`)
	likeQuoter          = strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
		`*`, `%`,
		`?`, `_`)
)

func HasWildcards(mask string) bool {
	return wildMaskExpr.MatchString(mask)
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

func QuoteLike(userhost string) string {
	return likeQuoter.Replace(userhost)
}

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

func (clients *ClientLookupSet) FindAll(userhost string) (set ClientSet) {
	userhost = ExpandUserHost(userhost)
	set = make(ClientSet)
	rows, err := clients.db.db.Query(
		`SELECT nickname FROM client WHERE userhost LIKE ? ESCAPE '\'`,
		QuoteLike(userhost))
	if err != nil {
		if DEBUG_SERVER {
			log.Println("ClientLookupSet.FindAll.Query:", err)
		}
		return
	}
	for rows.Next() {
		var nickname string
		err := rows.Scan(&nickname)
		if err != nil {
			if DEBUG_SERVER {
				log.Println("ClientLookupSet.FindAll.Scan:", err)
			}
			return
		}
		client := clients.Get(nickname)
		if client == nil {
			if DEBUG_SERVER {
				log.Println("ClientLookupSet.FindAll: missing client:", nickname)
			}
			continue
		}
		set.Add(client)
	}
	return
}

func (clients *ClientLookupSet) Find(userhost string) *Client {
	userhost = ExpandUserHost(userhost)
	row := clients.db.db.QueryRow(
		`SELECT nickname FROM client WHERE userhost LIKE ? ESCAPE '\' LIMIT 1`,
		QuoteLike(userhost))
	var nickname string
	err := row.Scan(&nickname)
	if err != nil {
		if DEBUG_SERVER {
			log.Println("ClientLookupSet.Find:", err)
		}
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
	stmts := []string{
		`CREATE TABLE client (
          nickname TEXT NOT NULL COLLATE NOCASE UNIQUE,
          userhost TEXT NOT NULL COLLATE NOCASE,
          UNIQUE (nickname, userhost) ON CONFLICT REPLACE)`,
		`CREATE UNIQUE INDEX idx_nick ON client (nickname COLLATE NOCASE)`,
		`CREATE UNIQUE INDEX idx_uh ON client (userhost COLLATE NOCASE)`,
	}
	for _, stmt := range stmts {
		_, err := db.db.Exec(stmt)
		if err != nil {
			log.Fatal("NewClientDB: ", stmt, err)
		}
	}
	return db
}

func (db *ClientDB) Add(client *Client) {
	_, err := db.db.Exec(`INSERT INTO client (nickname, userhost) VALUES (?, ?)`,
		client.Nick(), client.UserHost())
	if err != nil {
		if DEBUG_SERVER {
			log.Println("ClientDB.Add:", err)
		}
	}
}

func (db *ClientDB) Remove(client *Client) {
	_, err := db.db.Exec(`DELETE FROM client WHERE nickname = ?`,
		client.Nick())
	if err != nil {
		if DEBUG_SERVER {
			log.Println("ClientDB.Remove:", err)
		}
	}
}

//
// usermask to regexp
//

type UserMaskSet struct {
	masks  map[string]bool
	regexp *regexp.Regexp
}

func NewUserMaskSet() *UserMaskSet {
	return &UserMaskSet{
		masks: make(map[string]bool),
	}
}

func (set *UserMaskSet) Add(mask string) bool {
	if set.masks[mask] {
		return false
	}
	set.masks[mask] = true
	set.setRegexp()
	return true
}

func (set *UserMaskSet) Remove(mask string) bool {
	if !set.masks[mask] {
		return false
	}
	delete(set.masks, mask)
	set.setRegexp()
	return true
}

func (set *UserMaskSet) Match(userhost string) bool {
	if set.regexp == nil {
		return false
	}
	return set.regexp.MatchString(userhost)
}

func (set *UserMaskSet) String() string {
	masks := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		masks[index] = mask
		index += 1
	}
	return strings.Join(masks, " ")
}

func (set *UserMaskSet) setRegexp() {
	if len(set.masks) == 0 {
		set.regexp = nil
		return
	}

	maskExprs := make([]string, len(set.masks))
	index := 0
	for mask := range set.masks {
		manyParts := strings.Split(mask, "*")
		manyExprs := make([]string, len(manyParts))
		for mindex, manyPart := range manyParts {
			oneParts := strings.Split(manyPart, "?")
			oneExprs := make([]string, len(oneParts))
			for oindex, onePart := range oneParts {
				oneExprs[oindex] = regexp.QuoteMeta(onePart)
			}
			manyExprs[mindex] = strings.Join(oneExprs, ".")
		}
		maskExprs[index] = strings.Join(manyExprs, ".*")
	}
	expr := "^" + strings.Join(maskExprs, "|") + "$"
	set.regexp, _ = regexp.Compile(expr)
}
