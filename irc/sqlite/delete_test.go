//go:build sqlite && (linux || darwin || freebsd || windows)

package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/ergochat/ergo/irc/history"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/utils"
)

func TestDeleteMsgidIsTargetScoped(t *testing.T) {
	log, err := logger.NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewSQLiteDatabase(log, Config{DatabasePath: t.TempDir() + "/history.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	item := history.Item{}
	item.Message = utils.SplitMessage{Msgid: "shared-msgid", Time: time.Now()}
	for _, target := range []string{"#other", "#unregistered"} {
		if err := db.AddChannelItem(target, item, ""); err != nil {
			t.Fatal(err)
		}
	}

	target, _, err := db.LoadMsgid("#unregistered", "shared-msgid")
	if err != nil {
		t.Fatal(err)
	}
	if target != "#unregistered" {
		t.Fatalf("LoadMsgid returned target %q", target)
	}
	if _, _, err := db.LoadMsgid("#missing", "shared-msgid"); err != history.ErrNotFound {
		t.Fatalf("LoadMsgid for unrelated target: got %v, want ErrNotFound", err)
	}

	if err := db.DeleteMsgid("#unregistered", "shared-msgid"); err != nil {
		t.Fatal(err)
	}

	var remaining int
	if err := db.db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM history
		INNER JOIN sequence ON history.id = sequence.history_id
		WHERE history.msgid = ? AND sequence.target = ?`, "shared-msgid", "#other").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("history copies in unrelated target after delete: %d", remaining)
	}
	if err := db.db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM history
		INNER JOIN sequence ON history.id = sequence.history_id
		WHERE history.msgid = ? AND sequence.target = ?`, "shared-msgid", "#unregistered").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("history copies in requested target after delete: %d", remaining)
	}
}
