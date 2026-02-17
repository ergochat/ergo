package sqlite

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitemigration"
	"zombiezen.com/go/sqlite/sqlitex"
)

//go:embed migrations/*.sql
var migrationSrcs embed.FS

func migrate(conn *sqlite.Conn, srcs fs.FS) (start, end int, err error) {
	err = sqlitex.ExecuteTransient(conn, "PRAGMA user_version;", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			start = int(stmt.ColumnInt32(0))
			return nil
		},
	})
	if err != nil {
		return
	}
	schema := sqlitemigration.Schema{}
	for i := 1; ; i++ {
		var fn []string
		var migration []byte
		fn, err = fs.Glob(srcs, fmt.Sprintf("*/%03d_*.sql", i))
		if err != nil || len(fn) == 0 {
			break
		}
		migration, err = fs.ReadFile(srcs, fn[0])
		if err != nil {
			return
		}
		schema.Migrations = append(schema.Migrations, strings.TrimSpace(string(migration)))
	}
	err = sqlitemigration.Migrate(context.Background(), conn, schema)
	if err != nil {
		return
	}

	err = sqlitex.ExecuteTransient(conn, "PRAGMA user_version;", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			end = int(stmt.ColumnInt32(0))
			return nil
		},
	})
	return
}
