// Copyright 2025 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "modernc.org/sqlite"

import (
	"database/sql/driver"
	"fmt"

	"modernc.org/sqlite/vtab"
)

// Driver implements database/sql/driver.Driver.
//
// Registration functions and methods must be called before the first call to Open.
type Driver struct {
	// user defined functions that are added to every new connection on Open
	udfs map[string]*userDefinedFunction
	// collations that are added to every new connection on Open
	collations map[string]*collation
	// connection hooks are called after a connection is opened
	connectionHooks []ConnectionHookFn
	// modules holds registered virtual table modules that should be added to
	// every new connection on Open.
	modules map[string]vtab.Module
}

var d = &Driver{
	udfs:            make(map[string]*userDefinedFunction, 0),
	collations:      make(map[string]*collation, 0),
	connectionHooks: make([]ConnectionHookFn, 0),
	modules:         make(map[string]vtab.Module, 0),
}

func newDriver() *Driver { return d }

// Open returns a new connection to the database. The name is a string in a
// driver-specific format.
//
// Open may return a cached connection (one previously closed), but doing so is
// unnecessary; the sql package maintains a pool of idle connections for
// efficient re-use.
//
// The returned connection is only used by one goroutine at a time.
//
// The name may be a filename, e.g., "/tmp/mydata.sqlite", or a URI, in which
// case it may include a '?' followed by one or more query parameters.
// For example, "file:///tmp/mydata.sqlite?_pragma=foreign_keys(1)&_time_format=sqlite".
// The supported query parameters are:
//
// _pragma: Each value will be run as a "PRAGMA ..." statement (with the PRAGMA
// keyword added for you). May be specified more than once, '&'-separated. For more
// information on supported PRAGMAs see: https://www.sqlite.org/pragma.html
//
// _time_format: The name of a format to use when writing time values to the database.
// The currently supported values are (1) "sqlite" for YYYY-MM-DD HH:MM:SS.SSS[+-]HH:MM
// (format 4 from https://www.sqlite.org/lang_datefunc.html#time_values with sub-second
// precision and timezone specifier) and (2) "datetime" for YYYY-MM-DD HH:MM:SS
// (format 3, matching the output of SQLite's datetime() function).
// If this parameter is not specified, then the default String() format will be used.
//
// _time_integer_format: The name of a integer format to use when writing time values.
// By default, the time is stored as string and the format can be set with _time_format
// parameter. If _time_integer_format is set, the time will be stored as an integer and
// the integer value will depend on the integer format.
// If you decide to set both _time_format and _time_integer_format, the time will be
// converted as integer and the _time_format value will be ignored.
// Currently the supported value are "unix","unix_milli", "unix_micro" and "unix_nano",
// which corresponds to seconds, milliseconds, microseconds or nanoseconds
// since unixepoch (1 January 1970 00:00:00 UTC).
//
// _inttotime: Enable conversion of time column (DATE, DATETIME,TIMESTAMP) from integer
// to time if the field contain integer (int64).
//
// _texttotime: Enable ColumnTypeScanType to report time.Time instead of string
// for TEXT columns declared as DATE, DATETIME, TIME, or TIMESTAMP. It also
// best-effort upgrades date-shaped TEXT values from columns SQLite reports with
// an empty declared type (aggregates and expressions such as MAX(d) or
// upper(d), subqueries, and typeless real columns) to time.Time, since the
// declared-type test cannot catch those (#248). When that upgrade fires, a Scan
// into interface{} yields a time.Time where it previously yielded a string, and
// a Scan into *string receives the value reformatted to RFC3339Nano rather than
// the raw stored text. A value that does not parse as a time is delivered
// unchanged as the original string.
//
// _timezone: A timezone to use for all time reads and writes, such as "UTC".
// The value is parsed by time.LoadLocation.
// Writes will convert to the timezone before formatting as a string;
// it does not impact _inttotime integer values, as they always use UTC.
// Reads will interpret timezone-less strings as being in this timezone.
// Values that are in a known timezone, such as a string with a timezone specifier
// or an integer with _inttotime (specified to be in UTC), will be converted to this timezone.
//
// _txlock: The locking behavior to use when beginning a transaction. May be
// "deferred" (the default), "immediate", or "exclusive" (case insensitive). See:
// https://www.sqlite.org/lang_transaction.html#deferred_immediate_and_exclusive_transactions
//
// _dqs: Opt-in toggle for SQLite's double-quoted string literal
// compatibility quirk on the connection. Accepts the values strconv.ParseBool
// understands ("0"/"1", "false"/"true", "f"/"t", case-insensitive). When
// absent or set to a true value, SQLite's built-in behavior is unchanged:
// a double-quoted identifier that fails to resolve is silently
// re-interpreted as a string literal. When set to a false value,
// SQLITE_DBCONFIG_DQS_DDL and SQLITE_DBCONFIG_DQS_DML are both turned
// off via sqlite3_db_config so that mistakes hidden by the legacy
// fallback surface as a parse error instead. See:
// https://www.sqlite.org/quirks.html#dblquote and
// https://gitlab.com/cznic/sqlite/-/issues/61
//
// _error_rc: Opt-in error-string reporting mode for synthesised errors.
// Accepts the values strconv.ParseBool understands ("0"/"1",
// "false"/"true", "f"/"t", case-insensitive). When absent or set to a
// false value, the legacy "errstr: errmsg (rc)" form is preserved
// byte-for-byte: the canonical sqlite3_errstr(rc) and the connection's
// sqlite3_errmsg(db) are concatenated even when the latter belongs to a
// different operation, which can read as misleading on open-time
// failures such as SQLITE_CANTOPEN reporting "out of memory". When set
// to a true value, the appended errmsg is suppressed if
// sqlite3_extended_errcode(db) is inconsistent with the operation rc
// (full match first, primary code as fallback); in that case the
// canonical errstr(rc) is used alone. The Code() returned by the
// driver's *Error is unchanged in either mode. The parameter is parsed
// before sqlite3_open_v2 so open-time errors are covered. See
// https://gitlab.com/cznic/sqlite/-/issues/230.
func (d *Driver) Open(name string) (conn driver.Conn, err error) {
	if dmesgs {
		defer func() {
			dmesg("name %q: (driver.Conn %p, err %v)", name, conn, err)
		}()
	}
	c, err := newConn(name)
	if err != nil {
		return nil, err
	}

	for _, udf := range d.udfs {
		if err = c.createFunctionInternal(udf); err != nil {
			c.Close()
			return nil, err
		}
	}
	for _, coll := range d.collations {
		if err = c.createCollationInternal(coll); err != nil {
			c.Close()
			return nil, err
		}
	}
	for _, connHookFn := range d.connectionHooks {
		if err = connHookFn(c, name); err != nil {
			c.Close()
			return nil, fmt.Errorf("connection hook: %w", err)
		}
	}
	// Register any vtab modules with this connection.
	// Note: vtab module registration applies to new connections only. If a
	// module is registered after a connection has been opened, that existing
	// connection will not see the module; open a new connection to use it.
	if err := c.registerModules(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// RegisterConnectionHook registers a function to be called after each connection
// is opened. This is called after all the connection has been set up.
func (d *Driver) RegisterConnectionHook(fn ConnectionHookFn) {
	d.connectionHooks = append(d.connectionHooks, fn)
}
