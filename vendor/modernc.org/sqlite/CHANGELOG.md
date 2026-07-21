# Changelog

 - 2026-07-15 v1.54.0:
     - Upgrade to [SQLite 3.53.3](https://sqlite.org/releaselog/3_53_3.html). This also bumps the pinned `modernc.org/libc` to v1.74.1; as always, downstream modules must pin the exact same `modernc.org/libc` version this module's `go.mod` pins (see [GitLab issue #177](https://gitlab.com/cznic/sqlite/-/issues/177)).
     - Under the opt-in `_texttotime` DSN parameter, best-effort parse date-shaped TEXT values from columns SQLite reports with an empty declared type — aggregates and expressions over a date column (`MAX(d)`, `COALESCE(d, ...)`, `upper(d)`, `d || ''`), subqueries, and typeless real columns (`CREATE TABLE t(x)`) — into `time.Time`, instead of delivering them as a raw string that `Scan` cannot store into a `*time.Time`. The existing declared `DATE`/`DATETIME`/`TIME`/`TIMESTAMP` path is unchanged; this only adds the empty-decltype case. The conversion is strictly best-effort: a value that does not parse as a time falls through to the original string, so no `Scan` that worked before can newly fail. `ColumnTypeScanType` continues to report `string` for empty-decltype columns, since the declared type cannot prove the column is temporal. Without `_texttotime` the behavior is byte-for-byte unchanged. Resolves [GitLab issue #248](https://gitlab.com/cznic/sqlite/-/issues/248).
     - See [GitLab merge request #133](https://gitlab.com/cznic/sqlite/-/merge_requests/133), thanks Ian Chechin!

 - 2026-06-21 v1.53.0:
     - Add **experimental** `netbsd/amd64` support, resolving the long-standing build break in [GitLab issue #246](https://gitlab.com/cznic/sqlite/-/issues/246). This target is intentionally **not yet listed among the supported platforms** in the package documentation: the port had been broken for years and is only now revived, and there is as yet no real-world experience running it under production workloads. Green CI is not the same as battle-tested — so while the full test suite (including the `pcache` and `vec` packages and the `-race` concurrency test) passes on NetBSD 10.1 / Go 1.26.3, and the entire upstream toolchain (`libc`, `cc`, `ccgo`, `libz`, `libtcl8.6`, `libsqlite3`, `libsqlite_vec`) is green on the NetBSD CI builder, the target is offered for evaluation only. If you run NetBSD, please exercise it with your own workloads and report back via #246; the intent is to promote it to a fully supported platform after a period of broader real-world testing (on the order of a month) elapses without surprises.
     - Implementation notes: the previously shipped `lib/sqlite_netbsd_amd64.go` was a stale old-generator transpile that no longer compiled (the `mu.enter`/`mu.leave` break in #246); it is replaced by a fresh new-generator transpile consistent with every other platform, and `modernc.org/sqlite/vec` (sqlite-vec) is vendored and auto-registers on netbsd. Correct operation requires the matching pinned `modernc.org/libc`, which carries two NetBSD-specific fixes found during this work: the `mmap(2)` `PAD`-argument ABI (without it, concurrent WAL access faults with SIGBUS in the WAL-index shared memory) and a working `abort(3)` (the prior stub left SQLite's crash-recovery `writecrash` test unable to terminate by signal). As usual, downstream modules must pin the exact `modernc.org/libc` version this module's `go.mod` pins.
     - See [GitLab merge request #82](https://gitlab.com/cznic/sqlite/-/merge_requests/82), thanks Leonardo Taccari (@iamleot) and Thomas Klausner (@_wiz_)!
     - Add **experimental** `freebsd/386` and `freebsd/arm` support. As with the `netbsd/amd64` target above, these two 32-bit FreeBSD ports are intentionally **not yet listed among the supported platforms** in the package documentation: `freebsd/386` previously shipped a stale, effectively untested SQLite 3.41 transpile, and `freebsd/arm` is entirely new, so neither has real-world production mileage yet. Both are now freshly transpiled at SQLite 3.53.2 consistent with every other platform, build cleanly, and pass the full test suite (core, WAL/concurrency, and the `vec` package) on the FreeBSD CI builders; they are offered for evaluation only. If you run 32-bit FreeBSD, please exercise these targets with your own workloads and report back — the intent is to promote `freebsd/386`, `freebsd/arm`, and `netbsd/amd64` to fully supported platforms in a future release cycle, once a period of broader real-world testing elapses without surprises.
     - Implementation notes: correct operation on `freebsd/arm` requires the matching pinned `modernc.org/libc` (v1.73.4), which fixes the per-arch `mmap(2)` `off_t` encoding for 32-bit FreeBSD; without it the WAL shared-memory mapping faults with SIGBUS under concurrent access, the same class of bug found on the netbsd port. As usual, downstream modules must pin the exact `modernc.org/libc` version this module's `go.mod` pins.
     - See [GitLab merge request #119](https://gitlab.com/cznic/sqlite/-/merge_requests/119), thanks Olivier Cochard-Labbé (@ocochard)!
     - Add a Go-facing wrapper for `SQLITE_CONFIG_PCACHE2`. `PageCache` is the factory and `Cache` the per-database instance, both idiomatic Go interfaces; `Page` exposes the raw `Buf` and `Extra` pointers that SQLite reads through the C pcache contract. `RegisterPageCache` and `MustRegisterPageCache` install the module process-globally before the first `sql.Open`; subsequent Open calls are gated through a one-shot `Xsqlite3_config(SQLITE_CONFIG_PCACHE2)` so a too-late Register returns `ErrPageCacheTooLate` rather than silently falling through to the built-in pcache1. The binding owns the `sqlite3_pcache_page` stub and re-consults the implementation on every Fetch, reusing the stub only when the returned `Page` value is unchanged, which keeps a bounded/evicting purgeable cache safe by construction.
     - See [GitLab merge request #126](https://gitlab.com/cznic/sqlite/-/merge_requests/126), thanks Ian Chechin!
     - Add `modernc.org/sqlite/pcache`, the reference page-cache implementation that accompanies the #126 `SQLITE_CONFIG_PCACHE2` wrapper. `pcache.New` returns a `*Pool` satisfying the `PageCache` interface; register it once with `sqlite.MustRegisterPageCache(pcache.New())` and every connection opened afterwards draws its pages from it. Each `Pool.Create` mints a fresh per-database `Cache`: a bounded, LRU-evicting page store that honours the `PRAGMA cache_size` soft cap and releases the least-recently-unpinned page when it must make room. Page memory — the `Buf` and `Extra` buffers SQLite reads through — is allocated with `libc.Xmalloc`/`libc.Xcalloc` and therefore lives off the Go heap, which keeps SQLite's interior pointer arithmetic on the page extras from tripping the race detector's checkptr enforcement. `Pool.Stats` reports aggregate lifetime counters (hits, misses, allocs, evictions, rekeys, truncates, caches) across every cache a Pool has created, so hit/miss/eviction behaviour is observable without instrumenting individual caches. Cross-connection page sharing is out of scope for now; each `Create` returns an independent per-database cache.
     - Validated end-to-end against the #126 stress workload (`cache_size=16`, 4000 BLOB rows with DELETE and `incremental_vacuum`, `integrity_check` clean under `-race`) and benchmarked for the memory-utilization goal tracked in [GitLab issue #204](https://gitlab.com/cznic/sqlite/-/issues/204).
     - See [GitLab merge request #127](https://gitlab.com/cznic/sqlite/-/merge_requests/127), thanks Ian Chechin!
     - Tighten the `modernc.org/sqlite/pcache` reference implementation per cznic's !127 review follow-ups. Adds `Stats.EasyRefusals`, a per-Pool counter for the cases where `FetchCreateEasy` returns nil at cap; SQLite reacts to a refusal by spilling dirty pages and retrying with `FetchCreateForce`, so the new field is a direct proxy for the I/O pressure the strict Easy contract imposes vs pcache1's recycle-without-spill behavior. `BenchmarkPoolEvictionChurn` was reworked to drive a rotating-residue DELETE (`k % 3 = i % 3`) and re-insert a matching batch each cycle so the spill pressure recurs and `easy-refusals/op` scales with `b.N` instead of capping at the seed's one-time first-cycle cost; both existing benchmarks now report `easy-refusals/op` alongside the page-allocs/evictions metrics. `Stats.Evictions` documentation was tightened to match the actual behavior (counts LRU eviction, `Unpin(discard=true)`, `Shrink` releases, and `Unpin(discard=false)` trimming back to target after a `FetchCreateForce` overcommit; bulk frees from `Truncate`, `Rekey` collisions, and `Destroy` are not counted). The `TestPoolRoundTripIntegrity` comment claiming the workload exercises `xRekey` ~15 times has been corrected; the SQL surface does not reliably emit xRekey here, and that codepath is covered by the unit tests instead.
     - See [GitLab merge request #130](https://gitlab.com/cznic/sqlite/-/merge_requests/130), thanks Ian Chechin!
     - Make `modernc.org/sqlite/pcache` `-race`-clean under SQLite's `cache=shared` mode. The pool already runs correctly under shared-cache because every callback into a given `Cache` is serialised internally by SQLite's `sqlite3BtreeEnter` on the `BtShared` mutex; verified empirically with a lock-free in-flight probe (max-in-flight = 1 on the canonical two-connection workload, 4 on a positive control with goroutines hitting the cache directly). However the Go race detector does not recognise SQLite's libc mutex as a happens-before edge and reports false-positive races on `Fetch` vs `Unpin` reads/writes of the per-cache state, which surfaces as `DATA RACE` failures for any user who registers the pool and runs their suite under `-race`. A `sync.Mutex` on the `cache` type is now taken on every public method (`SetSize`, `PageCount`, `Fetch`, `Unpin`, `Rekey`, `Truncate`, `Destroy`, `Shrink`), always. On the common non-shared-cache path the lock is uncontended (one atomic CAS per Lock/Unlock pair, negligible next to the SQLite work it bookends); on the shared-cache path it just rubber-stamps the order SQLite's `BtShared` mutex already established. A new `e2e_test.go` `TestSharedCacheTwoConns_Integrity` drives two `sql.Conn` against the same `cache=shared` URI with concurrent writers and asserts `PRAGMA integrity_check = ok` under `-race`; passes cleanly with the lock, would surface the false-positive without it. Design notes live in `pcache/sharing.go`.
     - See [GitLab merge request #131](https://gitlab.com/cznic/sqlite/-/merge_requests/131), thanks Ian Chechin!
     - Add a Go wrapper for `sqlite3_db_status`, the per-connection runtime counters (cache hit/miss/write/spill rates, schema and prepared-statement memory, lookaside usage, deferred foreign keys). `DBStatus` is an interface implemented by the driver connection and reached through the `database/sql` escape hatch `(*sql.Conn).Raw()`, mirroring the existing `FileControl` surface; `DBStatusOp` is a distinct typed enum of the `SQLITE_DBSTATUS_*` verbs so a counter from a different op family will not compile in its place. `Status(op, reset)` returns the `(current, high)` pair and optionally resets the counter. This also lets `modernc.org/sqlite/pcache` measure real I/O instead of the `EasyRefusals` proxy: the new `BenchmarkPoolSpillIO` reads the pager-level `SQLITE_DBSTATUS_CACHE_SPILL`/`_CACHE_WRITE` counters, which the pager maintains identically for pcache1 and the pool, making the pcache1-vs-pool comparison cznic raised on the !127 review a genuine apples-to-apples measurement. On the rotating-residue eviction-churn workload at `cache_size=16` the pool spills ~3.5x more than pcache1 (cache-spill/op 31.96 vs 8.96) for ~3% more page writes (cache-write/op 450 vs 436) at identical hit/miss, quantifying the I/O cost of the strict Easy contract that `EasyRefusals` only proxied.
     - See [GitLab merge request #132](https://gitlab.com/cznic/sqlite/-/merge_requests/132), thanks Ian Chechin!
     - Add an opt-in `_dqs` DSN query parameter that disables SQLite's double-quoted string literal compatibility quirk on a per-connection basis. When `_dqs=0` (or any `strconv.ParseBool` false value) is supplied, the driver calls `sqlite3_db_config` with `SQLITE_DBCONFIG_DQS_DDL` and `SQLITE_DBCONFIG_DQS_DML` set to off before any statement is prepared, so a double-quoted identifier that fails to resolve raises a parse error instead of silently falling back to a string literal. Absence of the parameter, or `_dqs=1`, leaves SQLite's default behavior unchanged; existing DSNs continue to work byte-for-byte. Resolves [GitLab issue #61](https://gitlab.com/cznic/sqlite/-/issues/61).
     - See [GitLab merge request #128](https://gitlab.com/cznic/sqlite/-/merge_requests/128), thanks Ian Chechin!
     - Add an opt-in `_error_rc` DSN query parameter for clearer error reporting on open-time failures. When `_error_rc=1` (or any `strconv.ParseBool` true value) is supplied, error strings synthesised from a `(rc, db)` pair only append `sqlite3_errmsg(db)` when `sqlite3_extended_errcode(db)` is consistent with the operation rc (full match first, primary code `&0xff` as fallback). On mismatch the canonical `sqlite3_errstr(rc)` is used alone, so an open-time `SQLITE_CANTOPEN` no longer carries the temporary handle's stale "out of memory" errmsg. Absence of the parameter, or `_error_rc=0`, preserves the legacy "errstr: errmsg" form byte-for-byte; existing callers that parse error strings are unaffected. The driver's `*Error.Code()` returns the same SQLite result code in both modes. Parsed before `sqlite3_open_v2` so open-time errors are covered. Resolves [GitLab issue #230](https://gitlab.com/cznic/sqlite/-/issues/230).
     - See [GitLab merge request #129](https://gitlab.com/cznic/sqlite/-/merge_requests/129), thanks Ian Chechin!

 - 2026-06-06 v1.52.0:
     -  Upgrade to [SQLite 3.53.2](https://sqlite.org/releaselog/3_53_2.html).
     - Add `Backup.Remaining` and `Backup.PageCount`, thin wrappers around the existing `sqlite3_backup_remaining` and `sqlite3_backup_pagecount` C symbols. Together they expose the per-`Step` progress counters that the underlying backup object already maintains, enabling progress reporting during online backups without dropping to `modernc.org/sqlite/lib` directly.
     - See [GitLab merge request #122](https://gitlab.com/cznic/sqlite/-/merge_requests/122), thanks Ian Chechin!
     - Drop the redundant second copy in `(*conn).columnText`, the path that backs every `Rows.Scan` into a Go `string` for a TEXT column. The value's bytes are still copied once out of SQLite-owned memory into a fresh Go buffer; that buffer is then reinterpreted as the result string with `unsafe.String` rather than copied a second time by the implicit `string([]byte)` conversion. This removes one allocation per TEXT value per row and roughly halves the bytes allocated on that path; on the new `BenchmarkColumnTextScan` cases it is ~13–20% faster for payloads of 256 B and larger, with no measurable change for very short strings. Purely internal: no API or behavioral change, and the returned string never aliases SQLite's buffer.
     - See [GitLab merge request #123](https://gitlab.com/cznic/sqlite/-/merge_requests/123), thanks Ian Chechin!
     - Cache each result column's declared type once per result set in `newRows` instead of recomputing it on every row. The TEXT branch of `Rows.Next` calls `ColumnTypeDatabaseTypeName` for every TEXT column on every row (independent of any DSN flag), which previously did a `libc.GoString` + `strings.ToUpper` each time; that lookup is now a single index into a cached, pre-uppercased `[]string`, and `ColumnTypeScanType` reads the same cache and drops its per-call `strings.ToLower`. The declared type is fixed for the lifetime of a prepared statement, so the C round-trip is paid once per column rather than once per column per row, removing exactly 1 alloc + 8 B per TEXT column per row from the `Next` hot path. The new `BenchmarkTextToTimeScan` cases show ~7% faster on a 1000-row DATETIME SELECT under `_texttotime=1`. Purely internal: `ColumnTypeDatabaseTypeName` and `ColumnTypeScanType` return identical values, no API or behavioral change.
     - See [GitLab merge request #124](https://gitlab.com/cznic/sqlite/-/merge_requests/124), thanks Ian Chechin!
     - Cache, per result column, the `parseTimeFormats` index that first parsed a TEXT-stored DATE/DATETIME/TIMESTAMP value, and try that format first on later rows instead of re-walking the list from the top. `(*conn).parseTime` previously ran `time.Parse` down the format list on every such row; for the canonical SQLite TEXT datetime format every row paid two failed `time.Parse` attempts — each allocating a `*time.ParseError` — before the match. On a 1000-row DATETIME TEXT SELECT this cuts ~50% of allocs/op and ~57% of B/op and is ~37% faster. The fall-through chain is preserved exactly: the seven formats are mutually exclusive, so the cached hint can never select a different match than the in-order scan, and the parsed `driver.Value` is identical to before. Purely internal: no API or behavioral change.
     - See [GitLab merge request #125](https://gitlab.com/cznic/sqlite/-/merge_requests/125), thanks Ian Chechin!

 - 2026-05-28 v1.51.0:
     - Pool the `[]driver.Value` slice passed to scalar/aggregate UDF callbacks and to vtab `Filter`/`Insert`/`Update` callbacks, eliminating the dominant per-row allocation on UDF-heavy queries. Benchmarks on a 1000-row, 3-arg noop scalar UDF show ~40% fewer bytes/op and ~15% fewer allocs/op.
     - Document the matching "arguments are not valid past return" contract on `vtab.Cursor.Filter` and `vtab.Updater.Insert`/`Update`, consistent with the existing rule for `FunctionImpl.Scalar` / `AggregateFunction.Step` / `WindowInverse`.
     - Resolves [GitLab issue #226](https://gitlab.com/cznic/sqlite/-/issues/226). See [GitLab merge request #114](https://gitlab.com/cznic/sqlite/-/merge_requests/114), thanks Ian Chechin!
     - Add `FileControl.FileControlDataVersion`, a wrapper around `SQLITE_FCNTL_DATA_VERSION` for observing pager-cache data-version changes, including those made on the same connection. Useful as a primitive for application-level cache invalidation.
     - Exposed via the idiomatic `database/sql` escape hatch `(*sql.Conn).Raw()`, consistent with the existing `FileControlPersistWAL`.                                                                    
     - See [GitLab merge request #115](https://gitlab.com/cznic/sqlite/-/merge_requests/115), thanks Ian Chechin!
     - Fix a regression where in-memory connections (`:memory:`, `file::memory:`, shared-cache memory URIs) were discarded by `database/sql` after a context-cancelled query, taking the entire in-memory store with them. The fix for #198 had added an `sqlite3_is_interrupted` check to the connection validator that mistakenly applied to in-memory connections too, re-introducing the bug originally fixed by !74. File-backed connections keep the existing behaviour and are still discarded after an interrupt.
     - Resolves [GitLab issue #196](https://gitlab.com/cznic/sqlite/-/issues/196). See [GitLab merge request #116](https://gitlab.com/cznic/sqlite/-/merge_requests/116), thanks Ian Chechin!
     - Add an opt-in `FunctionImpl.VolatileArgs` flag that hands TEXT and BLOB arguments to scalar and aggregate UDF callbacks as zero-copy views (`unsafe.String`/`unsafe.Slice`) over SQLite's own value buffers, eliminating the per-argument `libc.GoString`/`make([]byte)` copy that the #226 slice-pooling left as the remaining per-row allocation. On the same 1000-row, 3-arg (INTEGER/TEXT/BLOB) noop scalar UDF this removes a further ~35% of allocs/op and ~11% of bytes/op on top of #226.
     - The views are valid only for the duration of the callback and must not be retained past return or across rows; a callback that needs to keep a value must copy it. With `VolatileArgs` unset (the default) arguments keep the existing copied, caller-owned semantics, so the flag is fully backward compatible; it has no effect on integer, float, time, or NULL arguments.
     - See [GitLab merge request #120](https://gitlab.com/cznic/sqlite/-/merge_requests/120), thanks Ian Chechin!
     - Extend the opt-in `VolatileArgs` zero-copy TEXT/BLOB argument access from #120 to the virtual-table `Cursor.Filter` (`xFilter`) and `Updater.Insert`/`Update` (`xUpdate`) callbacks. A `vtab.Module` opts in by implementing the new optional `vtab.VolatileArgsOpter` interface (`VolatileArgs() bool`); the flag is read once at module registration and shared by every table created from it. On a vtab call carrying one TEXT and one BLOB argument this removes 2 allocs/op (one `libc.GoString`, one `make([]byte)`) on each of the Filter and Update paths.
     - The same safety contract as #120 applies: the views are valid only for the duration of the callback and must not be retained past return or across rows; a callback that needs to keep a value must copy it. Modules that do not implement `VolatileArgsOpter` (the default for all existing modules) are byte-for-byte unchanged, and the flag has no effect on integer, float, time, or NULL arguments.
     - See [GitLab merge request #121](https://gitlab.com/cznic/sqlite/-/merge_requests/121), thanks Ian Chechin!

 - 2026-05-10 v1.50.1:
     - Upgrade to [SQLite 3.53.1](https://sqlite.org/releaselog/3_53_1.html).

 - 2026-04-24 v1.50.0:
     - Upgrade to sqlite-vec [v0.1.9](https://github.com/asg017/sqlite-vec/releases/tag/v0.1.9).
     - Introduce `ColumnInfo`, enabling dynamic query builders and ORMs to retrieve underlying SQLite C-API metadata (`OriginName`, `TableName`, `DatabaseName`, and `DeclType`).
     - This feature is exposed via the idiomatic `database/sql` escape hatch `(*sql.Conn).Raw()`, avoiding custom statement handles and keeping the standard library workflow intact.
     - See [GitLab merge request #113](https://gitlab.com/cznic/sqlite/-/merge_requests/113), thanks Josh Bleecher Snyder!
 
 - 2026-04-17 v1.49.0: Upgrade to [SQLite 3.53.0](https://sqlite.org/releaselog/3_53_0.html).
     - Added `-DSQLITE_ENABLE_DBPAGE_VTAB` to the transpilation. See ["The SQLITE_DBPAGE Virtual Table"](https://www.sqlite.org/dbpage.html) for details.

 - 2026-04-06 v1.48.2:
     - Fix ABI mapping mismatch in the pre-update hook trampoline that caused silent truncation of large 64-bit RowIDs.
     - Ensure the Go trampoline signature correctly aligns with the public `sqlite3_preupdate_hook` C API, preventing data corruption for high-entropy keys (e.g., Snowflake IDs).
     - See [GitLab merge request #98](https://gitlab.com/cznic/sqlite/-/merge_requests/98), thanks Josh Bleecher Snyder!
     - Fix the memory allocator used in `(*conn).Deserialize`.
     - Replace `tls.Alloc` with `sqlite3_malloc64` to prevent internal allocator corruption. This ensures the buffer is safely owned by SQLite, which may resize or free it due to the `SQLITE_DESERIALIZE_RESIZEABLE` and `SQLITE_DESERIALIZE_FREEONCLOSE` flags.
     - Prevent a memory leak by properly freeing the allocated buffer if fetching the main database name fails before handing ownership to SQLite.
     - See [GitLab merge request #100](https://gitlab.com/cznic/sqlite/-/merge_requests/100), thanks Josh Bleecher Snyder!
     - Fix `(*conn).Deserialize` to explicitly reject `nil` or empty byte slices.
     - Prevent silent database disconnection and connection pool corruption caused by SQLite's default behavior when `sqlite3_deserialize` receives a 0-length buffer.
     - See [GitLab merge request #101](https://gitlab.com/cznic/sqlite/-/merge_requests/101), thanks Josh Bleecher Snyder!
     - Fix `commitHookTrampoline` and `rollbackHookTrampoline` signatures by removing the unused `pCsr` parameter.
     - Aligns internal hook callbacks accurately with the underlying SQLite C API, cleaning up the code to prevent potential future confusion or bugs.
     - See [GitLab merge request #102](https://gitlab.com/cznic/sqlite/-/merge_requests/102), thanks Josh Bleecher Snyder!
     - Fix `checkptr` instrumentation failures during `go test -race` when registering and using virtual tables (`vtab`).
     - Allocate `sqlite3_module` instances using the C allocator (`libc.Xcalloc`) instead of the Go heap. This ensures transpiled C code can safely perform pointer operations on the struct without tripping Go's pointer checks.
     - See [GitLab merge request #103](https://gitlab.com/cznic/sqlite/-/merge_requests/103), thanks Josh Bleecher Snyder!
     - Fix data race on `mutex.id` in the `mutexTry` non-recursive path.
     - Ensure consistent atomic writes (`atomic.StoreInt32`) to prevent data races with atomic loads in `mutexHeld` and `mutexNotheld` during concurrent execution.
     - See [GitLab merge request #104](https://gitlab.com/cznic/sqlite/-/merge_requests/104), thanks Josh Bleecher Snyder!
     - Fix resource leak in `(*Backup).Commit` where the destination connection was not closed on error.
     - Ensure `dstConn` is properly closed when `sqlite3_backup_finish` fails, preventing file descriptor, TLS, and memory leaks.
     - See [GitLab merge request #105](https://gitlab.com/cznic/sqlite/-/merge_requests/105), thanks Josh Bleecher Snyder!
     - Fix `Exec` to fully drain rows when encountering `SQLITE_ROW`, preventing silent data loss in DML statements.
     - Previously, `Exec` aborted after the first row, meaning `INSERT`, `UPDATE`, or `DELETE` statements with a `RETURNING` clause would fail to process subsequent rows. The execution path now correctly loops until `SQLITE_DONE` and properly respects context cancellations during the drain loop, fully aligning with native C `sqlite3_exec` semantics.
     - See [GitLab merge request #106](https://gitlab.com/cznic/sqlite/-/merge_requests/106), thanks Josh Bleecher Snyder!
     - Fix "Shadowed err value (stmt.go)".
     - See [GitLab issue #249](https://gitlab.com/cznic/sqlite/-/work_items/249), thanks Emrecan BATI!
     - Fix silent omission of virtual table savepoint callbacks by correctly setting the sqlite3_module version.
     - See [GitLab merge request #107](https://gitlab.com/cznic/sqlite/-/merge_requests/107), thanks Josh Bleecher Snyder!
     - Fix `vfsRead` to properly handle partial and fragmented reads from `io.Reader`.
     - Replace `f.Read` with `io.ReadFull` to ensure the buffer is fully populated, preventing premature `SQLITE_IOERR_SHORT_READ` errors on valid mid-stream partial reads. Unread tail bytes at EOF are now efficiently zero-filled using the built-in `clear` function.
     - See [GitLab merge request #108](https://gitlab.com/cznic/sqlite/-/merge_requests/108), thanks Josh Bleecher Snyder!
     - Refactor internal error formatting to safely handle uninitialized or closed database pointers.
     - Prevent a misleading "out of memory" error message when an operation fails and the underlying SQLite database handle is `NULL` (`db == 0`).
     - See [GitLab merge request #109](https://gitlab.com/cznic/sqlite/-/merge_requests/109), thanks Josh Bleecher Snyder!
     - Fix error handling in database backup and restore initialization (`sqlite3_backup_init`).
     - Ensure error codes and messages are accurately read from the destination database handle rather than hardcoding the source or remote handle. This prevents swallowed errors or mismatched "not an error" messages when a backup or restore operation fails to start.
     - See [GitLab merge request #111](https://gitlab.com/cznic/sqlite/-/merge_requests/111), thanks Josh Bleecher Snyder!
     - Fix database handle and C-heap memory leaks when `sqlite3_open_v2` fails.
     - Ensure `sqlite3_close_v2` is called on the partially allocated database handle during a failed open, and explicitly close `libc.TLS` in `newConn` to prevent resource leakage.
     - Prevent misleading "out of memory" error messages on failed connections by correctly extracting the exact error string from the allocated handle before it is closed.
     - See [GitLab merge request #112](https://gitlab.com/cznic/sqlite/-/merge_requests/112), thanks Josh Bleecher Snyder!

 - 2026-04-03 v1.48.1:
     - Fix memory leaks and double-free vulnerabilities in the multi-statement query execution path.
     - Ensure bind-parameter allocations are reliably freed via strict ownership transfer if an error occurs mid-loop or if multiple statements bind parameters.
     - Fix a resource leak where a subsequent statement's error could orphan a previously generated `rows` object without closing it, leaking the prepared statement handle.
     - See [GitLab merge request #96](https://gitlab.com/cznic/sqlite/-/merge_requests/96), thanks Josh Bleecher Snyder!

 - 2026-03-27 v1.48.0:
     - Add `_timezone` DSN query parameter to apply IANA timezones (e.g., "America/New_York") to both reads and writes.
     - Writes will convert `time.Time` values to the target timezone before formatting as a string.
     - Reads will interpret timezone-less strings as being in the target timezone.
     - Does not impact `_inttotime` integer values, which will always safely evaluate as UTC.
     - Add support for `_time_format=datetime` URI parameter to format `time.Time` values identically to SQLite's native `datetime()` function and `CURRENT_TIMESTAMP` (`YYYY-MM-DD HH:MM:SS`).
     - See [GitLab merge request #94](https://gitlab.com/cznic/sqlite/-/merge_requests/94) and [GitLab merge request #95](https://gitlab.com/cznic/sqlite/-/merge_requests/95), thanks Josh Bleecher Snyder!

 - 2026-03-17 v1.47.0: Add CGO-free version of the vector extensions from https://github.com/asg017/sqlite-vec. See `vec_test.go` for example usage. From the GitHub project page:
     - **Important:** sqlite-vec is a pre-v1, so expect breaking changes!
     - Store and query float, int8, and binary vectors in vec0 virtual tables
     - Written in pure C, no dependencies, runs anywhere SQLite runs (Linux/MacOS/Windows, in the browser with WASM, Raspberry Pis, etc.)
     - Store non-vector data in metadata, auxiliary, or partition key columns
     - See [GitLab merge request #93](https://gitlab.com/cznic/sqlite/-/merge_requests/93), thanks Zhenghao Zhang!

 - 2026-03-16 v1.46.2: Upgrade to  [SQLite 3.51.3](https://sqlite.org/releaselog/3_51_3.html).

 - 2026-02-17 v1.46.1:
     - Ensure connection state is reset if Tx.Commit fails. Previously, errors like SQLITE_BUSY during COMMIT could leave the underlying connection inside a transaction, causing errors when the connection was reused by the database/sql pool. The driver now detects this state and forces a rollback internally.
     - Fixes [GitHub issue #2](https://github.com/modernc-org/sqlite/issues/2), thanks Edoardo Spadolini!

 - 2026-02-17 v1.46.0:
     - Enable ColumnTypeScanType to report time.Time instead of string for TEXT columns declared as DATE, DATETIME, TIME, or TIMESTAMP via a new `_texttotime` URI parameter.
     - See [GitHub pull request #1](https://github.com/modernc-org/sqlite/pull/1), thanks devhaozi!

 - 2026-02-09  v1.45.0:
     - Introduce vtab subpackage (modernc.org/sqlite/vtab) exposing Module, Table, Cursor, and IndexInfo API for Go virtual tables.
     - Wire vtab registration into the driver: vtab.RegisterModule installs modules globally and each new connection calls sqlite3_create_module_v2.
     - Implement vtab trampolines for xCreate/xConnect/xBestIndex/xDisconnect/xDestroy/xOpen/xClose/xFilter/xNext/xEof/xColumn/xRowid.
     - Map SQLite’s sqlite3_index_info into vtab.IndexInfo, including constraints, ORDER BY terms, and constraint usage (ArgIndex → xFilter argv[]).
     - Add an in‑repo dummy vtab module and test (module_test.go) that validates registration, basic scanning, and constraint visibility.
     - See [GitLab merge request #90](https://gitlab.com/cznic/sqlite/-/merge_requests/90), thanks Adrian Witas!

 - 2026-01-19 v1.44.3: Resolves [GitLab issue #243](https://gitlab.com/cznic/sqlite/-/issues/243).

 - 2026-01-18 v1.44.2: Upgrade to  [SQLite 3.51.2](https://sqlite.org/releaselog/3_51_2.html).

 - 2026-01-13 v1.44.0: Upgrade to SQLite 3.51.1.

 - 2025-10-10 v1.39.1: Upgrade to SQLite 3.50.4.

 - 2025-06-09 v1.38.0: Upgrade to SQLite 3.50.1.

 - 2025-02-26 v1.36.0: Upgrade to SQLite 3.49.0.

 - 2024-11-16 v1.34.0: Implement ResetSession and IsValid methods in connection

 - 2024-07-22 v1.31.0: Support windows/386.

 - 2024-06-04 v1.30.0: Upgrade to SQLite 3.46.0, release notes at
   https://sqlite.org/releaselog/3_46_0.html.

 - 2024-02-13 v1.29.0: Upgrade to SQLite 3.45.1, release notes at
   https://sqlite.org/releaselog/3_45_1.html.

 - 2023-12-14: v1.28.0: Add (*Driver).RegisterConnectionHook,
   ConnectionHookFn, ExecQuerierContext, RegisterConnectionHook.

 - 2023-08-03 v1.25.0: enable SQLITE_ENABLE_DBSTAT_VTAB.

 - 2023-07-11 v1.24.0: Add
   (*conn).{Serialize,Deserialize,NewBackup,NewRestore} methods, add Backup
   type.

 - 2023-06-01 v1.23.0: Allow registering aggregate functions.

 - 2023-04-22 v1.22.0: Support linux/s390x.

 - 2023-02-23 v1.21.0: Upgrade to SQLite 3.41.0, release notes at
   https://sqlite.org/releaselog/3_41_0.html.

 - 2022-11-28 v1.20.0: Support linux/ppc64le.

 - 2022-09-16 v1.19.0: Support frebsd/arm64.

 - 2022-07-26 v1.18.0: Add support for Go fs.FS based SQLite virtual
   filesystems, see function New in modernc.org/sqlite/vfs and/or TestVFS in
   all_test.go

 - 2022-04-24 v1.17.0: Support windows/arm64.

 - 2022-04-04 v1.16.0: Support scalar application defined functions written
   in Go. See https://www.sqlite.org/appfunc.html

 - 2022-03-13 v1.15.0: Support linux/riscv64.

 - 2021-11-13 v1.14.0: Support windows/amd64. This target had previously
   only experimental status because of a now resolved memory leak.

 - 2021-09-07 v1.13.0: Support freebsd/amd64.

 - 2021-06-23 v1.11.0: Upgrade to use sqlite 3.36.0, release notes at
   https://www.sqlite.org/releaselog/3_36_0.html.

 - 2021-05-06 v1.10.6: Fixes a memory corruption issue
   (https://gitlab.com/cznic/sqlite/-/issues/53).  Versions since v1.8.6 were
   affected and should be updated to v1.10.6.

 - 2021-03-14 v1.10.0: Update to use sqlite 3.35.0, release notes at
   https://www.sqlite.org/releaselog/3_35_0.html.

 - 2021-03-11 v1.9.0: Support darwin/arm64.

 - 2021-01-08 v1.8.0: Support darwin/amd64.

 - 2020-09-13 v1.7.0: Support linux/arm and linux/arm64.

 - 2020-09-08 v1.6.0: Support linux/386.

 - 2020-09-03 v1.5.0: This project is now completely CGo-free, including
   the Tcl tests.

 - 2020-08-26 v1.4.0: First stable release for linux/amd64.  The
   database/sql driver and its tests are CGo free.  Tests of the translated
   sqlite3.c library still require CGo.

 - 2020-07-26 v1.4.0-beta1: The project has reached beta status while
   supporting linux/amd64 only at the moment. The 'extraquick' Tcl testsuite
   reports

 - 2019-12-28 v1.2.0-alpha.3: Third alpha fixes issue #19.

 - 2019-12-26 v1.1.0-alpha.2: Second alpha release adds support for
   accessing a database concurrently by multiple goroutines and/or processes.
   v1.1.0 is now considered feature-complete. Next planed release should be a
   beta with a proper test suite.

 - 2019-12-18 v1.1.0-alpha.1: First alpha release using the new cc/v3,
   gocc, qbe toolchain. Some primitive tests pass on linux_{amd64,386}. Not
   yet safe for concurrent access by multiple goroutines. Next alpha release
   is planed to arrive before the end of this year.

 - 2017-06-10: Windows/Intel no more uses the VM (thanks Steffen Butzer).

 - 2017-06-05 Linux/Intel no more uses the VM (cznic/virtual).
