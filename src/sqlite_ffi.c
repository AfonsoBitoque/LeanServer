/*
 * SQLite FFI bindings for Lean 4 (ROADMAP F6.1)
 * Minimal C wrapper around sqlite3 — all logic stays in Lean.
 *
 * Compilation:
 *   With real SQLite:  gcc -c -DLEANSERVER_USE_SQLITE sqlite_ffi.c -I$(LEAN_INCLUDE) -lsqlite3
 *   Without (stubs):   gcc -c sqlite_ffi.c -I$(LEAN_INCLUDE)
 */

#include <lean/lean.h>
#include <string.h>
#include <stdlib.h>

#ifdef LEANSERVER_USE_SQLITE
#include <sqlite3.h>
#endif

/* ═══════════════════════════════════════════════════════════
 * SQLite Open / Close
 * ═══════════════════════════════════════════════════════════ */

/* lean_sqlite_open : String → IO UInt64 */
LEAN_EXPORT lean_obj_res lean_sqlite_open(lean_obj_arg path_obj, lean_obj_arg w) {
#ifdef LEANSERVER_USE_SQLITE
    const char *path = lean_string_cstr(path_obj);
    sqlite3 *db = NULL;
    int rc = sqlite3_open(path, &db);
    if (rc != SQLITE_OK) {
        const char *err = db ? sqlite3_errmsg(db) : "unknown error";
        lean_obj_res err_obj = lean_mk_string(err);
        if (db) sqlite3_close(db);
        return lean_io_result_mk_error(lean_mk_io_user_error(err_obj));
    }
    return lean_io_result_mk_ok(lean_box(((size_t)db)));
#else
    (void)path_obj;
    return lean_io_result_mk_error(lean_mk_io_user_error(
        lean_mk_string("SQLite not available (compile with -DLEANSERVER_USE_SQLITE)")));
#endif
}

/* lean_sqlite_close : UInt64 → IO Unit */
LEAN_EXPORT lean_obj_res lean_sqlite_close(size_t db_handle, lean_obj_arg w) {
#ifdef LEANSERVER_USE_SQLITE
    sqlite3 *db = (sqlite3 *)db_handle;
    if (db) sqlite3_close(db);
#else
    (void)db_handle;
#endif
    return lean_io_result_mk_ok(lean_box(0));
}

/* ═══════════════════════════════════════════════════════════
 * SQLite Execute (returns result as string table)
 * ═══════════════════════════════════════════════════════════ */

/* lean_sqlite_exec : UInt64 → String → IO String
 * Returns result rows as tab-separated lines:
 *   "col1\tcol2\tcol3\nval1\tval2\tval3\n..."
 * First line is column headers, subsequent lines are data rows. */
LEAN_EXPORT lean_obj_res lean_sqlite_exec(size_t db_handle, lean_obj_arg sql_obj, lean_obj_arg w) {
#ifdef LEANSERVER_USE_SQLITE
    sqlite3 *db = (sqlite3 *)db_handle;
    const char *sql = lean_string_cstr(sql_obj);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        const char *err = sqlite3_errmsg(db);
        return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(err)));
    }

    /* Build result string */
    size_t buf_size = 4096;
    size_t buf_len = 0;
    char *buf = (char *)malloc(buf_size);
    if (!buf) {
        sqlite3_finalize(stmt);
        return lean_io_result_mk_error(lean_mk_io_user_error(
            lean_mk_string("out of memory")));
    }
    buf[0] = '\0';

    /* Column headers */
    int ncols = sqlite3_column_count(stmt);
    for (int i = 0; i < ncols; i++) {
        const char *name = sqlite3_column_name(stmt, i);
        size_t name_len = strlen(name);
        while (buf_len + name_len + 2 > buf_size) {
            buf_size *= 2;
            buf = (char *)realloc(buf, buf_size);
        }
        if (i > 0) buf[buf_len++] = '\t';
        memcpy(buf + buf_len, name, name_len);
        buf_len += name_len;
    }
    if (ncols > 0) buf[buf_len++] = '\n';

    /* Data rows */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        for (int i = 0; i < ncols; i++) {
            const char *val = (const char *)sqlite3_column_text(stmt, i);
            if (!val) val = "NULL";
            size_t val_len = strlen(val);
            while (buf_len + val_len + 2 > buf_size) {
                buf_size *= 2;
                buf = (char *)realloc(buf, buf_size);
            }
            if (i > 0) buf[buf_len++] = '\t';
            memcpy(buf + buf_len, val, val_len);
            buf_len += val_len;
        }
        buf[buf_len++] = '\n';
    }

    buf[buf_len] = '\0';
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        const char *err = sqlite3_errmsg(db);
        free(buf);
        return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(err)));
    }

    lean_obj_res result = lean_mk_string(buf);
    free(buf);
    return lean_io_result_mk_ok(result);
#else
    (void)db_handle;
    (void)sql_obj;
    return lean_io_result_mk_error(lean_mk_io_user_error(
        lean_mk_string("SQLite not available (compile with -DLEANSERVER_USE_SQLITE)")));
#endif
}

/* ═══════════════════════════════════════════════════════════
 * SQLite Execute Non-Query (returns affected rows)
 * ═══════════════════════════════════════════════════════════ */

/* lean_sqlite_changes : UInt64 → IO UInt32 */
LEAN_EXPORT lean_obj_res lean_sqlite_changes(size_t db_handle, lean_obj_arg w) {
#ifdef LEANSERVER_USE_SQLITE
    sqlite3 *db = (sqlite3 *)db_handle;
    int changes = sqlite3_changes(db);
    return lean_io_result_mk_ok(lean_box((unsigned)changes));
#else
    (void)db_handle;
    return lean_io_result_mk_ok(lean_box(0));
#endif
}

/* lean_sqlite_last_insert_rowid : UInt64 → IO UInt64 */
LEAN_EXPORT lean_obj_res lean_sqlite_last_insert_rowid(size_t db_handle, lean_obj_arg w) {
#ifdef LEANSERVER_USE_SQLITE
    sqlite3 *db = (sqlite3 *)db_handle;
    sqlite3_int64 rowid = sqlite3_last_insert_rowid(db);
    return lean_io_result_mk_ok(lean_box((size_t)rowid));
#else
    (void)db_handle;
    return lean_io_result_mk_ok(lean_box(0));
#endif
}
