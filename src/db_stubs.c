/*
 * db_stubs.c — Stub implementations for MySQL/PostgreSQL FFI symbols.
 *
 * These stubs allow executables that transitively depend on the Database
 * modules to link without libmysqlclient or libpq installed.
 * All stubs return NULL / 0 / empty string — they should never be called
 * at runtime unless actual DB operations are attempted (which will fail safely).
 */

#include <stddef.h>
#include <stdint.h>

/* ====== MySQL stubs ====== */

void *mysql_init(void *mysql)         { (void)mysql; return NULL; }
void *mysql_real_connect(void *mysql, const char *host, const char *user,
                         const char *passwd, const char *db,
                         unsigned int port, const char *unix_socket,
                         unsigned long clientflag)
{
    (void)mysql; (void)host; (void)user; (void)passwd;
    (void)db; (void)port; (void)unix_socket; (void)clientflag;
    return NULL;
}
void  mysql_close(void *mysql)        { (void)mysql; }
int   mysql_ping(void *mysql)         { (void)mysql; return -1; }
const char *mysql_error(void *mysql)  { (void)mysql; return "stub: no MySQL"; }
int   mysql_query(void *mysql, const char *q) { (void)mysql; (void)q; return -1; }
void *mysql_store_result(void *mysql) { (void)mysql; return NULL; }
void  mysql_free_result(void *result) { (void)result; }
uint64_t mysql_num_rows(void *result) { (void)result; return 0; }
unsigned int mysql_num_fields(void *result) { (void)result; return 0; }
char **mysql_fetch_row(void *result)  { (void)result; return NULL; }
void *mysql_fetch_field(void *result) { (void)result; return NULL; }
uint64_t mysql_affected_rows(void *mysql) { (void)mysql; return 0; }

/* ====== PostgreSQL stubs ====== */

void *PQconnectdb(const char *conninfo)     { (void)conninfo; return NULL; }
void  PQfinish(void *conn)                  { (void)conn; }
int   PQstatus(const void *conn)            { (void)conn; return 1; /* CONNECTION_BAD */ }
const char *PQerrorMessage(const void *conn){ (void)conn; return "stub: no PostgreSQL"; }
void *PQexec(void *conn, const char *q)     { (void)conn; (void)q; return NULL; }
void  PQclear(void *res)                    { (void)res; }
int   PQresultStatus(const void *res)       { (void)res; return 7; /* PGRES_FATAL_ERROR */ }
int   PQntuples(const void *res)            { (void)res; return 0; }
int   PQnfields(const void *res)            { (void)res; return 0; }
const char *PQfname(const void *res, int n) { (void)res; (void)n; return ""; }
const char *PQgetvalue(const void *res, int row, int col) { (void)res; (void)row; (void)col; return ""; }
const char *PQcmdTuples(void *res)          { (void)res; return "0"; }
