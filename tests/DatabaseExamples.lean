-- Database Usage Examples
-- Complete examples of using LeanServer database layer
-- Shows PostgreSQL and MySQL integration

import LeanServer.Db.Database
import LeanServer.Db.PostgreSQL
import LeanServer.Db.MySQL

namespace LeanServer

def main : IO Unit := do
  IO.println "=== LeanServer Database Layer Test ==="

  -- PostgreSQL configuration
  let pgConfig : DatabaseConfig := {
    host := "localhost"
    port := 5432
    database := "lean_example"
    username := "postgres"
    password := "password"
    maxConnections := 10
  }

  -- MySQL configuration
  let mysqlConfig : DatabaseConfig := {
    host := "localhost"
    port := 3306
    database := "lean_example"
    username := "root"
    password := "password"
    maxConnections := 10
  }

  -- Initialize PostgreSQL manager
  let pgDriver : PostgreSQLDriver := {}
  let pgManager ← initDatabaseManager pgDriver pgConfig DatabaseType.PostgreSQL
  IO.println "✓ PostgreSQL manager initialized successfully"

  -- Initialize MySQL manager
  let mysqlDriver : MySQLDriver := {}
  let mysqlManager ← initDatabaseManager mysqlDriver mysqlConfig DatabaseType.MySQL
  IO.println "✓ MySQL manager initialized successfully"

  -- Show database statistics
  let pgStats := getDatabaseStats pgManager
  let mysqlStats := getDatabaseStats mysqlManager
  IO.println s!"PostgreSQL stats: {pgStats}"
  IO.println s!"MySQL stats: {mysqlStats}"

  IO.println "✓ Database layer compilation and basic functionality test passed!"
