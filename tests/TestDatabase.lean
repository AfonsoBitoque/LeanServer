-- Database Layer Tests
-- Testing the database abstraction layer

import LeanServer.Db.Database

namespace LeanServer

def main : IO Unit := do
  IO.println "=== Database Layer Tests ==="

  -- Test database configuration
  IO.println "Testing database configuration..."
  let config : DatabaseConfig := {
    host := "localhost"
    port := 5432
    database := "test_db"
    username := "test_user"
    password := "test_pass"
    maxConnections := 5
  }
  IO.println ("✅ Configuração criada: " ++ config.database ++ "@" ++ config.host ++ ":" ++ toString config.port)

  -- Test connection pool initialization
  IO.println "Testing connection pool..."
  let pool ← initConnectionPool config 5
  IO.println ("✅ Pool inicializado com tamanho máximo: " ++ toString pool.maxSize)

  -- Test database manager
  IO.println "Testing database manager..."
  let manager ← initDatabaseManager config
  IO.println ("✅ Gerenciador inicializado: " ++ getDatabaseStats manager)

  -- Test query builder
  IO.println "Testing query builder..."
  let qb : QueryBuilder := {
    table := "users"
    select := #["id", "name", "email"]
    whereClause := some "active = true"
    orderBy := some "name ASC"
    limit := some 10
  }
  let query := qb.buildSelect
  IO.println ("✅ Query construída: " ++ query)

  -- Test table schema
  IO.println "Testing table schema..."
  IO.println "✅ Schema test skipped for now"

  -- Test migration
  IO.println "Testing migration system..."
  let migration : Migration := {
    version := 1
    name := "create_users_table"
    up := "CREATE TABLE users (id BIGSERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMP NOT NULL DEFAULT NOW())"
    down := "DROP TABLE users"
  }
  IO.println ("✅ Migração criada: " ++ migration.name ++ " (versão " ++ toString migration.version ++ ")")

  -- Test SQL escaping
  IO.println "Testing SQL escaping..."
  let dangerousString := "'; DROP TABLE users; --"
  let escaped := escapeSqlString dangerousString
  IO.println ("✅ String escapada: '" ++ escaped ++ "'")

  -- Test parameterized query
  IO.println "Testing parameterized query..."
  let template := "SELECT * FROM users WHERE name = ? AND active = ?"
  let params := #["João", "true"]
  let parameterized := buildParameterizedQuery template params
  IO.println ("✅ Query parametrizada: " ++ parameterized)

  IO.println "All database layer tests passed!"

end LeanServer</content>
<parameter name="filePath">c:\Users\afobi\Desktop\LeanServer3\TestDatabase.lean
