-- Web Application Tests
-- Tests for the web application framework (Simple variant) and SampleWebApp

import LeanServer.Web.SampleWebApp

namespace LeanServer.Tests

/-- Check if a string contains a substring using splitOn -/
def stringContains (haystack : String) (needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

/-- Extract a string value for a given key from a JSON-like string -/
def extractJsonField (json : String) (key : String) : String :=
  let needle := "\"" ++ key ++ "\": "
  let parts := json.splitOn needle
  match parts with
  | [_, rest] =>
    if rest.length > 0 && rest.front == '"' then
      -- String value: take until closing quote
      let inner := rest.drop 1
      (inner.takeWhile (· != '"')).toString
    else
      -- Numeric value: take until comma/brace
      (rest.takeWhile (fun c => c != ',' && c != '}' && c != ' ')).toString
  | _ => ""

def testWebApplication : IO Unit := do
  IO.eprintln "🧪 Testing Web Application Framework"

  -- Create sample app
  let app ← LeanServer.createSampleWebApp
  IO.eprintln "✅ Web application created successfully"

  -- Test route registration (8 routes: setup, users CRUD, health, root)
  IO.eprintln s!"📊 Routes registered: {app.routes.length}"
  assert! app.routes.length == 8
  IO.eprintln "✅ Routes registered correctly"

  IO.eprintln "✅ Web application framework tests passed!"

def testResponseBuilders : IO Unit := do
  IO.eprintln "🧪 Testing Response Builders"

  -- Test JSON response
  let jsonResp := LeanServer.jsonResponse "{\"test\": \"data\"}"
  assert! jsonResp.statusCode == 200
  assert! jsonResp.contentType == "application/json"
  IO.eprintln "✅ JSON response builder works"

  -- Test HTML response
  let htmlResp := LeanServer.htmlResponse "<h1>Hello</h1>"
  assert! htmlResp.statusCode == 200
  assert! htmlResp.contentType == "text/html"
  IO.eprintln "✅ HTML response builder works"

  -- Test error response
  let errorResp := LeanServer.errorResponse 404 "Not found"
  assert! errorResp.statusCode == 404
  assert! errorResp.contentType == "text/plain"
  IO.eprintln "✅ Error response builder works"

  IO.eprintln "✅ Response builder tests passed!"

def testUserJsonConversion : IO Unit := do
  IO.eprintln "🧪 Testing User JSON Conversion"

  let user : LeanServer.User := {
    id := some 1
    name := "John Doe"
    email := "john@example.com"
    age := 30
    created_at := some "2024-01-01"
  }

  let json := LeanServer.userToJson user
  IO.eprintln s!"📋 User JSON: {json}"
  assert! stringContains json "\"name\": \"John Doe\""
  assert! stringContains json "\"email\": \"john@example.com\""
  assert! stringContains json "\"age\": 30"
  IO.eprintln "✅ User to JSON conversion works"

  IO.eprintln "✅ User JSON conversion tests passed!"

def testJsonFieldExtraction : IO Unit := do
  IO.eprintln "🧪 Testing JSON Field Extraction"

  let json := "{\"name\": \"Alice\", \"email\": \"alice@test.com\", \"age\": 25}"

  let name := extractJsonField json "name"
  IO.eprintln s!"📋 Extracted name: {name}"
  assert! name == "Alice"
  IO.eprintln "✅ String field extraction works"

  let email := extractJsonField json "email"
  assert! email == "alice@test.com"
  IO.eprintln "✅ Email field extraction works"

  let age := extractJsonField json "age"
  assert! age == "25"
  IO.eprintln "✅ Numeric field extraction works"

  IO.eprintln "✅ JSON field extraction tests passed!"

def testRouteHandling : IO Unit := do
  IO.eprintln "🧪 Testing Route Handling"

  let app ← LeanServer.createSampleWebApp

  -- Test health check route
  let healthReq : LeanServer.HttpRequest := {
    method := "GET"
    path := "/health"
    headers := #[]
    body := ByteArray.empty
    streamId := 1
  }
  let healthResp ← LeanServer.handleWebRequest app healthReq
  assert! healthResp.statusCode == 200
  assert! healthResp.contentType == "application/json"
  IO.eprintln "✅ Health check route works"

  -- Test 404 for unknown route
  let unknownReq : LeanServer.HttpRequest := {
    method := "GET"
    path := "/nonexistent"
    headers := #[]
    body := ByteArray.empty
    streamId := 1
  }
  let unknownResp ← LeanServer.handleWebRequest app unknownReq
  assert! unknownResp.statusCode == 404
  IO.eprintln "✅ Unknown route returns 404"

  IO.eprintln "✅ Route handling tests passed!"

end LeanServer.Tests

-- Main entry point (outside LeanServer namespace to avoid conflict with SampleWebApp.main)
def main : IO Unit := do
  IO.eprintln "🚀 Running Web Application Tests"

  LeanServer.Tests.testWebApplication
  LeanServer.Tests.testResponseBuilders
  LeanServer.Tests.testUserJsonConversion
  LeanServer.Tests.testJsonFieldExtraction
  LeanServer.Tests.testRouteHandling

  IO.eprintln "🎉 All web application tests passed!"
