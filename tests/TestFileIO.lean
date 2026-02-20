-- Test File I/O Functions
import Lean

def main : IO Unit := do
  IO.println "Testing file I/O functions..."

  -- Test write to log file
  IO.println "Writing to test.log..."
  IO.FS.withFile "test.log" IO.FS.Mode.append (fun handle => do
    handle.putStrLn "Test log entry from Lean"
    handle.flush
  )
  IO.println "Write completed"

  -- Check if file exists
  let fileExists ← System.FilePath.pathExists "test.log"
  IO.println s!"File exists: {fileExists}"

  -- Read and display file content
  if fileExists then
    let content ← IO.FS.readFile "test.log"
    IO.println s!"File content: {content}"

  IO.println "Test complete"
