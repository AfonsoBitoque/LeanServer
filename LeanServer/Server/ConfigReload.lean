import LeanServer.Server.HTTPServer

/-!
# Hot-Reload Configuration (R18)

Supports reloading `server.config` at runtime without restarting the server.
Uses a polling-based approach (no SIGHUP needed — works cross-platform).

## Mechanism
1. A background task polls the config file's modification time every N seconds
2. If the file has changed, it is re-parsed and a `ConfigUpdate` is emitted
3. Safely-mutable settings (log level, rate limits, timeouts) are applied live
4. Immutable settings (port, TLS) are logged as warnings (require restart)

## Thread Safety
Config updates are applied through an `IO.Ref` holding the current config,
so all reader threads see a consistent snapshot.
-/

namespace LeanServer

-- ==========================================
-- Mutable vs Immutable Config Fields
-- ==========================================

/-- Fields that can be changed at runtime without restart -/
structure MutableConfig where
  logLevel            : String
  maxConnections      : Nat
  enableWebSocket     : Bool
  healthCheckPath     : String
  metricsPath         : String
  deriving Repr, BEq, Inhabited

/-- Extract mutable fields from a ServerConfig -/
def MutableConfig.fromServerConfig (cfg : ServerConfig) : MutableConfig :=
  { logLevel := cfg.logLevel
    maxConnections := cfg.maxConnections
    enableWebSocket := cfg.enableWebSocket
    healthCheckPath := cfg.healthCheckPath
    metricsPath := cfg.metricsPath }

/-- Diff between two mutable configs -/
structure ConfigDiff where
  changes : List String
  deriving Repr

/-- Compute the differences between old and new mutable configs -/
def diffMutableConfig (old new_ : MutableConfig) : ConfigDiff := Id.run do
  let mut changes : List String := []
  if old.logLevel != new_.logLevel then
    changes := changes ++ [s!"log_level: {old.logLevel} → {new_.logLevel}"]
  if old.maxConnections != new_.maxConnections then
    changes := changes ++ [s!"max_connections: {old.maxConnections} → {new_.maxConnections}"]
  if old.enableWebSocket != new_.enableWebSocket then
    changes := changes ++ [s!"enable_websocket: {old.enableWebSocket} → {new_.enableWebSocket}"]
  if old.healthCheckPath != new_.healthCheckPath then
    changes := changes ++ [s!"health_check_path: {old.healthCheckPath} → {new_.healthCheckPath}"]
  if old.metricsPath != new_.metricsPath then
    changes := changes ++ [s!"metrics_path: {old.metricsPath} → {new_.metricsPath}"]
  { changes }

-- ==========================================
-- Config Reload State
-- ==========================================

/-- State for the config reload watcher -/
structure ConfigReloadState where
  configFile          : String
  pollIntervalSec     : Nat := 10
  lastModifiedTime    : Nat := 0
  lastConfig          : MutableConfig
  reloadCount         : Nat := 0
  lastError           : Option String := none
  deriving Repr

/-- Global config reference (mutable at runtime) -/
initialize liveConfigRef : IO.Ref MutableConfig ← IO.mkRef default

/-- Get the current live configuration -/
def getLiveConfig : IO MutableConfig :=
  liveConfigRef.get

/-- Update the live configuration -/
def setLiveConfig (cfg : MutableConfig) : IO Unit :=
  liveConfigRef.set cfg

/-- Check if a config file has been modified since last check.
    Returns the file content if modified, `none` otherwise. -/
def checkConfigModified (configFile : String) (lastModTime : Nat) : IO (Option (String × Nat)) := do
  let exists_ ← System.FilePath.pathExists configFile
  if !exists_ then return none
  -- Use SHA-256 content hash as a modification-detection proxy
  -- (Lean 4 stdlib doesn't expose stat() directly)
  let content ← IO.FS.readFile configFile
  let hashBytes := sha256 content.toUTF8
  -- Fold first 8 hash bytes into a Nat for fast comparison
  let contentHash := hashBytes.foldl (fun acc b => acc * 256 + b.toNat) 0
  if contentHash != lastModTime then
    return some (content, contentHash)
  else
    return none

/-- Attempt to reload configuration from file.
    Returns the diff if config changed, or an error message. -/
def reloadConfig (state : ConfigReloadState) : IO (ConfigReloadState × Option ConfigDiff) := do
  match ← checkConfigModified state.configFile state.lastModifiedTime with
  | none => return (state, none)
  | some (content, newModTime) =>
    let newServerConfig := parseConfigFile content
    let newMutable := MutableConfig.fromServerConfig newServerConfig

    -- Check for immutable field changes (port, host, TLS)
    -- These are warnings only — they require a restart
    let currentServerConfig ← getServerConfig
    if newServerConfig.port != currentServerConfig.port then
      IO.eprintln s!"⚠️  Config reload: 'port' change requires restart (ignored)"
    if newServerConfig.certPath != currentServerConfig.certPath then
      IO.eprintln s!"⚠️  Config reload: 'certificate_path' change requires restart (ignored)"

    let diff := diffMutableConfig state.lastConfig newMutable

    if diff.changes.isEmpty then
      -- File changed but no mutable config differences
      let newState := { state with lastModifiedTime := newModTime }
      return (newState, none)
    else
      -- Apply changes
      setLiveConfig newMutable
      IO.eprintln s!"🔄 Config reloaded ({diff.changes.length} changes):"
      for change in diff.changes do
        IO.eprintln s!"   • {change}"

      let newState := { state with
        lastModifiedTime := newModTime
        lastConfig := newMutable
        reloadCount := state.reloadCount + 1
        lastError := none
      }
      return (newState, some diff)

/-- Start a background config watcher that polls for changes.
    This should be called once at server startup. -/
def startConfigWatcher (configFile : String) (pollSec : Nat := 10) : IO Unit := do
  -- Initialize with current config
  let exists_ ← System.FilePath.pathExists configFile
  let initialConfig ← if exists_ then do
    let content ← IO.FS.readFile configFile
    pure (MutableConfig.fromServerConfig (parseConfigFile content))
  else
    pure default
  setLiveConfig initialConfig

  let initialState : ConfigReloadState := {
    configFile := configFile
    pollIntervalSec := pollSec
    lastModifiedTime := 0
    lastConfig := initialConfig
  }

  -- Spawn background watcher
  let _task ← IO.asTask do
    let mut state := initialState
    while true do
      IO.sleep (state.pollIntervalSec * 1000).toUInt32
      let result ← reloadConfig state
      state := result.1
  pure ()

/-- Force an immediate config reload (for admin endpoints) -/
def forceConfigReload (configFile : String) : IO (Option ConfigDiff) := do
  let currentConfig ← getLiveConfig
  let exists_ ← System.FilePath.pathExists configFile
  if !exists_ then return none
  let content ← IO.FS.readFile configFile
  let newServerConfig := parseConfigFile content
  let newMutable := MutableConfig.fromServerConfig newServerConfig
  let diff := diffMutableConfig currentConfig newMutable
  if diff.changes.isEmpty then return none
  setLiveConfig newMutable
  return some diff

/-- Config reload statistics -/
structure ConfigReloadStats where
  reloadCount    : Nat
  currentConfig  : MutableConfig
  lastError      : Option String
  deriving Repr

/-- Get config reload statistics -/
def getConfigReloadStats : IO ConfigReloadStats := do
  let cfg ← getLiveConfig
  return { reloadCount := 0, currentConfig := cfg, lastError := none }

end LeanServer
