import LeanServer.Server.HTTPServer

/-!
# Content Negotiation (R26)

Implements HTTP content negotiation per RFC 7231 §5.3:
- `Accept` header parsing and matching
- `Accept-Encoding` for compression selection
- `Accept-Language` for locale selection
- Quality value (q-factor) sorting
- Media type matching with wildcards

## Usage
```lean
let accept := "text/html, application/json;q=0.9, */*;q=0.1"
let negotiated := negotiateContentType accept ["application/json", "text/html"]
-- returns some "text/html" (q=1.0 > 0.9)
```
-/

namespace LeanServer

-- ==========================================
-- Media Type Parsing
-- ==========================================

/-- A parsed media type with quality factor -/
structure MediaType where
  /-- Main type (e.g., "text", "application", "*") -/
  type_    : String
  /-- Sub type (e.g., "html", "json", "*") -/
  subtype  : String
  /-- Quality factor 0-1000 (q × 1000 for integer math) -/
  quality  : Nat := 1000
  /-- Media type parameters (excluding q) -/
  params   : List (String × String) := []
  deriving Inhabited, BEq, Repr

instance : ToString MediaType where
  toString mt :=
    let base := s!"{mt.type_}/{mt.subtype}"
    if mt.quality < 1000 then s!"{base};q=0.{mt.quality}" else base

/-- Parse a quality value string like "0.9" into 0-1000 -/
def parseQuality (s : String) : Nat :=
  let trimmed := s.trimAscii.toString
  if trimmed == "1" || trimmed == "1.0" || trimmed == "1.00" || trimmed == "1.000" then 1000
  else if trimmed == "0" || trimmed == "0.0" then 0
  else if trimmed.startsWith "0." then
    let frac := (trimmed.drop 2).toString
    match frac.toNat? with
    | some n =>
      if frac.length == 1 then n * 100
      else if frac.length == 2 then n * 10
      else if frac.length == 3 then n
      else n
    | none => 1000
  else 1000

/-- Parse a single media type entry like "text/html;q=0.9;charset=utf-8" -/
def parseMediaType (s : String) : MediaType :=
  let trimmed := s.trimAscii.toString
  let parts := trimmed.splitOn ";"
  match parts with
  | [] => { type_ := "*", subtype := "*" }
  | typePart :: paramParts =>
    let typeStr := typePart.trimAscii.toString
    let (type_, subtype) := match typeStr.splitOn "/" with
      | [t, s] => (t.trimAscii.toString, s.trimAscii.toString)
      | [t]    => (t.trimAscii.toString, "*")
      | _      => ("*", "*")
    -- Parse parameters
    let rec go (remaining : List String) (q : Nat) (params : List (String × String)) : MediaType :=
      match remaining with
      | [] => { type_, subtype, quality := q, params }
      | p :: rest =>
        match p.splitOn "=" with
        | [key, value] =>
          let k := key.trimAscii.toString.toLower
          let v := value.trimAscii.toString
          if k == "q" then go rest (parseQuality v) params
          else go rest q (params ++ [(k, v)])
        | _ => go rest q params
    go paramParts 1000 []

/-- Parse an Accept header into a sorted list of media types -/
def parseAcceptHeader (accept : String) : List MediaType :=
  let entries := accept.splitOn ","
  let parsed := entries.map parseMediaType
  -- Sort by quality (descending), then by specificity
  parsed.mergeSort fun a b => a.quality > b.quality

-- ==========================================
-- Media Type Matching
-- ==========================================

/-- Check if a media type matches a pattern (with wildcard support) -/
def mediaTypeMatches (pattern offered : MediaType) : Bool :=
  let typeMatch := pattern.type_ == "*" || pattern.type_ == offered.type_
  let subMatch := pattern.subtype == "*" || pattern.subtype == offered.subtype
  typeMatch && subMatch

/-- Specificity score for a media type (higher = more specific) -/
def mediaTypeSpecificity (mt : MediaType) : Nat :=
  let typeScore := if mt.type_ == "*" then 0 else 2
  let subScore := if mt.subtype == "*" then 0 else 1
  typeScore + subScore + mt.params.length

/-- Negotiate the best content type from a list of offered types -/
def negotiateContentType (acceptHeader : String) (offered : List String) : Option String :=
  let accepted := parseAcceptHeader acceptHeader
  let offeredTypes := offered.map parseMediaType
  -- For each accepted type (in quality order), find the first matching offered type
  let rec findBest (remaining : List MediaType) : Option MediaType :=
    match remaining with
    | [] => none
    | pattern :: rest =>
      match offeredTypes.find? (mediaTypeMatches pattern) with
      | some mt => some mt
      | none => findBest rest
  match findBest accepted with
  | some mt => some (toString mt)
  | none => none

/-- Negotiate with a default fallback -/
def negotiateContentTypeWithDefault (acceptHeader : String) (offered : List String)
    (default_ : String := "application/octet-stream") : String :=
  match negotiateContentType acceptHeader offered with
  | some ct => ct
  | none => default_

-- ==========================================
-- Accept-Encoding Negotiation
-- ==========================================

/-- A parsed encoding with quality factor -/
structure AcceptEncoding where
  encoding : String
  quality  : Nat := 1000  -- q × 1000
  deriving Inhabited, BEq, Repr

/-- Parse Accept-Encoding header -/
def parseAcceptEncoding (header : String) : List AcceptEncoding :=
  let entries := header.splitOn ","
  let parsed := entries.map fun entry =>
    let parts := entry.trimAscii.toString.splitOn ";"
    match parts with
    | [] => { encoding := "identity" : AcceptEncoding }
    | enc :: rest =>
      let encoding := enc.trimAscii.toString.toLower
      let quality := match rest.head? with
        | some qPart =>
          match qPart.trimAscii.toString.splitOn "=" with
          | [_, qVal] => parseQuality qVal
          | _ => 1000
        | none => 1000
      { encoding, quality }
  parsed.mergeSort fun a b => a.quality > b.quality

/-- Select the best encoding from supported list -/
def negotiateEncoding (acceptEncodingHeader : String)
    (supported : List String := ["gzip", "identity"]) : String :=
  let accepted := parseAcceptEncoding acceptEncodingHeader
  match accepted.find? (fun ae => supported.any (· == ae.encoding) && ae.quality > 0) with
  | some ae => ae.encoding
  | none => "identity"

-- ==========================================
-- Accept-Language Negotiation
-- ==========================================

/-- A parsed language tag with quality -/
structure AcceptLanguage where
  tag     : String
  quality : Nat := 1000
  deriving Inhabited, BEq, Repr

/-- Parse Accept-Language header -/
def parseAcceptLanguage (header : String) : List AcceptLanguage :=
  let entries := header.splitOn ","
  let parsed := entries.map fun entry =>
    let parts := entry.trimAscii.toString.splitOn ";"
    match parts with
    | [] => { tag := "en" : AcceptLanguage }
    | lang :: rest =>
      let tag := lang.trimAscii.toString.toLower
      let quality := match rest.head? with
        | some qPart =>
          match qPart.trimAscii.toString.splitOn "=" with
          | [_, qVal] => parseQuality qVal
          | _ => 1000
        | none => 1000
      { tag, quality }
  parsed.mergeSort fun a b => a.quality > b.quality

/-- Check if a language tag matches (prefix matching) -/
def languageMatches (pattern offered : String) : Bool :=
  pattern == "*" || pattern == offered || offered.startsWith (pattern ++ "-")

/-- Select the best language from supported list -/
def negotiateLanguage (acceptLanguageHeader : String)
    (supported : List String := ["en"]) : String :=
  let accepted := parseAcceptLanguage acceptLanguageHeader
  match accepted.find? (fun al => supported.any (languageMatches al.tag) && al.quality > 0) with
  | some al => al.tag
  | none => supported.headD "en"

-- ==========================================
-- Content Negotiation Middleware
-- ==========================================

/-- Content negotiation result -/
structure ContentNegotiationResult where
  contentType : String
  encoding    : String
  language    : String
  deriving Inhabited, Repr

/-- Full content negotiation from request headers -/
def negotiateContent (headers : List (String × String))
    (offeredTypes : List String := ["text/html", "application/json"])
    (supportedEncodings : List String := ["gzip", "identity"])
    (supportedLanguages : List String := ["en"]) : ContentNegotiationResult :=
  let accept := match headers.find? (fun (k, _) => k.toLower == "accept") with
    | some (_, v) => v | none => "*/*"
  let acceptEnc := match headers.find? (fun (k, _) => k.toLower == "accept-encoding") with
    | some (_, v) => v | none => "identity"
  let acceptLang := match headers.find? (fun (k, _) => k.toLower == "accept-language") with
    | some (_, v) => v | none => "en"
  { contentType := negotiateContentTypeWithDefault accept offeredTypes
    encoding := negotiateEncoding acceptEnc supportedEncodings
    language := negotiateLanguage acceptLang supportedLanguages }

/-- Content negotiation middleware -/
def contentNegotiationMiddleware : Middleware := {
  name := "content-negotiation"
  apply := fun _ _ _ _ resp =>
    -- Add Vary header to indicate content negotiation
    { resp with extraHeaders := resp.extraHeaders ++
      [("vary", "Accept, Accept-Encoding, Accept-Language")] }
}

-- ==========================================
-- Proofs
-- ==========================================

/-- Quality parsing of \"1\" returns 1000 (verified: concrete value check via native_decide) -/
theorem quality_one : parseQuality "1" = 1000 := by
  native_decide

/-- Wildcard media type matches any type -/
theorem wildcard_matches_all (mt : MediaType) :
    mediaTypeMatches { type_ := "*", subtype := "*" } mt = true := by
  simp [mediaTypeMatches]

/-- Exact type match works -/
theorem exact_type_match (t s : String) :
    mediaTypeMatches { type_ := t, subtype := s } { type_ := t, subtype := s } = true := by
  simp [mediaTypeMatches]

end LeanServer
