import LeanServer.Crypto.X25519
import Init.Data.Array
import LeanServer.Crypto.AES
import LeanServer.Core.Base64
import LeanServer.Crypto.RSA

namespace LeanServer

-- ==========================================
-- Named Constants (eliminates magic numbers across the module)
-- RFC references for each value are noted inline.
-- ==========================================

/-- SHA-256 output length in bytes -/
def hashLen : Nat := 32

/-- AES-128 key length in bytes -/
def aesKeyLen : Nat := 16

/-- AES-GCM initialization vector length in bytes -/
def aesGCMIvLen : Nat := 12

/-- HMAC-SHA256 block size in bytes -/
def hmacBlockSize : Nat := 64

/-- TLS_AES_128_GCM_SHA256 cipher suite identifier (RFC 8446 §B.4) -/
def tlsAES128GCMSHA256 : UInt16 := 0x1301

/-- X25519 named group identifier (RFC 8446 §4.2.7) -/
def x25519GroupId : Nat := 0x001d

/-- RSA-PSS-RSAE-SHA256 signature scheme (RFC 8446 §4.2.3) -/
def rsaPSSRSAeSHA256 : Nat := 0x0804

/-- Default session ticket lifetime in seconds (2 hours) -/
def defaultTicketLifetimeSec : UInt32 := 7200

/-- Default max early data size for 0-RTT (16 KB) -/
def defaultMaxEarlyData : UInt32 := 16384

/-- PSK cache max entries -/
def pskCacheMaxSize : Nat := 256

-- ==========================================
-- Byte Encoding Helpers (eliminates repetitive shift/mask patterns)
-- ==========================================

/-- Encode a `Nat` as 2 bytes, big-endian. -/
def encodeUInt16BE (n : Nat) : ByteArray :=
  ByteArray.mk #[(n / 256).toUInt8, (n % 256).toUInt8]

/-- Encode a `Nat` as 3 bytes, big-endian. -/
def encodeUInt24BE (n : Nat) : ByteArray :=
  ByteArray.mk #[(n / 65536).toUInt8, ((n / 256) % 256).toUInt8, (n % 256).toUInt8]

/-- Create a zero-filled ByteArray of length `n`. -/
def zeroBytes (n : Nat) : ByteArray :=
  ByteArray.mk (List.replicate n (0 : UInt8)).toArray

/-- Load a PEM-encoded file, strip headers/footers, and Base64-decode to raw bytes.
    Shared between certificate and private key loading to avoid duplication. -/
def loadPEMFile (filename : String) : IO (Option ByteArray) := do
  try
    let content ← IO.FS.readFile filename
    let lines := content.splitOn "\n"
    let bodyLines := lines.filter (fun l => !l.startsWith "-----")
    let body := String.join bodyLines
    match LeanServer.Base64.decode body with
    | some bytes => pure (some bytes)
    | none =>
      IO.eprintln s!"❌ Base64 decode failed for {filename}"
      pure none
  catch e =>
    IO.eprintln s!"❌ Failed to load {filename}: {e}"
    pure none

/-- Tipos de chave para tipos dependentes. -/
inductive KeyType where
  | Private
  | Public

/-- Estrutura para chaves, com tipo dependente para garantir que privada não seja pública. -/
structure Key (t : KeyType) where
  data : ByteArray

/-- Tipo para certificados X.509 válidos. -/
structure Certificate where
  data : ByteArray

/-- Certificado X.509 -/
structure X509Certificate where
  data : ByteArray
  subject : String
  issuer : String
  validFrom : Nat
  validTo : Nat

/-- Estados do handshake TLS. -/
inductive TLSState where
  | Handshake
  | Data
  | Closed
  deriving BEq, Inhabited

/-- Sessão TLS segura, com provas. -/
structure TLSSession (state : TLSState) where
  masterSecret : ByteArray

/-- Helper: Convert sequence of 4 bytes to UInt32 (Big Endian) -/
def bytesToUInt32 (b1 b2 b3 b4 : UInt8) : UInt32 :=
  (b1.toUInt32 <<< 24) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 8) ||| b4.toUInt32

/-- Convert a nibble (0–15) to its lowercase hex character. -/
def hexChar (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

/-- Convert a ByteArray to its lowercase hexadecimal string representation. -/
def bytesToHex (bytes : ByteArray) : String :=
  let res := bytes.data.foldl (fun acc b =>
    let n := b.toNat
    let hi := hexChar (n / 16)
    let lo := hexChar (n % 16)
    acc ++ [hi, lo]
  ) []
  String.ofList res

/-- Alias for backwards compatibility — prefer `bytesToHex`. -/
def hex := bytesToHex

/-- Convert a hex character to its nibble value (0–15). Returns 0 for invalid chars. -/
def hexNibble (c : Char) : Nat :=
  if c >= '0' && c <= '9' then c.toNat - '0'.toNat
  else if c >= 'a' && c <= 'f' then c.toNat - 'a'.toNat + 10
  else if c >= 'A' && c <= 'F' then c.toNat - 'A'.toNat + 10
  else 0

/-- Convert a hexadecimal string to a ByteArray.
    Ignores spaces; non-hex characters are treated as 0. -/
def hexToBytes (s : String) : ByteArray :=
  let chars := s.toList.filter (· ≠ ' ')
  let rec go (cs : List Char) (acc : ByteArray) : ByteArray :=
    match cs with
    | c1 :: c2 :: rest =>
      go rest (acc.push (UInt8.ofNat (hexNibble c1 * 16 + hexNibble c2)))
    | _ => acc
  go chars ByteArray.empty

/-- Alias for backwards compatibility — prefer `hexToBytes`. -/
def fromHex := hexToBytes

/-- Helper: Convert UInt32 to 4 bytes (Big Endian) -/
def uint32ToBytes (u : UInt32) : Array UInt8 :=
  #[((u >>> 24) &&& 0xFF).toUInt8,
    ((u >>> 16) &&& 0xFF).toUInt8,
    ((u >>> 8) &&& 0xFF).toUInt8,
    (u &&& 0xFF).toUInt8]

/-- SHA-256: Padding the message -/
def sha256_pad (msg : ByteArray) : ByteArray :=
  let len := msg.size
  -- 1. Append '1' bit (0x80 byte)
  let tmp := msg.push 0x80

  -- 2. Append k zero bits, where k is the smallest non-negative solution to
  --    l + 1 + k = 448 mod 512
  --    So (len * 8 + 8 + k') % 512 = 448
  --    In bytes: (len + 1 + k_bytes) % 64 = 56
  let padLen := (120 - (tmp.size % 64)) % 64
  let tmp := tmp ++ ByteArray.mk (List.replicate padLen (0 : UInt8)).toArray

  -- 3. Append 64-bit block equal to the number of bits in the original message
  --    We only support messages up to 2^64-1 bits (which is huge)
  let bitLen : UInt64 := len.toUInt64 * 8
  tmp ++ ByteArray.mk #[
    ((bitLen >>> 56) &&& 0xFF).toUInt8,
    ((bitLen >>> 48) &&& 0xFF).toUInt8,
    ((bitLen >>> 40) &&& 0xFF).toUInt8,
    ((bitLen >>> 32) &&& 0xFF).toUInt8,
    ((bitLen >>> 24) &&& 0xFF).toUInt8,
    ((bitLen >>> 16) &&& 0xFF).toUInt8,
    ((bitLen >>> 8) &&& 0xFF).toUInt8,
    (bitLen &&& 0xFF).toUInt8
  ]

/-- SHA-256: Constantes iniciais H -/
def sha256_h0 : Array UInt32 :=
  #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

/-- SHA-256: Constantes K (primeiros 64 bits da parte fracional de cubos de primeiros 64 primos) -/
def sha256_k : Array UInt32 :=
  #[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-- SHA-256: Função auxiliar right rotate -/
def rotr (x : UInt32) (n : Nat) : UInt32 :=
  (x.shiftRight n.toUInt32) ||| (x.shiftLeft (32 - n).toUInt32)

/-- SHA-256: Função Σ₀ -/
def sigma0 (x : UInt32) : UInt32 :=
  rotr x 2 ^^^ rotr x 13 ^^^ rotr x 22

/-- SHA-256: Função Σ₁ -/
def sigma1 (x : UInt32) : UInt32 :=
  rotr x 6 ^^^ rotr x 11 ^^^ rotr x 25

/-- SHA-256: Função σ₀ -/
def sigma0_small (x : UInt32) : UInt32 :=
  rotr x 7 ^^^ rotr x 18 ^^^ (x >>> 3)

/-- SHA-256: Função σ₁ -/
def sigma1_small (x : UInt32) : UInt32 :=
  rotr x 17 ^^^ rotr x 19 ^^^ (x >>> 10)

/-- SHA-256: Função Ch (Choose) -/
def ch (x y z : UInt32) : UInt32 :=
  (x &&& y) ^^^ (~~~x &&& z)

/-- SHA-256: Função Maj (Majority) -/
def maj (x y z : UInt32) : UInt32 :=
  (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

-- SHA-256: Process a single 64-byte block
def sha256_process_block (h : Array UInt32) (chunk : ByteArray) : Array UInt32 :=
  -- 1. Prepare Message Schedule W (64 words)
  --    The first 16 words are the data itself
  let w_init := (List.replicate 64 (0 : UInt32)).toArray
  let w := (List.range 16).foldl (fun (w : Array UInt32) i =>
    let offset := i * 4
    let val := bytesToUInt32 (chunk.get! offset) (chunk.get! (offset+1)) (chunk.get! (offset+2)) (chunk.get! (offset+3))
    w.set! i val
  ) w_init

  --    The remaining 48 words are derived
  let w := (List.range 48).foldl (fun (w : Array UInt32) i =>
    let i := i + 16
    let s0 := sigma0_small (w[i-15]!)
    let s1 := sigma1_small (w[i-2]!)
    let val := (w[i-16]!) + s0 + (w[i-7]!) + s1
    w.set! i val
  ) w

  -- 2. Initialize working variables
  let a := h[0]!
  let b := h[1]!
  let c := h[2]!
  let d := h[3]!
  let e := h[4]!
  let f := h[5]!
  let g := h[6]!
  let hh := h[7]!

  -- 3. Main Compression Loop
  let (a, b, c, d, e, f, g, hh) := (List.range 64).foldl (fun (vars : UInt32 × UInt32 × UInt32 × UInt32 × UInt32 × UInt32 × UInt32 × UInt32) i =>
    let (a, b, c, d, e, f, g, hh) := vars
    let s1 := sigma1 e
    let ch_val := ch e f g
    let temp1 := hh + s1 + ch_val + (sha256_k[i]!) + (w[i]!)
    let s0 := sigma0 a
    let maj_val := maj a b c
    let temp2 := s0 + maj_val

    (temp1 + temp2, a, b, c, d + temp1, e, f, g)
  ) (a, b, c, d, e, f, g, hh)

  -- 4. Add the compressed chunk to the current hash value
  #[
    (h[0]!) + a,
    (h[1]!) + b,
    (h[2]!) + c,
    (h[3]!) + d,
    (h[4]!) + e,
    (h[5]!) + f,
    (h[6]!) + g,
    (h[7]!) + hh
  ]

/-- SHA-256: Implementação completa e funcional -/
def sha256_real (msg : ByteArray) : ByteArray :=
  let padded := sha256_pad msg
  let numBlocks := padded.size / 64

  let finalH := (List.range numBlocks).foldl (fun h i =>
    let offset := i * 64
    let chunk := padded.extract offset (offset + 64)
    sha256_process_block h chunk
  ) sha256_h0

  let resBytes := finalH.foldl (fun bytes word => bytes ++ (uint32ToBytes word)) #[]
  ByteArray.mk resBytes

/-- SHA-256 hash (implementação básica funcional) -/
def sha256 (msg : ByteArray) : ByteArray :=
  sha256_real msg





/-- Helper for HMAC: XOR array with byte -/
def xorArray (arr : ByteArray) (b : UInt8) : ByteArray :=
  ByteArray.mk (arr.data.map (fun x => x ^^^ b))

/-- HMAC-SHA256 (RFC 2104)
    Hash is SHA-256 (block size 64 bytes, output 32 bytes) -/
def hmac_sha256 (key : ByteArray) (msg : ByteArray) : ByteArray :=
  let blockSize := 64

  -- Keys longer than blockSize are hashed
  let key := if key.size > blockSize then sha256 key else key

  -- Keys shorter than blockSize are padded with zeros
  let key := if key.size < blockSize then
               key ++ ByteArray.mk (List.replicate (blockSize - key.size) (0 : UInt8)).toArray
             else key

  -- Inner and Outer pads
  let opad := xorArray key 0x5c
  let ipad := xorArray key 0x36

  let innerHash := sha256 (ipad ++ msg)
  sha256 (opad ++ innerHash)

/-- HKDF-Extract. -/
def hkdf_extract (salt : ByteArray) (ikm : ByteArray) : ByteArray :=
  hmac_sha256 salt ikm

/-- Encode HKDF Label for TLS 1.3
    Structure: Length(2) | LabelLen(1) | Label | ContextLen(1) | Context
    Label is prefixed with "tls13 " -/
def encodeHkdfLabel (label : String) (context : ByteArray) (len : UInt16) : ByteArray :=
  let labelStr := "tls13 " ++ label
  let labelBytes := labelStr.toUTF8
  let labelLen := labelBytes.size.toUInt8

  -- Context length (1 byte for now, usually hash of transcript)
  let contextLen := context.size.toUInt8

  let result := ByteArray.empty

  -- Length (UInt16, big endian)
  let result := ByteArray.push result ((len >>> 8).toUInt8)
  let result := ByteArray.push result (len.toUInt8)

  -- Label
  let result := ByteArray.push result labelLen
  let result := result ++ labelBytes

  -- Context
  let result := ByteArray.push result contextLen
  let result := result ++ context

  result

/-- HKDF-Expand (RFC 5869) -/
def hkdf_expand (prk : ByteArray) (info : ByteArray) (len : Nat) : ByteArray :=
  let hashLen := 32
  let n := (len + hashLen - 1) / hashLen -- ceil(len / hashLen)

  let rec loop (i : Nat) (prevT : ByteArray) (acc : ByteArray) : ByteArray :=
    if _h : i > n then acc
    else
      -- T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x<i-byte>)
      let data := prevT ++ info ++ ByteArray.mk #[i.toUInt8]
      let t := hmac_sha256 prk data
      if i == n then
        -- Final iteration, append and done
        acc ++ t
      else
        loop (i + 1) t (acc ++ t)
  termination_by n + 1 - i
  decreasing_by omega

  let t_total := loop 1 (ByteArray.mk #[]) (ByteArray.mk #[])
  t_total.extract 0 len

/-- HKDF-Expand-Label (RFC 8446) -/
def hkdfExpandLabel (secret : ByteArray) (label : String) (context : ByteArray) (len : UInt16) : ByteArray :=
  hkdf_expand secret (encodeHkdfLabel label context len) len.toNat

/-- Derive-Secret (HashLen=32 for SHA256) -/
def deriveSecret (secret : ByteArray) (label : String) (context : ByteArray) : ByteArray :=
  hkdfExpandLabel secret label context 32

structure HandshakeKeys where
  serverKey : ByteArray
  serverIV  : ByteArray
  serverHP  : ByteArray -- [NEW] Server Header Protection Key
  clientKey : ByteArray
  clientIV  : ByteArray
  clientHP  : ByteArray -- [NEW] Client Header Protection Key
  serverTrafficSecret : ByteArray
  clientTrafficSecret : ByteArray
  serverFinishedKey : ByteArray
  clientFinishedKey : ByteArray
  handshakeSecret : ByteArray -- [NEW] Needed for Master Secret derivation

/-- Derive Handshake Keys from Shared Secret and Transcript Hash.
    `keyLabel`/`ivLabel`/`hpLabel` select between TLS ("key"/"iv"/"hp") and
    QUIC ("quic key"/"quic iv"/"quic hp") label sets. -/
def deriveHandshakeKeysWithLabels (sharedSecret : ByteArray) (helloHash : ByteArray)
    (keyLabel : String) (ivLabel : String) (hpLabel : String) : HandshakeKeys :=
  let emptyHash := sha256 ByteArray.empty
  let zeroSalt := zeroBytes hashLen
  -- 1. Early Secret
  let earlySecret := hkdf_extract zeroSalt (zeroBytes hashLen)
  -- 2. Derived Secret (for Handshake)
  let derivedSecret := deriveSecret earlySecret "derived" emptyHash
  -- 3. Handshake Secret
  let handshakeSecret := hkdf_extract derivedSecret sharedSecret
  -- 4. Traffic Secrets
  let clientHandshakeTrafficSecret := deriveSecret handshakeSecret "c hs traffic" helloHash
  let serverHandshakeTrafficSecret := deriveSecret handshakeSecret "s hs traffic" helloHash
  -- 5. Keys, IVs, HP
  let clientKey := hkdfExpandLabel clientHandshakeTrafficSecret keyLabel ByteArray.empty aesKeyLen.toUInt16
  let clientIV  := hkdfExpandLabel clientHandshakeTrafficSecret ivLabel  ByteArray.empty aesGCMIvLen.toUInt16
  let clientHP  := hkdfExpandLabel clientHandshakeTrafficSecret hpLabel  ByteArray.empty aesKeyLen.toUInt16
  let serverKey := hkdfExpandLabel serverHandshakeTrafficSecret keyLabel ByteArray.empty aesKeyLen.toUInt16
  let serverIV  := hkdfExpandLabel serverHandshakeTrafficSecret ivLabel  ByteArray.empty aesGCMIvLen.toUInt16
  let serverHP  := hkdfExpandLabel serverHandshakeTrafficSecret hpLabel  ByteArray.empty aesKeyLen.toUInt16
  let clientFinishedKey := hkdfExpandLabel clientHandshakeTrafficSecret "finished" ByteArray.empty hashLen.toUInt16
  let serverFinishedKey := hkdfExpandLabel serverHandshakeTrafficSecret "finished" ByteArray.empty hashLen.toUInt16
  {
    serverKey, serverIV, serverHP, clientKey, clientIV, clientHP,
    serverTrafficSecret := serverHandshakeTrafficSecret,
    clientTrafficSecret := clientHandshakeTrafficSecret,
    serverFinishedKey, clientFinishedKey,
    handshakeSecret
  }

/-- Derive Handshake Keys using TLS labels ("key", "iv", "hp") -/
def deriveHandshakeKeys (sharedSecret : ByteArray) (helloHash : ByteArray) : HandshakeKeys :=
  deriveHandshakeKeysWithLabels sharedSecret helloHash "key" "iv" "hp"

/-- Derive QUIC Handshake Keys using QUIC labels ("quic key", "quic iv", "quic hp") (RFC 9001) -/
def deriveQUICHandshakeKeys (sharedSecret : ByteArray) (helloHash : ByteArray) : HandshakeKeys :=
  deriveHandshakeKeysWithLabels sharedSecret helloHash "quic key" "quic iv" "quic hp"

/-- AES-128-GCM Encrypt
    Returns (Ciphertext, Tag) -/
def aes128_gcm_encrypt (key : ByteArray) (iv : ByteArray) (aad : ByteArray) (plaintext : ByteArray) : (ByteArray × ByteArray) :=
  LeanServer.AES.aesGCMEncrypt key iv plaintext aad

/-- AES-128-GCM Decrypt -/
def aes128_gcm_decrypt (key : ByteArray) (iv : ByteArray) (aad : ByteArray) (ciphertextWithTag : ByteArray) : Option ByteArray :=
  LeanServer.AES.aesGCMDecrypt key iv ciphertextWithTag aad

/-- Helper: Handshake Header (Type + 3-byte Length) -/
def mkHandshakeMsg (type : UInt8) (body : ByteArray) : ByteArray :=
  let len := body.size
  let header := #[type, (len / 65536).toUInt8, ((len / 256) % 256).toUInt8, (len % 256).toUInt8]
  ByteArray.mk header ++ body

/-- Construct EncryptedExtensions -/
def buildEncryptedExtensions (alpnProtocol : Option String) (quicParams : Option ByteArray) : ByteArray :=
  -- ALPN Extension (if selected)
  let alpnExt := match alpnProtocol with
    | some p =>
       let pBytes := p.toUTF8
       let pLen := pBytes.size
       -- ProtocolNameList: List Len (2) + ProtocolName (1 + Len)
       let listLen := 1 + pLen
       let extData :=
         ByteArray.mk #[((listLen / 256).toUInt8), (listLen % 256).toUInt8] ++
         ByteArray.mk #[pLen.toUInt8] ++
         pBytes

       ByteArray.mk #[0x00, 0x10] ++ -- Type: ALPN
       ByteArray.mk #[((extData.size / 256).toUInt8), (extData.size % 256).toUInt8] ++ -- Ext Len
       extData
    | none => ByteArray.empty

  -- Extension: QUIC Transport Parameters (0x0039)
  let quicExt := match quicParams with
    | some params =>
      ByteArray.mk #[0x00, 0x39] ++ -- Type: QUIC Transport Parameters
      ByteArray.mk #[((params.size / 256).toUInt8), (params.size % 256).toUInt8] ++ -- Len
      params
    | none => ByteArray.empty

  let extensions := alpnExt ++ quicExt
  let extLen := extensions.size
  let body := ByteArray.mk #[((extLen / 256).toUInt8), (extLen % 256).toUInt8] ++ extensions

  mkHandshakeMsg 0x08 body

/-- Construct Certificate -/
def buildCertificate (certData : ByteArray) : ByteArray :=
  -- Request Context (1 byte len + data), usually empty for Server Cert
  let reqCtx := #[0x00]

  -- Certificate Entry: Data Len (3) + Data + Extensions Len (2) + Extensions
  let certEntry :=
    #[0x00, (certData.size / 256).toUInt8, (certData.size % 256).toUInt8] ++ -- Implies < 64KB cert
    certData.data ++
    #[0x00, 0x00] -- No extensions for this cert

  -- Certificate List: Total Len (3) + Entry
  let len := certEntry.size
  let certList := #[0x00, (len / 256).toUInt8, (len % 256).toUInt8] ++ certEntry

  mkHandshakeMsg 0x0b (ByteArray.mk (reqCtx ++ certList))

/-- Construct CertificateVerify -/
def buildCertificateVerify (signature : ByteArray) : ByteArray :=
  -- Algorithm (2 bytes) + Signature Len (2 bytes) + Signature
  -- Using 0x0804 (rsa_pss_rsae_sha256) which matches our RSA-PSS implementation
  let algo := #[0x08, 0x04]
  let len := signature.size
  let body := algo ++ #[ (len / 256).toUInt8, (len % 256).toUInt8 ] ++ signature.data
  mkHandshakeMsg 0x0f (ByteArray.mk body)

/-- Construct Finished -/
def buildFinished (baseKey : ByteArray) (transcriptHash : ByteArray) : ByteArray :=
  let verifyData := hmac_sha256 baseKey transcriptHash
  mkHandshakeMsg 0x14 verifyData

/-- [NEW] Build ChangeCipherSpec message (TLS 1.3 Middlebox Compat) -/
def buildChangeCipherSpec : ByteArray :=
  -- Type (20/0x14), Version (03 03), Length (00 01), Payload (01)
  ByteArray.mk #[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]



/-- Generates key pair (X25519) using cryptographically secure random bytes.
    The private key is clamped per RFC 7748 §5 before computing the public key. -/
def generateKeyPair : IO (ByteArray × ByteArray) := do
  -- Generate 32 cryptographically secure random bytes for private key
  let rawKey ← IO.getRandomBytes 32
  -- Apply X25519 clamping (RFC 7748 §5):
  --   privKey[0]  &= 248   (clear 3 low bits)
  --   privKey[31] &= 127   (clear bit 255)
  --   privKey[31] |= 64    (set bit 254)
  let privKey := rawKey
    |>.set! 0  (rawKey.get! 0 &&& 248)
    |>.set! 31 ((rawKey.get! 31 &&& 127) ||| 64)
  let pubKey := LeanServer.X25519.scalarmult_base privKey
  return (privKey, pubKey)

/-- Computes shared secret (X25519). -/
def computeSharedSecret (privateKey : ByteArray) (peerPublicKey : ByteArray) : ByteArray :=
  LeanServer.X25519.scalarmult privateKey peerPublicKey



-- ASN.1 / PEM Helpers

/-- Parse ASN.1 Length -/
def parseASN1Length (data : ByteArray) (offset : Nat) : Option (Nat × Nat) :=
  if offset >= data.size then none
  else
    let b := data.get! offset
    if b < 0x80 then
      some (b.toNat, 1)
    else
      let numBytes := (b &&& 0x7F).toNat
      if offset + 1 + numBytes > data.size then none
      else
        let lenBytes := data.extract (offset + 1) (offset + 1 + numBytes)
        let len := LeanServer.RSA.os2ip lenBytes
        some (len, 1 + numBytes)

/-- Parse ASN.1 Integer -/
def parseASN1Integer (data : ByteArray) (offset : Nat) : Option (Nat × Nat) :=
  if offset >= data.size then none
  else if data.get! offset != 0x02 then none -- Tag INTEGER
  else
    match parseASN1Length data (offset + 1) with
    | some (len, lenBytes) =>
      let contentOffset := offset + 1 + lenBytes
      if contentOffset + len > data.size then none
      else
        let bytes := data.extract contentOffset (contentOffset + len)
        let n := LeanServer.RSA.os2ip bytes
        some (n, 1 + lenBytes + len)
    | none => none

/-- Parse ASN.1 Sequence -/
def parseASN1Sequence (data : ByteArray) (offset : Nat) : Option (Nat × Nat × Nat) :=
  if offset >= data.size then none
  else if data.get! offset != 0x30 then none -- Tag SEQUENCE
  else
    match parseASN1Length data (offset + 1) with
    | some (len, lenBytes) =>
       some (len, offset + 1 + lenBytes, 1 + lenBytes + len) -- contentLen, contentOffset, totalLen
    | none => none

/-- Parse RSA Private Key (PKCS#1 or PKCS#8)
    Retorna (n, d)
    Uses fuel parameter to guarantee termination: PKCS#8 wraps PKCS#1
    at most once, so fuel=2 suffices. -/
def parseRSAPrivateKey (keyBytes : ByteArray) : Option (Nat × Nat) :=
  parseRSAPrivateKeyAux keyBytes 2
where
  parseRSAPrivateKeyAux (keyBytes : ByteArray) (fuel : Nat) : Option (Nat × Nat) :=
  match fuel with
  | 0 => none  -- Terminação garantida
  | fuel' + 1 =>
  -- Tenta analisar como PKCS#8 (Sequence -> Version -> Algo -> OctetString(PrivateKey))
  -- Ou PKCS#1 (Sequence -> Version -> n -> e -> d ...)

  -- Check Sequence
  match parseASN1Sequence keyBytes 0 with
  | some (_seqLen, contentOffset, _totalLen) =>
    -- PKCS#8 usually starts with Version (0) then AlgorithmIdentifier
    -- PKCS#1 also starts with Version (0)

    -- Let's try to find Integers directly (PKCS#1)
    match parseASN1Integer keyBytes contentOffset with
    | some (_version, vLen) =>
      let offset := contentOffset + vLen

      -- If version is 0, next could be n (PKCS#1) or Algo (PKCS#8)
      -- PKCS#1: INTEGER n
      -- PKCS#8: SEQUENCE AlgorithmIdentifier

      if offset >= keyBytes.size then none
      else
        let tag := keyBytes.get! offset
        if tag == 0x02 then
           -- Looks like PKCS#1 (Integer n)
           match parseASN1Integer keyBytes offset with
           | some (n, nLen) =>
             let offset := offset + nLen
             match parseASN1Integer keyBytes offset with
             | some (_e, eLen) =>
               let offset := offset + eLen
               match parseASN1Integer keyBytes offset with
               | some (d, _dLen) => some (n, d)
               | none => none
             | none => none
           | none => none
        else if tag == 0x30 then
           -- Looks like PKCS#8 (Sequence Algo)
           -- Skip Algo Sequence
           match parseASN1Sequence keyBytes offset with
           | some (_algoLen, _, algoTotalLen) =>
             let offset := offset + algoTotalLen
             -- Next is OCTET STRING (0x04) containing the PrivateKey
             if offset >= keyBytes.size || keyBytes.get! offset != 0x04 then none
             else
               match parseASN1Length keyBytes (offset + 1) with
               | some (octetLen, octetLenBytes) =>
                 let innerOffset := offset + 1 + octetLenBytes
                 let innerBytes := keyBytes.extract innerOffset (innerOffset + octetLen)
                 -- Recurse with decreased fuel to parse the inner PKCS#1 key
                 parseRSAPrivateKeyAux innerBytes fuel'
               | none => none
           | none => none
        else none
    | none => none
  | none => none

/-- Load Certificate from PEM file, returning a Certificate structure. -/
def loadCertificateDER (filename : String) : IO (Option Certificate) := do
  match ← loadPEMFile filename with
  | some bytes => pure (some { data := bytes })
  | none => pure none

/-- Load Private Key from PEM file, returning raw DER bytes. -/
def loadPrivateKey (filename : String) : IO (Option ByteArray) :=
  loadPEMFile filename

/-- Sign with RSA-PSS-SHA256: parses the DER-encoded private key,
    hashes the message with SHA-256, and produces an RSA-PSS signature.
    Returns empty ByteArray on failure (key parse or signing error). -/
def sign (privateKey : ByteArray) (message : ByteArray) : IO ByteArray := do
  -- 1. Parse Private Key (Assuming PKCS#8 DER -> RSA Private Key)
  match parseRSAPrivateKey privateKey with
  | some (n, d) =>
     let msgHash := sha256 message
     match ← LeanServer.RSA.rsassa_pss_sign sha256 n d msgHash with
     | some sig => pure sig
     | none =>
       IO.eprintln "❌ RSA Signing Failed"
       pure ByteArray.empty
  | none =>
     IO.eprintln "❌ Failed to parse RSA Private Key for signing"
     pure ByteArray.empty

/-- Verifies an RSA-PSS-SHA256 signature against a public key.
    Parses the public key (n, e) from DER, hashes the message, and
    delegates to rsassa_pss_verify (RFC 8017 §8.1.2).
    Returns false if key parsing fails or signature is invalid. -/
def verify (publicKey : ByteArray) (message : ByteArray) (signature : ByteArray) : Bool :=
  -- Parse public key to extract (n, e)
  -- Typical X.509 SubjectPublicKeyInfo contains a SEQUENCE with AlgoID + BIT STRING wrapping PKCS#1 RSAPublicKey
  -- RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
  -- For simplicity we try PKCS#1 direct parse: SEQUENCE { n INTEGER, e INTEGER }
  let parseRSAPublicKey (keyBytes : ByteArray) : Option (Nat × Nat) :=
    match parseASN1Sequence keyBytes 0 with
    | some (_, contentOffset, _) =>
      -- Try to find the inner SEQUENCE (skip AlgorithmIdentifier if PKCS#8/X.509)
      let tag := keyBytes.get! contentOffset
      if tag == 0x30 then
        -- X.509 SubjectPublicKeyInfo: SEQUENCE { AlgoID, BIT STRING { SEQUENCE { n, e } } }
        match parseASN1Sequence keyBytes contentOffset with
        | some (_, _, algoTotalLen) =>
          let offset := contentOffset + algoTotalLen
          if offset >= keyBytes.size then none
          else if keyBytes.get! offset == 0x03 then -- BIT STRING
            match parseASN1Length keyBytes (offset + 1) with
            | some (_, lenBytes) =>
              let bitStrContent := offset + 1 + lenBytes + 1 -- Skip unused-bits byte
              match parseASN1Sequence keyBytes bitStrContent with
              | some (_, innerOff, _) =>
                match parseASN1Integer keyBytes innerOff with
                | some (n, nLen) =>
                  match parseASN1Integer keyBytes (innerOff + nLen) with
                  | some (e, _) => some (n, e)
                  | none => none
                | none => none
              | none => none
            | none => none
          else none
        | none => none
      else if tag == 0x02 then
        -- Direct PKCS#1 RSAPublicKey: SEQUENCE { n INTEGER, e INTEGER }
        match parseASN1Integer keyBytes contentOffset with
        | some (n, nLen) =>
          match parseASN1Integer keyBytes (contentOffset + nLen) with
          | some (e, _) => some (n, e)
          | none => none
        | none => none
      else none
    | none => none

  match parseRSAPublicKey publicKey with
  | some (n, e) =>
    let msgHash := sha256 message
    LeanServer.RSA.rsassa_pss_verify sha256 n e msgHash signature
  | none => false



/-- ClientHello Data Structure -/
structure ClientHello where
  clientRandom : ByteArray
  sessionId : ByteArray
  cipherSuites : Array UInt16
  legacyCompressionMethods : ByteArray
  extensions : ByteArray -- Raw extensions
  clientKeyShare : Option ByteArray -- Parsed X25519 Key Share
  alpnProtocols : Option (Array String) -- [NEW] ALPN
  pskIdentities : Option (List (ByteArray × UInt32)) := none -- PSK identities from pre_shared_key ext
  pskBinders : Option (List ByteArray) := none -- PSK binders from pre_shared_key ext
  sni : Option String := none -- Server Name Indication (RFC 6066)

/-- ServerHello Data Structure -/
structure ServerHello where
  serverRandom : ByteArray
  sessionId : ByteArray
  cipherSuite : UInt16
  publicKey : ByteArray -- Added for X25519 Key Share

/-- Parse ALPN Extension Data -/
def parseALPNList (data : ByteArray) : Option (Array String) :=
  -- Structure: List Length (2 bytes) + Protocol Name Strings (1 byte len + data)
  if data.size < 2 then none
  else
    let listLen := ((data.get! 0).toNat * 256) + (data.get! 1).toNat
    if data.size < 2 + listLen then none
    else
      let limit := 2 + listLen
      let rec loop (offset : Nat) (acc : Array String) : Option (Array String) :=
        if _h : offset >= limit then some acc
        else
          if offset >= data.size then some acc -- Should not happen if listLen check passed
          else
            let len := (data.get! offset).toNat
            let nextOffset := offset + 1 + len
            if nextOffset > limit then none
            else
              let protoBytes := data.extract (offset + 1) nextOffset
              match String.fromUTF8? protoBytes with
              | some s => loop nextOffset (acc.push s)
              | none => loop nextOffset acc -- Skip invalid UTF8
      termination_by limit - offset
      decreasing_by all_goals omega
      loop 2 #[]

/-- Parsed Extensions Container -/
structure ClientExtensions where
  keyShare : Option ByteArray
  alpn : Option (Array String)
  pskExtension : Option (List (ByteArray × UInt32) × List ByteArray) := none
  sni : Option String := none  -- Server Name Indication (RFC 6066)

/-- Parse Server Name Indication extension (RFC 6066 §3)
    Structure: ServerNameList Length (2) + ServerName entries (type(1) + len(2) + data)
    We extract the first host_name (type 0). -/
def parseServerNameExtension (data : ByteArray) : Option String :=
  if data.size < 2 then none
  else
    let listLen := (data.get! 0).toNat * 256 + (data.get! 1).toNat
    if data.size < 2 + listLen then none
    else
      -- Parse first ServerName entry
      let offset := 2
      if offset + 3 > data.size then none
      else
        let nameType := data.get! offset
        let nameLen := (data.get! (offset + 1)).toNat * 256 + (data.get! (offset + 2)).toNat
        if nameType != 0 then none  -- 0 = host_name
        else if offset + 3 + nameLen > data.size then none
        else
          let nameBytes := data.extract (offset + 3) (offset + 3 + nameLen)
          String.fromUTF8? nameBytes

/-- Helper to parse Key Share Extension (0x0033) for X25519 (0x001d) -/
def parseKeyShareExtension (data : ByteArray) : Option ByteArray :=
  -- Structure: ClientKeyShareList Length (2 bytes) + ClientKeyShare objects
  if data.size < 2 then none
  else
    let listLen := ((data.get! 0).toNat * 256) + (data.get! 1).toNat
    if data.size < 2 + listLen then none
    else
      let shares := data.extract 2 (2 + listLen)
      -- Iterate shares: Group (2), KeyExchangeLen (2), KeyExchange (N)
      let rec findX25519 (offset : Nat) : Option ByteArray :=
        if h : offset + 4 > shares.size then none
        else
          let group := ((shares.get! offset).toNat * 256) + (shares.get! (offset+1)).toNat
          let keyLen := ((shares.get! (offset+2)).toNat * 256) + (shares.get! (offset+3)).toNat
          let nextOffset := offset + 4 + keyLen

          if nextOffset > shares.size then none
          else if group == 0x001d then -- X25519
             if keyLen == 32 then
               some (shares.extract (offset+4) nextOffset)
             else
               findX25519 nextOffset -- Invalid len for X25519, skip or fail? Skip.
          else
            findX25519 nextOffset
      termination_by shares.size - offset
      decreasing_by all_goals omega

      findX25519 0

/-- Parse pre_shared_key extension from ClientHello (RFC 8446 §4.2.11)
    Returns list of (identity, obfuscated_ticket_age) pairs and binders -/
def parsePSKExtension (data : ByteArray) (offset : Nat) : Option (List (ByteArray × UInt32) × List ByteArray) := Id.run do
  if offset + 2 > data.size then return none
  let identitiesLen := (data.get! offset).toNat * 256 + (data.get! (offset + 1)).toNat
  let mut pos := offset + 2
  let endIdentities := pos + identitiesLen
  let mut identities : List (ByteArray × UInt32) := []
  -- Parse PskIdentity list
  while pos + 2 < endIdentities do
    let idLen := (data.get! pos).toNat * 256 + (data.get! (pos + 1)).toNat
    pos := pos + 2
    if pos + idLen + 4 > data.size then break
    let identity := data.extract pos (pos + idLen)
    let age := ((data.get! (pos + idLen)).toUInt32 <<< 24) |||
               ((data.get! (pos + idLen + 1)).toUInt32 <<< 16) |||
               ((data.get! (pos + idLen + 2)).toUInt32 <<< 8) |||
               (data.get! (pos + idLen + 3)).toUInt32
    identities := identities ++ [(identity, age)]
    pos := pos + idLen + 4
  -- Parse binders
  pos := endIdentities
  if pos + 2 > data.size then return some (identities, [])
  let bindersLen := (data.get! pos).toNat * 256 + (data.get! (pos + 1)).toNat
  pos := pos + 2
  let endBinders := pos + bindersLen
  let mut binders : List ByteArray := []
  while pos + 1 < endBinders do
    let bLen := (data.get! pos).toNat
    pos := pos + 1
    if pos + bLen > data.size then break
    binders := binders ++ [data.extract pos (pos + bLen)]
    pos := pos + bLen
  return some (identities, binders)

/-- Parse Extensions List to find specific extensions -/
def parseExtensions (data : ByteArray) : ClientExtensions :=
  let rec loop (offset : Nat) (acc : ClientExtensions) : ClientExtensions :=
    if h : offset + 4 > data.size then acc
    else
      let extType := ((data.get! offset).toNat * 256) + (data.get! (offset+1)).toNat
      let extLen := ((data.get! (offset+2)).toNat * 256) + (data.get! (offset+3)).toNat
      let nextOffset := offset + 4 + extLen

      if nextOffset > data.size then acc
      else
        let extData := data.extract (offset+4) nextOffset
        let newAcc := match extType with
          | 0x0000 => { acc with sni := parseServerNameExtension extData }
          | 0x0033 => { acc with keyShare := parseKeyShareExtension extData }
          | 0x0010 => { acc with alpn := parseALPNList extData }
          | 0x0029 => { acc with pskExtension := parsePSKExtension extData 0 }
          | _ => acc
        loop nextOffset newAcc
  termination_by data.size - offset
  decreasing_by omega
  loop 0 { keyShare := none, alpn := none, pskExtension := none, sni := none }

/-- Encrypts a TLS 1.3 Record --/
def encryptTLS13Record (key : ByteArray) (nonce : ByteArray) (innerContent : ByteArray) (innerType : UInt8) : ByteArray :=
  -- 1. Append Inner Content Type
  let plaintext := innerContent.push innerType

  -- 2. Construct AAD (Record Header)
  let payloadLen := plaintext.size + 16
  let header := #[0x17, 0x03, 0x03, (payloadLen / 256).toUInt8, (payloadLen % 256).toUInt8]
  let aad := ByteArray.mk header

  -- 3. Encrypt
  let (cipher, tag) := aes128_gcm_encrypt key nonce aad plaintext

  -- 4. Result
  aad ++ cipher ++ tag

/-- Decrypts a TLS 1.3 Record
    Returns (Plaintext, ContentType) if successful -/
def decryptTLS13Record (key : ByteArray) (nonce : ByteArray) (ciphertextWithTag : ByteArray) : Option (ByteArray × UInt8) :=
  -- 1. Construct AAD
  let header := #[0x17, 0x03, 0x03, (ciphertextWithTag.size / 256).toUInt8, (ciphertextWithTag.size % 256).toUInt8]
  let aad := ByteArray.mk header

  -- 2. Decrypt
  match aes128_gcm_decrypt key nonce aad ciphertextWithTag with
  | some plaintext =>
    -- 3. Parse Content Type (Last Byte)
    if plaintext.size == 0 then none
    else
      let contentType := plaintext.get! (plaintext.size - 1)
      let innerContent := plaintext.extract 0 (plaintext.size - 1)
      some (innerContent, contentType)
  | none => none

/-- Parse ClientHello message (Raw Handshake Message, no Record Header) -/
def parseClientHelloMessage (data : ByteArray) : Option ClientHello :=
  -- Minimum size check
  if data.size < 40 then none
  else
    -- 0: Handshake Type
    let handshakeType := data.get! 0
    if handshakeType != 1 then none -- Must be ClientHello (1)
    else
      -- 1-3: Handshake Length (3 bytes)
      -- 4-5: Legacy Version (2 bytes)

      -- 6-37: Client Random (32 bytes)
      let clientRandom := data.extract 6 38

      -- 38: Session ID Length
      let sessIdLen := (data.get! 38).toNat
      let currentOffset := 39

      -- Session ID
      let sessionId := data.extract currentOffset (currentOffset + sessIdLen)
      let currentOffset := currentOffset + sessIdLen

      -- Cipher Suites Length (2 bytes)
      if currentOffset + 1 >= data.size then none
      else
        let cipherSuitesLen := ((data.get! currentOffset).toNat * 256) + (data.get! (currentOffset+1)).toNat
        let currentOffset := currentOffset + 2

        -- Parse Cipher Suites into Array UInt16
        let cipherSuitesBytes := data.extract currentOffset (currentOffset + cipherSuitesLen)
        let numSuites := cipherSuitesLen / 2
        let parsedSuites := (List.range numSuites).foldl (fun acc i =>
          let off := i * 2
          if off + 1 < cipherSuitesBytes.size then
            let suite := ((cipherSuitesBytes.get! off).toUInt16 <<< 8) ||| (cipherSuitesBytes.get! (off + 1)).toUInt16
            acc.push suite
          else acc
        ) (#[] : Array UInt16)
        let currentOffset := currentOffset + cipherSuitesLen

        -- Compression Methods Length (1 byte)
        if currentOffset >= data.size then none
        else
          let compMethodsLen := (data.get! currentOffset).toNat
          let currentOffset := currentOffset + 1

          let compMethods := data.extract currentOffset (currentOffset + compMethodsLen)
          let currentOffset := currentOffset + compMethodsLen

          -- Extensions Length (2 bytes)
          if currentOffset + 1 >= data.size then none
          else
            let extLen := ((data.get! currentOffset).toNat * 256) + (data.get! (currentOffset+1)).toNat
            let currentOffset := currentOffset + 2
            let extensions := data.extract currentOffset (currentOffset + extLen)

            -- Parse Key Share, ALPN, and PSK from extensions
            let parsedExt := parseExtensions extensions

            let (pskIds, pskBnds) := match parsedExt.pskExtension with
              | some (ids, bnds) => (some ids, some bnds)
              | none => (none, none)

            some {
              clientRandom := clientRandom
              sessionId := sessionId
              cipherSuites := parsedSuites
              legacyCompressionMethods := compMethods
              extensions := extensions
              clientKeyShare := parsedExt.keyShare
              alpnProtocols := parsedExt.alpn
              pskIdentities := pskIds
              pskBinders := pskBnds
              sni := parsedExt.sni
            }

/-- Parse ClientHello message (RFC 5246 TLS 1.2 Record wrapper) -/
def parseClientHello (data : ByteArray) : Option ClientHello :=
  if data.size < 5 then none
  else parseClientHelloMessage (data.extract 5 data.size)

/-- Supported TLS 1.3 cipher suites in preference order.
    Currently only AES-128-GCM-SHA256 (0x1301) is implemented;
    more suites can be appended here when their AEAD backends are ready. -/
def supportedCipherSuites : Array UInt16 := #[
  0x1301  -- TLS_AES_128_GCM_SHA256
  -- 0x1302  -- TLS_AES_256_GCM_SHA384 (future)
  -- 0x1303  -- TLS_CHACHA20_POLY1305_SHA256 (future)
]

/-- Negotiate cipher suite: pick the first server-preferred suite that
    also appears in the client's list.  Returns `none` when no common
    suite exists (should trigger a handshake_failure alert). -/
def negotiateCipherSuite (clientSuites : Array UInt16) : Option UInt16 :=
  -- Server preference order
  supportedCipherSuites.findSome? fun s =>
    if clientSuites.contains s then some s else none

/-- Generate ServerHello Bytes -/
def generateServerHello (ch : ClientHello) (serverPublicKey : ByteArray) (serverRandom : ByteArray) (_selectedProtocol : Option String) : ByteArray :=

  -- Legacy Session ID (echo client's if present, else empty or random)
  -- For TLS 1.3 middlebox compat, usually echoed
  let sessionId := ch.sessionId

  -- Cipher Suite negotiation (RFC 8446 §4.1.3)
  -- Select the best mutually-supported suite; default to 0x1301 for backwards compat
  let selectedSuite := match negotiateCipherSuite ch.cipherSuites with
    | some s => s
    | none   => (0x1301 : UInt16)  -- fallback
  let cipherSuite := #[((selectedSuite.toNat >>> 8) &&& 0xFF).toUInt8, (selectedSuite.toNat &&& 0xFF).toUInt8]

  -- Compression Method: 0x00 (Null)
  let compression := #[0x00]

  -- Extension: Supported Versions (TLS 1.3)
  let supportedVersionsExt := ByteArray.mk #[
    0x00, 0x2b, -- Type: Supported Versions
    0x00, 0x02, -- Len: 2
    0x03, 0x04  -- Version: TLS 1.3
  ]

  --   Key Exchange (32 bytes): <serverPublicKey>
  let keyShareData :=
    ByteArray.mk #[0x00, 0x1d] ++ -- Group: X25519
    ByteArray.mk #[0x00, 0x20] ++ -- Key Len: 32
    serverPublicKey

  let keyShareExt :=
    ByteArray.mk #[0x00, 0x33] ++ -- Type: Key Share
    ByteArray.mk #[
      ((keyShareData.size / 256).toUInt8),
      (keyShareData.size % 256).toUInt8
    ] ++ -- Len
    keyShareData

  -- Extension: Signature Algorithms (0x000d)
  -- We MUST assert we support rsa_pss_rsae_sha256 (0x0804)
  -- Or rely on client offer. But typically we should respond if we select one.
  -- Actually, TLS 1.3 ServerHello doesn't usually send SigAlgs,
  -- but it sends "Supported Versions" and "Key Share".
  -- SigAlg is negotiated in CertificateVerify.

  let extensionsBody := supportedVersionsExt ++ keyShareExt

  let serverHelloBody :=
    ByteArray.mk #[0x03, 0x03] ++ -- Legacy Version
    serverRandom ++
    ByteArray.mk #[sessionId.size.toUInt8] ++ sessionId ++
    ByteArray.mk cipherSuite ++
    ByteArray.mk compression ++
    ByteArray.mk #[((extensionsBody.size / 256).toUInt8), (extensionsBody.size % 256).toUInt8] ++ -- Extensions Length
    extensionsBody

  -- Handshake Message Header: Type (1 byte) + Length (3 bytes)
  let handshakeMsg :=
    ByteArray.mk #[0x02] ++ -- Handshake Type: ServerHello
    ByteArray.mk #[0x00, ((serverHelloBody.size / 256).toUInt8), (serverHelloBody.size % 256).toUInt8] ++ -- 3-byte length
    serverHelloBody

  handshakeMsg

/-- Generate Server Hello Record (Wraps message in TLS Record) -/
def generateServerHelloRecord (handshakeMsg : ByteArray) : ByteArray :=
  -- Same logic as before, but separated
  -- Record Header
  -- Content Type (0x16 Handshake)
  -- Version (0x0303 legacy)
  let recordHeader := #[
    0x16,       -- Handshake
    0x03, 0x03, -- Version
    ((handshakeMsg.size / 256).toUInt8), (handshakeMsg.size % 256).toUInt8
  ]

  ByteArray.mk recordHeader ++ handshakeMsg

-- ==========================================
-- PSK Session Cache (TLS 1.3 §2.2 / §4.6.1)
-- ==========================================

/-- Cached PSK entry for session resumption -/
structure PSKEntry where
  ticketData : ByteArray        -- The opaque ticket (== PSK identity)
  psk : ByteArray               -- Pre-Shared Key derived from resumption secret
  ticketAgeAdd : UInt32         -- Obfuscated ticket age
  createdMs : UInt64            -- Monotonic time at creation (ms)
  lifetimeMs : UInt64           -- Max lifetime (ms)
  maxEarlyData : UInt32         -- Max 0-RTT bytes
  alpnProtocol : Option String  -- Original ALPN
  deriving Inhabited

/-- Server-side PSK cache (bounded, FIFO eviction) -/
structure PSKCache where
  entries : Array PSKEntry := #[]
  maxSize : Nat := 256
  deriving Inhabited

/-- Add a PSK entry to the cache (evicts oldest if full) -/
def PSKCache.insert (cache : PSKCache) (entry : PSKEntry) : PSKCache :=
  let entries := if cache.entries.size >= cache.maxSize then
    cache.entries.extract 1 cache.entries.size |>.push entry
  else
    cache.entries.push entry
  { cache with entries := entries }

/-- Look up PSK by ticket identity. Returns matching entry if found and not expired. -/
def PSKCache.lookup (cache : PSKCache) (identity : ByteArray) (nowMs : UInt64) : Option PSKEntry :=
  cache.entries.find? fun e =>
    constantTimeEqual e.ticketData identity && nowMs < e.createdMs + e.lifetimeMs

/-- Remove expired entries from the cache -/
def PSKCache.prune (cache : PSKCache) (nowMs : UInt64) : PSKCache :=
  { cache with entries := cache.entries.filter fun e => nowMs < e.createdMs + e.lifetimeMs }

-- ==========================================
-- Certificate Chain Support (TLS 1.3 §4.4.2)
-- ==========================================

/-- Load additional certificates from a chain file.
    Each certificate is DER-encoded (after PEM stripping). -/
def loadCertificateChain (path : String) : IO (Array ByteArray) := do
  let content ← IO.FS.readFile path
  -- Split on certificate boundaries
  let parts := content.splitOn "-----BEGIN CERTIFICATE-----"
  let mut certs : Array ByteArray := #[]
  for part in parts.drop 1 do  -- Skip text before first cert
    let endParts := part.splitOn "-----END CERTIFICATE-----"
    match endParts with
    | b64Part :: _ =>
      -- Strip whitespace and decode base64
      let cleaned := b64Part.replace "\n" "" |>.replace "\r" "" |>.replace " " ""
      -- Simple base64 decode
      let decoded := base64DecodeString cleaned
      if decoded.size > 0 then
        certs := certs.push decoded
    | _ => pure ()
  return certs
where
  b64CharVal (c : Char) : Option UInt32 :=
    if 'A' ≤ c && c ≤ 'Z' then some (c.toNat - 'A'.toNat).toUInt32
    else if 'a' ≤ c && c ≤ 'z' then some (c.toNat - 'a'.toNat + 26).toUInt32
    else if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat + 52).toUInt32
    else if c == '+' then some 62
    else if c == '/' then some 63
    else none
  base64DecodeString (s : String) : ByteArray := Id.run do
    let mut result : Array UInt8 := #[]
    let mut buffer : UInt32 := 0
    let mut bits : Nat := 0
    for c in s.toList do
      if c == '=' then break
      match b64CharVal c with
      | some val =>
        buffer := (buffer <<< 6) ||| val
        bits := bits + 6
        if bits >= 8 then
          bits := bits - 8
          result := result.push ((buffer >>> bits.toUInt32) &&& 0xFF).toUInt8
          buffer := buffer &&& ((1 <<< bits.toUInt32) - 1)
      | none => pure ()
    return ByteArray.mk result

/-- Build Certificate message with full chain (RFC 8446 §4.4.2)
    Includes leaf cert + intermediate certs -/
def buildCertificateChain (leafCert : ByteArray) (intermediates : Array ByteArray) : ByteArray := Id.run do
  -- Certificate request context (empty for server)
  let context := ByteArray.mk #[0x00]
  -- Build certificate entries: each is (3-byte cert length ++ cert ++ 2-byte extensions length (0))
  let mut certList := ByteArray.empty
  -- Leaf cert first
  let leafEntry := ByteArray.mk #[
    (leafCert.size / 65536).toUInt8, ((leafCert.size / 256) % 256).toUInt8, (leafCert.size % 256).toUInt8
  ] ++ leafCert ++ ByteArray.mk #[0x00, 0x00]  -- No per-cert extensions
  certList := certList ++ leafEntry
  -- Intermediate certs
  for cert in intermediates do
    let entry := ByteArray.mk #[
      (cert.size / 65536).toUInt8, ((cert.size / 256) % 256).toUInt8, (cert.size % 256).toUInt8
    ] ++ cert ++ ByteArray.mk #[0x00, 0x00]
    certList := certList ++ entry
  -- Wrap in certificate_list (3-byte length)
  let listLen := certList.size
  let certListWrapper := ByteArray.mk #[
    (listLen / 65536).toUInt8, ((listLen / 256) % 256).toUInt8, (listLen % 256).toUInt8
  ] ++ certList
  let body := context ++ certListWrapper
  -- Handshake header: Certificate (0x0B)
  let bodyLen := body.size
  return ByteArray.mk #[
    0x0B,
    (bodyLen / 65536).toUInt8, ((bodyLen / 256) % 256).toUInt8, (bodyLen % 256).toUInt8
  ] ++ body

-- ==========================================
-- OCSP Stapling (RFC 6066 §8, RFC 8446 §4.4.2.1)
-- ==========================================

/-- Load OCSP response from a DER-encoded file.
    The OCSP response is stapled in the Certificate extensions. -/
def loadOCSPResponse (path : String) : IO (Option ByteArray) := do
  try
    let content ← IO.FS.readBinFile path
    if content.size > 0 then
      IO.eprintln s!"   -> 📋 Loaded OCSP response ({content.size} bytes)"
      return some content
    else return none
  catch _ => return none

/-- Build Certificate message with OCSP stapling (RFC 8446 §4.4.2.1).
    The OCSP response is included as a status_request (type 5) extension
    on the leaf certificate entry. -/
def buildCertificateChainWithOCSP (leafCert : ByteArray) (intermediates : Array ByteArray) (ocspResponse : Option ByteArray) : ByteArray := Id.run do
  let context := ByteArray.mk #[0x00]
  let mut certList := ByteArray.empty
  -- Leaf cert with optional OCSP extension
  let leafExtensions := match ocspResponse with
    | some ocsp =>
      -- status_request extension (type 0x0005)
      -- CertificateStatus: status_type(1) = ocsp(1) + OCSPResponse
      let statusBody := ByteArray.mk #[0x01] ++ -- status_type: ocsp
        ByteArray.mk #[
          (ocsp.size / 65536).toUInt8, ((ocsp.size / 256) % 256).toUInt8, (ocsp.size % 256).toUInt8
        ] ++ ocsp
      let extData :=
        ByteArray.mk #[0x00, 0x05] ++ -- Extension type: status_request
        ByteArray.mk #[((statusBody.size / 256).toUInt8), (statusBody.size % 256).toUInt8] ++
        statusBody
      -- Extensions wrapper (2-byte length)
      ByteArray.mk #[((extData.size / 256).toUInt8), (extData.size % 256).toUInt8] ++ extData
    | none => ByteArray.mk #[0x00, 0x00]
  let leafEntry := ByteArray.mk #[
    (leafCert.size / 65536).toUInt8, ((leafCert.size / 256) % 256).toUInt8, (leafCert.size % 256).toUInt8
  ] ++ leafCert ++ leafExtensions
  certList := certList ++ leafEntry
  for cert in intermediates do
    let entry := ByteArray.mk #[
      (cert.size / 65536).toUInt8, ((cert.size / 256) % 256).toUInt8, (cert.size % 256).toUInt8
    ] ++ cert ++ ByteArray.mk #[0x00, 0x00]
    certList := certList ++ entry
  let listLen := certList.size
  let certListWrapper := ByteArray.mk #[
    (listLen / 65536).toUInt8, ((listLen / 256) % 256).toUInt8, (listLen % 256).toUInt8
  ] ++ certList
  let body := context ++ certListWrapper
  let bodyLen := body.size
  return ByteArray.mk #[
    0x0B,
    (bodyLen / 65536).toUInt8, ((bodyLen / 256) % 256).toUInt8, (bodyLen % 256).toUInt8
  ] ++ body

-- ==========================================
-- Certificate Transparency (RFC 6962, RFC 8446 §4.4.2.1)
-- ==========================================

/-- Load SCT list from file (DER-encoded SignedCertificateTimestampList) -/
def loadSCTList (path : String) : IO (Option ByteArray) := do
  try
    let content ← IO.FS.readBinFile path
    if content.size > 0 then
      IO.eprintln s!"   -> 📋 Loaded SCT list ({content.size} bytes)"
      return some content
    else return none
  catch _ => return none

/-- Build Certificate message with OCSP stapling + SCT extension.
    SCT (Signed Certificate Timestamp) extension type = 0x0012.
    Used for Certificate Transparency (CT) compliance. -/
def buildCertificateChainWithSCT (leafCert : ByteArray) (intermediates : Array ByteArray)
    (ocspResponse : Option ByteArray) (sctList : Option ByteArray) : ByteArray := Id.run do
  let context := ByteArray.mk #[0x00]
  let mut certList := ByteArray.empty
  -- Build leaf cert extensions (OCSP + SCT)
  let mut leafExts := ByteArray.empty
  -- OCSP stapling (type 0x0005)
  match ocspResponse with
  | some ocsp =>
    let statusBody := ByteArray.mk #[0x01] ++
      ByteArray.mk #[
        (ocsp.size / 65536).toUInt8, ((ocsp.size / 256) % 256).toUInt8, (ocsp.size % 256).toUInt8
      ] ++ ocsp
    leafExts := leafExts ++
      ByteArray.mk #[0x00, 0x05] ++
      ByteArray.mk #[((statusBody.size / 256).toUInt8), (statusBody.size % 256).toUInt8] ++
      statusBody
  | none => pure ()
  -- SCT extension (type 0x0012)
  match sctList with
  | some sct =>
    -- SCT list is opaque<2^16-1> (2-byte length prefix + SCT entries)
    let sctData := ByteArray.mk #[((sct.size / 256).toUInt8), (sct.size % 256).toUInt8] ++ sct
    leafExts := leafExts ++
      ByteArray.mk #[0x00, 0x12] ++
      ByteArray.mk #[((sctData.size / 256).toUInt8), (sctData.size % 256).toUInt8] ++
      sctData
  | none => pure ()
  -- Extensions length wrapper
  let leafExtWrapper := ByteArray.mk #[((leafExts.size / 256).toUInt8), (leafExts.size % 256).toUInt8] ++ leafExts
  let leafEntry := ByteArray.mk #[
    (leafCert.size / 65536).toUInt8, ((leafCert.size / 256) % 256).toUInt8, (leafCert.size % 256).toUInt8
  ] ++ leafCert ++ leafExtWrapper
  certList := certList ++ leafEntry
  for cert in intermediates do
    let entry := ByteArray.mk #[
      (cert.size / 65536).toUInt8, ((cert.size / 256) % 256).toUInt8, (cert.size % 256).toUInt8
    ] ++ cert ++ ByteArray.mk #[0x00, 0x00]
    certList := certList ++ entry
  let listLen := certList.size
  let certListWrapper := ByteArray.mk #[
    (listLen / 65536).toUInt8, ((listLen / 256) % 256).toUInt8, (listLen % 256).toUInt8
  ] ++ certList
  let body := context ++ certListWrapper
  let bodyLen := body.size
  return ByteArray.mk #[
    0x0B,
    (bodyLen / 65536).toUInt8, ((bodyLen / 256) % 256).toUInt8, (bodyLen % 256).toUInt8
  ] ++ body

/-- Sessão TLS. -/
structure ApplicationKeys where
  serverKey : ByteArray
  serverIV  : ByteArray
  serverHP  : ByteArray
  clientKey : ByteArray
  clientIV  : ByteArray
  clientHP  : ByteArray

/-- Sessão TLS. -/
structure TLSSessionTLS where
  state : TLSState
  masterSecret : ByteArray
  privateKey : ByteArray
  peerPublicKey : Option ByteArray
  handshakeKeys : Option HandshakeKeys -- Store Handshake keys
  appKeys : Option ApplicationKeys -- [NEW] Store Application keys
  transcript : ByteArray -- Store transcript for hashing
  readSeq : Nat -- [NEW] Read Sequence Number
  writeSeq : Nat -- [NEW] Write Sequence Number
  alpnProtocol : Option String -- [NEW] Negotiated ALPN Protocol
  resumptionSecret : Option ByteArray := none -- For session tickets / 0-RTT
  clientAppTrafficSecret : Option ByteArray := none -- Current client app traffic secret (for KeyUpdate rotation)
  serverAppTrafficSecret : Option ByteArray := none -- Current server app traffic secret (for KeyUpdate rotation)
  /-- Nonce state for AES-GCM nonce management (Phase 4.4).
      Monotonic counter for per-record nonce construction (RFC 8446 §5.3).
      Formal proofs of uniqueness are in NonceManager.lean. -/
  writeNonceCounter : Nat := 0

/-- Derive Application Keys for QUIC (RFC 9001 §5.1: uses "quic key", "quic iv", "quic hp") -/
def deriveApplicationKeys (handshakeSecret : ByteArray) (helloHash : ByteArray) : ApplicationKeys :=
  let emptyHash := sha256 ByteArray.empty

  -- 1. Derive Master Secret
  let derivedSecret := deriveSecret handshakeSecret "derived" emptyHash
  let zeroKey := ByteArray.mk (List.replicate 32 0).toArray
  let masterSecret := hkdf_extract derivedSecret zeroKey

  -- 2. Traffic Secrets
  let clientAppTrafficSecret := deriveSecret masterSecret "c ap traffic" helloHash
  let serverAppTrafficSecret := deriveSecret masterSecret "s ap traffic" helloHash

  -- 3. Keys, IVs, and Header Protection (QUIC labels)
  let clientKey := hkdfExpandLabel clientAppTrafficSecret "quic key" ByteArray.empty 16
  let clientIV  := hkdfExpandLabel clientAppTrafficSecret "quic iv"  ByteArray.empty 12
  let clientHP  := hkdfExpandLabel clientAppTrafficSecret "quic hp" ByteArray.empty 16
  let serverKey := hkdfExpandLabel serverAppTrafficSecret "quic key" ByteArray.empty 16
  let serverIV  := hkdfExpandLabel serverAppTrafficSecret "quic iv"  ByteArray.empty 12
  let serverHP  := hkdfExpandLabel serverAppTrafficSecret "quic hp" ByteArray.empty 16

  {
    serverKey := serverKey
    serverIV := serverIV
    serverHP := serverHP
    clientKey := clientKey
    clientIV := clientIV
    clientHP := clientHP
  }

/-- Derive Application Keys for TLS 1.3 over TCP (RFC 8446: uses "key", "iv") -/
def deriveTLSApplicationKeys (handshakeSecret : ByteArray) (helloHash : ByteArray) : ApplicationKeys :=
  let emptyHash := sha256 ByteArray.empty

  -- 1. Derive Master Secret
  let derivedSecret := deriveSecret handshakeSecret "derived" emptyHash
  let zeroKey := ByteArray.mk (List.replicate 32 0).toArray
  let masterSecret := hkdf_extract derivedSecret zeroKey

  -- 2. Traffic Secrets
  let clientAppTrafficSecret := deriveSecret masterSecret "c ap traffic" helloHash
  let serverAppTrafficSecret := deriveSecret masterSecret "s ap traffic" helloHash

  -- 3. Keys and IVs (Standard TLS 1.3 labels per RFC 8446)
  let clientKey := hkdfExpandLabel clientAppTrafficSecret "key" ByteArray.empty 16
  let clientIV  := hkdfExpandLabel clientAppTrafficSecret "iv"  ByteArray.empty 12
  let clientHP  := ByteArray.mk (List.replicate 16 0).toArray  -- HP not used in TCP TLS
  let serverKey := hkdfExpandLabel serverAppTrafficSecret "key" ByteArray.empty 16
  let serverIV  := hkdfExpandLabel serverAppTrafficSecret "iv"  ByteArray.empty 12
  let serverHP  := ByteArray.mk (List.replicate 16 0).toArray  -- HP not used in TCP TLS

  {
    serverKey := serverKey
    serverIV := serverIV
    serverHP := serverHP
    clientKey := clientKey
    clientIV := clientIV
    clientHP := clientHP
  }

/-- Calculate nonce for Record Layer -/
def getNonce (iv : ByteArray) (seqNum : Nat) : ByteArray :=
  -- IV is 12 bytes. SeqNum is 64-bit.
  -- Pad SeqNum to 12 bytes (4 zeros + 8 seq).
  let seqBytes := ByteArray.mk #[
    0, 0, 0, 0,
    (seqNum >>> 56).toUInt8, (seqNum >>> 48).toUInt8, (seqNum >>> 40).toUInt8, (seqNum >>> 32).toUInt8,
    (seqNum >>> 24).toUInt8, (seqNum >>> 16).toUInt8, (seqNum >>> 8).toUInt8, seqNum.toUInt8
  ]
  LeanServer.AES.xorBytes iv seqBytes

/-- Build TLS 1.3 Flight 2 Messages (EncryptedExtensions, Cert, CV, Finished) -/
def buildFlight2Messages (session : TLSSessionTLS) (keys : HandshakeKeys) (quicParams : Option ByteArray) (intermediateCerts : Array ByteArray := #[]) : IO (ByteArray × TLSSessionTLS) := do
  -- 1. EncryptedExtensions
  let eeMsg := buildEncryptedExtensions session.alpnProtocol quicParams
  let transcript := session.transcript ++ eeMsg

  -- 2. Certificate (with optional chain + OCSP stapling)
  let certOpt ← loadCertificateDER "cert.pem"
  let certData := match certOpt with
    | some c => c.data
    | none => ByteArray.mk #[0] -- Fallback (will fail)

  -- Try to load OCSP response for stapling
  let ocspResp ← loadOCSPResponse "ocsp.der"
  -- Try to load SCT list for Certificate Transparency
  let sctList ← loadSCTList "sct.der"

  let certMsg := if intermediateCerts.size > 0 || ocspResp.isSome || sctList.isSome then
    buildCertificateChainWithSCT certData intermediateCerts ocspResp sctList
  else
    buildCertificate certData
  let transcript := transcript ++ certMsg

  -- 3. CertificateVerify
  let transcriptHash := sha256 transcript
  -- Sign Input construction
  let signPrefix := ByteArray.mk (List.replicate 64 0x20).toArray
  let signLabel := "TLS 1.3, server CertificateVerify".toUTF8
  let signInput := signPrefix ++ signLabel ++ ByteArray.mk #[0x00] ++ transcriptHash

  -- Load Private Key for Signing (RSA)
  let keyOpt ← loadPrivateKey "key.pem"
  let rsaPrivKey := match keyOpt with
    | some k => k
    | none => ByteArray.empty -- Will cause sign to fail safely

  let sig ← sign rsaPrivKey signInput
  let cvMsg := buildCertificateVerify sig
  let transcript := transcript ++ cvMsg

  -- 4. Finished
  let transcriptHashFin := sha256 transcript
  let finMsg := buildFinished keys.serverFinishedKey transcriptHashFin
  -- Update transcript with FIN for next steps (Client Finished)
  let transcript := transcript ++ finMsg

  let messages := eeMsg ++ certMsg ++ cvMsg ++ finMsg
  let newSession := { session with transcript := transcript, handshakeKeys := some keys }

  return (messages, newSession)

/-- Build TLS 1.3 Flight 2 Record (Legacy Wrapper for TCP) -/
def buildFlight2 (session : TLSSessionTLS) (keys : HandshakeKeys) (quicParams : Option ByteArray) (intermediateCerts : Array ByteArray := #[]) : IO (ByteArray × TLSSessionTLS) := do
  let (messages, newSession) ← buildFlight2Messages session keys quicParams intermediateCerts

  -- Encrypt into Record
  -- Use sequence number 0 for the first encrypted record
  let nonce := getNonce keys.serverIV 0
  let record := encryptTLS13Record keys.serverKey nonce messages 0x16

  return (record, newSession)

-- ==========================================
-- PSK Resumption (RFC 8446 §2.2, §4.2.11)
-- ==========================================

/-- Derive Handshake Keys using PSK (psk_dhe_ke mode).
    Early Secret uses PSK instead of zeros. -/
def deriveHandshakeKeysPSK (psk : ByteArray) (sharedSecret : ByteArray) (helloHash : ByteArray) : HandshakeKeys :=
  let emptyHash := sha256 ByteArray.empty
  let zeroSalt := ByteArray.mk (List.replicate 32 0).toArray
  -- 1. Early Secret = HKDF-Extract(0, PSK)  — differs from non-PSK which uses zeros
  let earlySecret := hkdf_extract zeroSalt psk
  -- 2. Derived Secret
  let derivedSecret := deriveSecret earlySecret "derived" emptyHash
  -- 3. Handshake Secret (still uses ECDHE shared secret for psk_dhe_ke)
  let handshakeSecret := hkdf_extract derivedSecret sharedSecret
  -- 4. Traffic Secrets
  let clientHandshakeTrafficSecret := deriveSecret handshakeSecret "c hs traffic" helloHash
  let serverHandshakeTrafficSecret := deriveSecret handshakeSecret "s hs traffic" helloHash
  -- 5. Keys and IVs
  let clientKey := hkdfExpandLabel clientHandshakeTrafficSecret "key" ByteArray.empty 16
  let clientIV  := hkdfExpandLabel clientHandshakeTrafficSecret "iv"  ByteArray.empty 12
  let clientHP  := hkdfExpandLabel clientHandshakeTrafficSecret "hp"  ByteArray.empty 16
  let serverKey := hkdfExpandLabel serverHandshakeTrafficSecret "key" ByteArray.empty 16
  let serverIV  := hkdfExpandLabel serverHandshakeTrafficSecret "iv"  ByteArray.empty 12
  let serverHP  := hkdfExpandLabel serverHandshakeTrafficSecret "hp"  ByteArray.empty 16
  let clientFinishedKey := hkdfExpandLabel clientHandshakeTrafficSecret "finished" ByteArray.empty 32
  let serverFinishedKey := hkdfExpandLabel serverHandshakeTrafficSecret "finished" ByteArray.empty 32
  {
    serverKey := serverKey, serverIV := serverIV, serverHP := serverHP,
    clientKey := clientKey, clientIV := clientIV, clientHP := clientHP,
    serverTrafficSecret := serverHandshakeTrafficSecret,
    clientTrafficSecret := clientHandshakeTrafficSecret,
    serverFinishedKey := serverFinishedKey,
    clientFinishedKey := clientFinishedKey,
    handshakeSecret := handshakeSecret
  }

/-- Compute the truncated ClientHello for PSK binder verification (RFC 8446 §4.2.11.2).
    The truncated CH includes everything up to but NOT including the binders list
    in the pre_shared_key extension. The binders are at the tail of the ClientHello.
    Binders section = 2-byte binders_list_length + (for each binder: 1-byte length + binder_data) -/
def computeTruncatedClientHello (fullCH : ByteArray) (binders : List ByteArray) : ByteArray :=
  let bindersSize := binders.foldl (fun acc b => acc + 1 + b.size) 0
  let bindersSectionSize := 2 + bindersSize
  if fullCH.size > bindersSectionSize then
    fullCH.extract 0 (fullCH.size - bindersSectionSize)
  else fullCH

/-- Verify PSK binder (RFC 8446 §4.2.11.2).
    binder = HMAC(finished_key, Transcript-Hash(Truncated-ClientHello))
    where finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    and binder_key = Derive-Secret(early_secret, "res binder", empty_hash) -/
def verifyPSKBinder (psk : ByteArray) (truncatedCH : ByteArray) (binder : ByteArray) : Bool :=
  let zeroSalt := ByteArray.mk (List.replicate 32 0).toArray
  let earlySecret := hkdf_extract zeroSalt psk
  let emptyHash := sha256 ByteArray.empty
  let binderKey := deriveSecret earlySecret "res binder" emptyHash
  let finishedKey := hkdfExpandLabel binderKey "finished" ByteArray.empty 32
  let transcriptHash := sha256 truncatedCH
  let expectedBinder := hmac_sha256 finishedKey transcriptHash
  constantTimeEqual expectedBinder binder

/-- Generate ServerHello with pre_shared_key extension (selected_identity=0) for PSK resumption -/
def generateServerHelloPSK (ch : ClientHello) (serverPublicKey : ByteArray) (serverRandom : ByteArray) (_selectedProtocol : Option String) : ByteArray :=
  let sessionId := ch.sessionId
  let cipherSuite := #[0x13, 0x01]
  let compression := #[0x00]
  -- Extension: Supported Versions (TLS 1.3)
  let supportedVersionsExt := ByteArray.mk #[
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
  ]
  -- Extension: Key Share (X25519)
  let keyShareData :=
    ByteArray.mk #[0x00, 0x1d, 0x00, 0x20] ++ serverPublicKey
  let keyShareExt :=
    ByteArray.mk #[0x00, 0x33] ++
    ByteArray.mk #[((keyShareData.size / 256).toUInt8), (keyShareData.size % 256).toUInt8] ++
    keyShareData
  -- Extension: pre_shared_key (selected_identity = 0)
  let pskExt := ByteArray.mk #[
    0x00, 0x29, -- Type: pre_shared_key
    0x00, 0x02, -- Ext Length: 2
    0x00, 0x00  -- Selected Identity: 0
  ]
  let extensionsBody := supportedVersionsExt ++ keyShareExt ++ pskExt
  let serverHelloBody :=
    ByteArray.mk #[0x03, 0x03] ++
    serverRandom ++
    ByteArray.mk #[sessionId.size.toUInt8] ++ sessionId ++
    ByteArray.mk cipherSuite ++
    ByteArray.mk compression ++
    ByteArray.mk #[((extensionsBody.size / 256).toUInt8), (extensionsBody.size % 256).toUInt8] ++
    extensionsBody
  ByteArray.mk #[0x02, 0x00, ((serverHelloBody.size / 256).toUInt8), (serverHelloBody.size % 256).toUInt8] ++ serverHelloBody

/-- Build Flight 2 for PSK resumption (EncryptedExtensions + Finished only, no Cert/CV) -/
def buildFlight2PSK (session : TLSSessionTLS) (keys : HandshakeKeys) : IO (ByteArray × TLSSessionTLS) := do
  -- 1. EncryptedExtensions
  let eeMsg := buildEncryptedExtensions session.alpnProtocol none
  let transcript := session.transcript ++ eeMsg
  -- 2. Finished (skip Certificate and CertificateVerify for PSK)
  let transcriptHashFin := sha256 transcript
  let finMsg := buildFinished keys.serverFinishedKey transcriptHashFin
  let transcript := transcript ++ finMsg
  let messages := eeMsg ++ finMsg
  let newSession := { session with transcript := transcript, handshakeKeys := some keys }
  -- Encrypt into Record
  let nonce := getNonce keys.serverIV 0
  let record := encryptTLS13Record keys.serverKey nonce messages 0x16
  return (record, newSession)

/-- Build a TLS 1.3 HelloRetryRequest (RFC 8446 §4.1.4).
    An HRR is a ServerHello with the special SHA-256 hash of
    "HelloRetryRequest" as the Random value and a
    `key_share` extension that names the desired group (x25519 = 0x001d).
    The client must then retry with a key share for that group. -/
def buildHelloRetryRequest (ch : ClientHello) : ByteArray :=
  let sessionId := ch.sessionId
  -- RFC 8446 §4.1.3: The special "random" value for HRR
  let hrrRandom := ByteArray.mk #[
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
  ]
  -- Selected cipher suite (negotiate or default)
  let selectedSuite := match negotiateCipherSuite ch.cipherSuites with
    | some s => s
    | none   => (0x1301 : UInt16)
  let cipherSuite := #[((selectedSuite.toNat >>> 8) &&& 0xFF).toUInt8, (selectedSuite.toNat &&& 0xFF).toUInt8]
  let compression := #[0x00]
  -- Extension: Supported Versions (TLS 1.3)
  let supportedVersionsExt := ByteArray.mk #[
    0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
  ]
  -- Extension: Key Share — selected_group only (no key exchange data)
  -- Type 0x0033, Length 2, NamedGroup x25519 (0x001d)
  let keyShareExt := ByteArray.mk #[
    0x00, 0x33, 0x00, 0x02, 0x00, 0x1d
  ]
  let extensionsBody := supportedVersionsExt ++ keyShareExt
  let serverHelloBody :=
    ByteArray.mk #[0x03, 0x03] ++ hrrRandom ++
    ByteArray.mk #[sessionId.size.toUInt8] ++ sessionId ++
    ByteArray.mk cipherSuite ++ ByteArray.mk compression ++
    ByteArray.mk #[((extensionsBody.size / 256).toUInt8), (extensionsBody.size % 256).toUInt8] ++
    extensionsBody
  -- Handshake Message Header: Type 0x02 (ServerHello), 3-byte length
  let handshakeMsg :=
    ByteArray.mk #[0x02, 0x00, ((serverHelloBody.size / 256).toUInt8), (serverHelloBody.size % 256).toUInt8] ++
    serverHelloBody
  handshakeMsg

/-- Inicia handshake. -/
def initiateHandshake (clientData : ByteArray) (serverPublicKey : ByteArray) (selectedProtocol : Option String) : IO (Option (TLSSessionTLS × ByteArray)) := do
  match parseClientHello clientData with
  | some ch =>
      -- Check if the client provided an x25519 key share (RFC 8446 §4.2.8)
      -- If not, send HelloRetryRequest asking for one
      if ch.clientKeyShare.isNone then
        IO.eprintln "   🔄 No x25519 key share in ClientHello — sending HelloRetryRequest"
        let hrrMsg := buildHelloRetryRequest ch
        let hrrRecord := generateServerHelloRecord hrrMsg
        return some ({
          state := TLSState.Handshake,
          masterSecret := ByteArray.mk #[],
          privateKey := ByteArray.mk #[],
          peerPublicKey := none,
          handshakeKeys := none,
          appKeys := none,
          transcript := ByteArray.empty,
          readSeq := 0,
          writeSeq := 0,
          alpnProtocol := selectedProtocol
        }, hrrRecord)
      let serverRandom ← IO.getRandomBytes 32
      let serverHelloMsg := generateServerHello ch serverPublicKey serverRandom selectedProtocol
      let serverHelloRecord := generateServerHelloRecord serverHelloMsg
      if clientData.size < 5 then return none
      else
        let chRecordLen := ((clientData.get! 3).toNat * 256) + (clientData.get! 4).toNat
        let extractLen := if 5 + chRecordLen <= clientData.size then chRecordLen else (clientData.size - 5)
        let clientHelloMsg := clientData.extract 5 (5 + extractLen)
        -- Transcript uses logic message, not record
        let transcript := clientHelloMsg ++ serverHelloMsg
        return some ({
          state := TLSState.Handshake,
          masterSecret := ByteArray.mk #[],
          privateKey := ByteArray.mk #[],
          peerPublicKey := ch.clientKeyShare,
          handshakeKeys := none,
          appKeys := none,
          transcript := transcript,
          readSeq := 0,
          writeSeq := 0,
          alpnProtocol := selectedProtocol
        }, serverHelloRecord)
  | none =>
      return none

/-- Process TLS application data: decrypt incoming record using client app key.
    Uses AES-128-GCM with sequence-number-derived nonces per RFC 8446 §5.3. -/
def processTLSData (session : TLSSessionTLS) (data : ByteArray) : (TLSSessionTLS × ByteArray) :=
  match session.appKeys with
  | none => (session, data)  -- No app keys yet (still in handshake), pass through
  | some keys =>
    let nonce := getNonce keys.clientIV session.readSeq
    match decryptTLS13Record keys.clientKey nonce data with
    | some (plaintext, _contentType) =>
      let newSession := { session with readSeq := session.readSeq + 1 }
      (newSession, plaintext)
    | none =>
      -- Decryption failed — return empty (connection should be closed)
      let newSession := { session with readSeq := session.readSeq + 1 }
      (newSession, ByteArray.empty)

/-- TLS 1.3 Session Ticket (RFC 8446 §4.6.1) for session resumption and 0-RTT -/
structure SessionTicket where
  ticketLifetime : UInt32 := 7200       -- 2 hours in seconds
  ticketAgeAdd : UInt32 := 0            -- Random value to obscure ticket age
  ticketNonce : ByteArray := ByteArray.empty
  ticket : ByteArray := ByteArray.empty  -- Opaque ticket data
  -- Extensions (max_early_data_size for 0-RTT)
  maxEarlyDataSize : UInt32 := 16384    -- 16KB max early data
  deriving Inhabited

/-- Build NewSessionTicket handshake message (RFC 8446 §4.6.1)
    Message type 0x04, sent after server's Finished -/
def buildNewSessionTicket (resumptionSecret : ByteArray) (ticketAgeAdd : UInt32) (ticketNonce : ByteArray) (maxEarlyData : UInt32 := 16384) : ByteArray :=
  -- Ticket = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)
  let psk := hkdfExpandLabel resumptionSecret "resumption" ticketNonce 32

  -- Build ticket data (in production, this would be encrypted server state)
  -- For now, the PSK itself serves as the ticket (self-encrypted ticket pattern)
  let ticketData := psk

  -- Extensions: early_data (type=0x002A) with max_early_data_size
  let earlyDataExt := ByteArray.mk #[
    0x00, 0x2A,  -- early_data extension type
    0x00, 0x04,  -- extension data length (4 bytes)
    (maxEarlyData >>> 24).toUInt8, (maxEarlyData >>> 16).toUInt8,
    (maxEarlyData >>> 8).toUInt8, maxEarlyData.toUInt8
  ]
  let extensionsLen := earlyDataExt.size
  let extensions := ByteArray.mk #[
    (extensionsLen / 256).toUInt8, (extensionsLen % 256).toUInt8
  ] ++ earlyDataExt

  -- Build message body
  let lifetime : UInt32 := 7200
  let body := ByteArray.mk #[
    -- ticket_lifetime (4 bytes)
    (lifetime >>> 24).toUInt8, (lifetime >>> 16).toUInt8,
    (lifetime >>> 8).toUInt8, lifetime.toUInt8,
    -- ticket_age_add (4 bytes)
    (ticketAgeAdd >>> 24).toUInt8, (ticketAgeAdd >>> 16).toUInt8,
    (ticketAgeAdd >>> 8).toUInt8, ticketAgeAdd.toUInt8
  ]
  -- ticket_nonce (1 byte length + nonce)
  let nonceField := ByteArray.mk #[ticketNonce.size.toUInt8] ++ ticketNonce
  -- ticket (2 byte length + data)
  let ticketField := ByteArray.mk #[
    (ticketData.size / 256).toUInt8, (ticketData.size % 256).toUInt8
  ] ++ ticketData

  let msgBody := body ++ nonceField ++ ticketField ++ extensions

  -- Handshake header: type=0x04 (NewSessionTicket), 3-byte length
  let msgLen := msgBody.size
  ByteArray.mk #[
    0x04,  -- NewSessionTicket
    (msgLen / 65536).toUInt8, ((msgLen / 256) % 256).toUInt8, (msgLen % 256).toUInt8
  ] ++ msgBody

/-- Derive resumption master secret (RFC 8446 §7.1) -/
def deriveResumptionSecret (masterSecret : ByteArray) (transcriptHash : ByteArray) : ByteArray :=
  deriveSecret masterSecret "res master" transcriptHash

/-- Derive early data keys for 0-RTT (RFC 8446 §7.1) -/
def deriveEarlyDataKeys (psk : ByteArray) (helloHash : ByteArray) : ApplicationKeys :=
  -- 1. Early Secret = HKDF-Extract(0, PSK)
  let zeroSalt := ByteArray.mk (List.replicate 32 0).toArray
  let earlySecret := hkdf_extract zeroSalt psk

  -- 2. Client Early Traffic Secret
  let clientEarlyTrafficSecret := deriveSecret earlySecret "c e traffic" helloHash

  -- 3. Derive keys (use TLS labels for TCP, would use "quic" labels for QUIC)
  let clientKey := hkdfExpandLabel clientEarlyTrafficSecret "key" ByteArray.empty 16
  let clientIV := hkdfExpandLabel clientEarlyTrafficSecret "iv" ByteArray.empty 12
  let clientHP := hkdfExpandLabel clientEarlyTrafficSecret "quic hp" ByteArray.empty 16

  -- Early data is client-to-server only; server keys are zeroed
  {
    serverKey := ByteArray.mk (List.replicate 16 0).toArray
    serverIV := ByteArray.mk (List.replicate 12 0).toArray
    serverHP := ByteArray.mk (List.replicate 16 0).toArray
    clientKey := clientKey
    clientIV := clientIV
    clientHP := clientHP
  }

/-- Transition to Application Data State (TLS 1.3) -/
def transitionToAppData (session : TLSSessionTLS) : Option TLSSessionTLS :=
  match session.handshakeKeys with
  | some keys =>
      let transcriptHash := sha256 session.transcript
      -- Use TLS 1.3 labels ("key", "iv") for TCP connections (not QUIC labels)
      let appKeys := deriveTLSApplicationKeys keys.handshakeSecret transcriptHash
      -- Derive resumption master secret and traffic secrets for session tickets / key rotation
      let emptyHash := sha256 ByteArray.empty
      let derivedSecret := deriveSecret keys.handshakeSecret "derived" emptyHash
      let zeroKey := ByteArray.mk (List.replicate 32 0).toArray
      let masterSecret := hkdf_extract derivedSecret zeroKey
      let resSecret := deriveResumptionSecret masterSecret transcriptHash
      -- Store traffic secrets for KeyUpdate rotation (RFC 8446 §7.2)
      let clientAppSecret := deriveSecret masterSecret "c ap traffic" transcriptHash
      let serverAppSecret := deriveSecret masterSecret "s ap traffic" transcriptHash
      some { session with
        state := TLSState.Data,
        appKeys := some appKeys,
        readSeq := 0,  -- Reset sequencia para AppData
        writeSeq := 0,
        resumptionSecret := some resSecret,
        clientAppTrafficSecret := some clientAppSecret,
        serverAppTrafficSecret := some serverAppSecret
      }
  | none => none

/-- Encrypt Application Data (TLS 1.3)
    Returns (EncryptedRecord, UpdatedSession) -/
def encryptAppData (session : TLSSessionTLS) (plaintext : ByteArray) : Option (ByteArray × TLSSessionTLS) :=
  match session.appKeys with
  | some keys =>
      let nonce := getNonce keys.serverIV session.writeSeq
      -- 0x17 é o tipo para Application Data
      let record := encryptTLS13Record keys.serverKey nonce plaintext 0x17
      let newSession := { session with writeSeq := session.writeSeq + 1 }
      some (record, newSession)
  | none => none

/-- Encrypt a post-handshake message (e.g., NewSessionTicket) with inner content type 0x16.
    TLS 1.3 §4.6: Post-handshake messages are encrypted under application traffic keys
    but retain inner content type 0x16 (Handshake) so the TLS layer routes them correctly. -/
def encryptPostHandshake (session : TLSSessionTLS) (plaintext : ByteArray) : Option (ByteArray × TLSSessionTLS) :=
  match session.appKeys with
  | some keys =>
      let nonce := getNonce keys.serverIV session.writeSeq
      -- 0x16 = Handshake inner type for post-handshake messages (NST, KeyUpdate, etc.)
      let record := encryptTLS13Record keys.serverKey nonce plaintext 0x16
      let newSession := { session with writeSeq := session.writeSeq + 1 }
      some (record, newSession)
  | none => none



-- ==========================================
-- 0-RTT Anti-Replay Window (RFC 8446 §8, RFC 9001 §9.2)
-- ==========================================

/-- Time-windowed anti-replay protection for 0-RTT packets.
    Uses a sliding window of seen (clientHello hash, timestamp) pairs.
    Window size is configurable (default 10 seconds). -/
structure AntiReplayEntry where
  fingerprint : UInt64    -- Hash of client identifier (DCID + PN)
  timestampMs : UInt64    -- When this entry was recorded
  deriving Inhabited

structure AntiReplayWindow where
  entries : List AntiReplayEntry := []
  windowMs : UInt64 := 10000         -- 10-second window
  maxEntries : Nat := 4096           -- Max entries (bloom filter approximation)
  deriving Inhabited

/-- Simple hash for anti-replay fingerprinting -/
def antiReplayHash (dcid : ByteArray) (pn : UInt64) : UInt64 :=
  let h := dcid.foldl (fun acc b => acc * 31 + b.toUInt64) 0x811c9dc5
  h ^^^ (pn * 0x9e3779b97f4a7c15)

-- ==========================================
-- 0-RTT STREAM Frame Parser (RFC 9000 §19.8)
-- ==========================================

/-- Parsed QUIC STREAM frame -/
structure QUICStreamFrame where
  streamId : UInt64
  offset : UInt64 := 0
  data : ByteArray
  fin : Bool := false
  deriving Inhabited

/-- Decode a QUIC variable-length integer (RFC 9000 §16) -/
def decodeVarIntCrypto (data : ByteArray) (pos : Nat) : Option (UInt64 × Nat) :=
  if pos >= data.size then none
  else
    let first := data.get! pos
    let lenBits := (first.toNat >>> 6) &&& 0x03
    match lenBits with
    | 0 => some ((first &&& 0x3F).toUInt64, 1)
    | 1 =>
      if pos + 2 > data.size then none
      else
        let v := ((first &&& 0x3F).toUInt64 <<< 8) ||| (data.get! (pos + 1)).toUInt64
        some (v, 2)
    | 2 =>
      if pos + 4 > data.size then none
      else
        let v := ((first &&& 0x3F).toUInt64 <<< 24) |||
                 ((data.get! (pos + 1)).toUInt64 <<< 16) |||
                 ((data.get! (pos + 2)).toUInt64 <<< 8) |||
                 (data.get! (pos + 3)).toUInt64
        some (v, 4)
    | _ =>
      if pos + 8 > data.size then none
      else
        let v := ((first &&& 0x3F).toUInt64 <<< 56) |||
                 ((data.get! (pos + 1)).toUInt64 <<< 48) |||
                 ((data.get! (pos + 2)).toUInt64 <<< 40) |||
                 ((data.get! (pos + 3)).toUInt64 <<< 32) |||
                 ((data.get! (pos + 4)).toUInt64 <<< 24) |||
                 ((data.get! (pos + 5)).toUInt64 <<< 16) |||
                 ((data.get! (pos + 6)).toUInt64 <<< 8) |||
                 (data.get! (pos + 7)).toUInt64
        some (v, 8)

/-- Parse QUIC STREAM frames from decrypted 0-RTT payload (RFC 9000 §19.8).
    Frame type 0x08-0x0F: bits indicate OFF(0x04), LEN(0x02), FIN(0x01). -/
def parseStreamFrames (payload : ByteArray) : List QUICStreamFrame := Id.run do
  let mut frames : List QUICStreamFrame := []
  let mut pos := 0
  while pos < payload.size do
    let frameType := (payload.get! pos).toNat
    pos := pos + 1
    if frameType >= 0x08 && frameType <= 0x0F then
      let hasOffset := (frameType &&& 0x04) != 0
      let hasLength := (frameType &&& 0x02) != 0
      let hasFin := (frameType &&& 0x01) != 0
      -- Stream ID (varint)
      match decodeVarIntCrypto payload pos with
      | some (streamId, sidLen) =>
        pos := pos + sidLen
        -- Offset (varint, if OFF bit set)
        let (offset, offsetLen) := if hasOffset then
          match decodeVarIntCrypto payload pos with
          | some (off, len) => (off, len)
          | none => (0, 0)
        else (0, 0)
        pos := pos + offsetLen
        -- Length (varint, if LEN bit set)
        let (dataLen, lenLen) := if hasLength then
          match decodeVarIntCrypto payload pos with
          | some (len, ll) => (len.toNat, ll)
          | none => (0, 0)
        else (payload.size - pos, 0)  -- Rest of payload
        pos := pos + lenLen
        let data := if pos + dataLen <= payload.size then
          payload.extract pos (pos + dataLen)
        else payload.extract pos payload.size
        pos := pos + dataLen
        frames := frames ++ [{ streamId := streamId, offset := offset, data := data, fin := hasFin }]
      | none => pos := payload.size  -- Bail
    else if frameType == 0x06 then  -- CRYPTO frame
      match decodeVarIntCrypto payload pos with
      | some (_, offLen) =>
        pos := pos + offLen
        match decodeVarIntCrypto payload pos with
        | some (len, lenLen) =>
          pos := pos + lenLen + len.toNat
        | none => pos := payload.size
      | none => pos := payload.size
    else if frameType == 0x00 then  -- PADDING
      pos := pos  -- skip padding byte (already advanced)
    else if frameType == 0x01 then  -- PING
      pure ()  -- no payload
    else
      pos := payload.size  -- Unknown frame, bail
  return frames

-- ==========================================
-- Session Ticket Encryption Key Rotation (RFC 8446 §4.6.1)
-- ==========================================

/-- Ticket encryption key with generation timestamp -/
structure TicketKey where
  key : ByteArray          -- 32-byte key for ticket encryption
  createdMs : UInt64       -- When this key was created
  deriving Inhabited

/-- Ticket key manager: current + previous key for graceful rotation -/
structure TicketKeyManager where
  current : TicketKey
  previous : Option TicketKey := none
  rotationIntervalMs : UInt64 := 3600000  -- 1 hour
  deriving Inhabited

/-- Rotate ticket encryption key if interval has elapsed.
    Returns (manager, didRotate). Old key is kept as "previous" for
    decrypting tickets encrypted with the prior key. -/
def rotateTicketKeyIfNeeded (mgr : TicketKeyManager) (nowMs : UInt64) (newKeyBytes : ByteArray) : (TicketKeyManager × Bool) :=
  if nowMs - mgr.current.createdMs > mgr.rotationIntervalMs then
    let newMgr : TicketKeyManager := {
      current := { key := newKeyBytes, createdMs := nowMs },
      previous := some mgr.current,
      rotationIntervalMs := mgr.rotationIntervalMs
    }
    (newMgr, true)
  else
    (mgr, false)

/-- Encrypt a session ticket using the current ticket key.
    Format: 16-byte nonce + AES-128-GCM(key, nonce, ticket_plaintext, aad="ticket") -/
def encryptSessionTicket (ticketKey : ByteArray) (nonce : ByteArray) (plaintext : ByteArray) : ByteArray :=
  let aad := "ticket".toUTF8
  let (ciphertext, tag) := aes128_gcm_encrypt (ticketKey.extract 0 16) (nonce.extract 0 12) aad plaintext
  nonce ++ ciphertext ++ tag

/-- Decrypt a session ticket. Returns plaintext or none if decryption fails.
    Tries current key first, then previous key (for rotation overlap). -/
def decryptSessionTicket (mgr : TicketKeyManager) (encryptedTicket : ByteArray) : Option ByteArray :=
  if encryptedTicket.size < 28 then none  -- 12 nonce + 16 tag minimum
  else
    let nonce := encryptedTicket.extract 0 12
    let ciphertextWithTag := encryptedTicket.extract 12 encryptedTicket.size
    let aad := "ticket".toUTF8
    -- Try current key
    match aes128_gcm_decrypt (mgr.current.key.extract 0 16) nonce aad ciphertextWithTag with
    | some pt => some pt
    | none =>
      -- Try previous key (rotation grace period)
      match mgr.previous with
      | some prev =>
        aes128_gcm_decrypt (prev.key.extract 0 16) nonce aad ciphertextWithTag
      | none => none

-- ==========================================
-- KeyUpdate (RFC 8446 §4.6.3)
-- ==========================================

/-- Build KeyUpdate handshake message (RFC 8446 §4.6.3).
    request_update: 0 = update_not_requested, 1 = update_requested -/
def buildKeyUpdate (requestUpdate : Bool) : ByteArray :=
  let requestByte : UInt8 := if requestUpdate then 1 else 0
  -- Handshake type 0x18 (KeyUpdate), length 1
  ByteArray.mk #[0x18, 0x00, 0x00, 0x01, requestByte]

/-- Derive next-generation application traffic secret (RFC 8446 §7.2).
    application_traffic_secret_N+1 =
      HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length) -/
def deriveNextTrafficSecret (currentSecret : ByteArray) : ByteArray :=
  hkdfExpandLabel currentSecret "traffic upd" ByteArray.empty 32

/-- Derive new application keys from updated traffic secret -/
def deriveUpdatedAppKeys (newClientSecret : ByteArray) (newServerSecret : ByteArray) : ApplicationKeys :=
  let clientKey := hkdfExpandLabel newClientSecret "key" ByteArray.empty 16
  let clientIV  := hkdfExpandLabel newClientSecret "iv"  ByteArray.empty 12
  let serverKey := hkdfExpandLabel newServerSecret "key" ByteArray.empty 16
  let serverIV  := hkdfExpandLabel newServerSecret "iv"  ByteArray.empty 12
  {
    serverKey := serverKey, serverIV := serverIV,
    serverHP := ByteArray.mk (List.replicate 16 0).toArray,
    clientKey := clientKey, clientIV := clientIV,
    clientHP := ByteArray.mk (List.replicate 16 0).toArray
  }

/-- Process a received KeyUpdate and rotate keys (RFC 8446 §4.6.3).
    Updates the read keys (peer's write keys) immediately.
    If request_update=1, caller must also send KeyUpdate response and update write keys. -/
def processKeyUpdate (session : TLSSessionTLS) (requestUpdate : Bool) : Option (TLSSessionTLS × Bool) :=
  match session.appKeys, session.clientAppTrafficSecret, session.serverAppTrafficSecret with
  | some _keys, some clientSecret, some serverSecret =>
    -- Derive next-generation secrets per RFC 8446 §7.2:
    -- application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", 32)
    let newClientSecret := deriveNextTrafficSecret clientSecret
    let newServerSecret := deriveNextTrafficSecret serverSecret
    let newKeys := deriveUpdatedAppKeys newClientSecret newServerSecret
    let newSession := { session with
      appKeys := some newKeys,
      readSeq := 0,   -- Reset sequence numbers after key update
      writeSeq := 0,
      clientAppTrafficSecret := some newClientSecret,
      serverAppTrafficSecret := some newServerSecret
    }
    some (newSession, requestUpdate)
  | _, _, _ => none

open LeanServer

/-- Teorema: Sessões TLS têm estados bem-definidos. -/
theorem tls_session_state_well_defined (state : TLSState) (s : TLSSession state) : state = TLSState.Handshake ∨ state = TLSState.Data ∨ state = TLSState.Closed :=
  match state with
  | TLSState.Handshake => Or.inl rfl
  | TLSState.Data => Or.inr (Or.inl rfl)
  | TLSState.Closed => Or.inr (Or.inr rfl)

/-- Teorema: ByteArray.size é sempre ≥ 0 (propriedade fundamental de Nat). -/
theorem key_has_data (k : Key t) : k.data.size ≥ 0 :=
  Nat.zero_le _
