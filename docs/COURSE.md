# Learn Networking & Crypto with Lean 4 Proofs

A hands-on course using LeanServer as a teaching platform.
Each lesson corresponds to a module in the codebase with exercises.

---

## Course Structure

### Part I: Foundations (Weeks 1-3)

#### Lesson 1: **Hash Functions — SHA-256**
📁 `LeanServer/Crypto/SHA256.lean`

**Concepts**: Merkle-Damgård construction, compression function, padding

**Reading**:
- FIPS 180-4 (SHA standard)
- SHA-256 in `SHA256.lean`: `sha256_compress`, `sha256_pad`, `sha256_hash`

**Exercises**:
1. Trace SHA-256 on the string `"abc"` by hand. Compare with `SHA256.hash "abc".toUTF8`
2. Why must the padding include the message length? What attack does this prevent?
3. Read the proof `sha256_deterministic`. Why is this property important for digital signatures?
4. **Challenge**: Implement SHA-224 (same algorithm, different initial values, truncated output)

---

#### Lesson 2: **Symmetric Encryption — AES-128-GCM**
📁 `LeanServer/Crypto/AES.lean`

**Concepts**: Block ciphers, Galois/Counter Mode, authenticated encryption

**Reading**:
- NIST SP 800-38D (GCM specification)
- `AES.lean`: `subBytes`, `shiftRows`, `mixColumns`, `aesEncryptBlock`

**Exercises**:
1. What is the difference between ECB and GCM modes? Why is ECB insecure?
2. Verify: `aes_encrypt_decrypt_inverse` — what does this prove about data integrity?
3. What role does the authentication tag play in GCM? What happens if you modify a ciphertext byte?
4. **Challenge**: Add AES-256 support (14 rounds, 256-bit key schedule)

---

#### Lesson 3: **Key Exchange — X25519**
📁 `LeanServer/Crypto/X25519.lean`

**Concepts**: Elliptic curves, Montgomery form, Diffie-Hellman

**Reading**:
- RFC 7748 (Elliptic Curves for Security)
- `X25519.lean`: Montgomery ladder, field arithmetic in GF(2^255-19)

**Exercises**:
1. Why does X25519 use a Montgomery ladder instead of double-and-add?
2. What is the "clamping" operation on private keys? Why is it necessary?
3. Verify: if Alice computes `X25519(a, X25519(b, G))` and Bob computes `X25519(b, X25519(a, G))`, they get the same result. Which proof guarantees this?
4. **Challenge**: Implement X448 (Curve448, 224 bits of security)

---

### Part II: Protocols (Weeks 4-6)

#### Lesson 4: **TLS 1.3 Handshake**
📁 `LeanServer/Crypto/TLSHandshake.lean`, `TLSKeySchedule.lean`

**Concepts**: Key derivation, HKDF, transcript hash, state machines

**Reading**:
- RFC 8446 §2 (Protocol Overview), §7 (Key Schedule)
- `TLSHandshake.lean`: ClientHello/ServerHello processing
- `TLSKeySchedule.lean`: `hkdfExpandLabel`, `deriveHandshakeKeys`

**Exercises**:
1. Draw the TLS 1.3 handshake message flow. Which messages are encrypted?
2. What is a transcript hash? Why does TLS 1.3 hash all handshake messages?
3. Read `tls_state_machine_theorem`. What invalid transitions does it prevent?
4. What is 0-RTT resumption? What security property does it sacrifice?
5. **Challenge**: Add session ticket support (RFC 8446 §4.6.1)

---

#### Lesson 5: **HTTP/2 and HPACK**
📁 `LeanServer/Protocol/HTTP2.lean`, `HPACK.lean`

**Concepts**: Binary framing, multiplexing, header compression

**Reading**:
- RFC 7540 (HTTP/2), RFC 7541 (HPACK)
- `HTTP2.lean`: Frame types, stream states
- `HPACK.lean`: Static table, dynamic table, Huffman coding

**Exercises**:
1. How does HTTP/2 multiplexing differ from HTTP/1.1 pipelining?
2. Why does HPACK use both a static and dynamic table?
3. What is a CONTINUATION frame? When is it needed?
4. Read `hpack_integer_encode_decode_inverse`. Why is codec correctness important?
5. **Challenge**: Implement HPACK dynamic table size update (RFC 7541 §6.3)

---

#### Lesson 6: **WebSocket Protocol**
📁 `LeanServer/Protocol/WebSocket.lean`

**Concepts**: Upgrade mechanism, frame format, masking

**Reading**:
- RFC 6455 (WebSocket Protocol)
- `WebSocket.lean`: Frame parsing, masking/unmasking

**Exercises**:
1. Why does WebSocket require client-to-server masking?
2. Read `websocket_frame_mask_involution`. Why is XOR its own inverse?
3. How does WebSocket over HTTP/2 (RFC 8441) work differently?
4. **Challenge**: Implement WebSocket ping/pong heartbeat with timeout

---

### Part III: Verification (Weeks 7-8)

#### Lesson 7: **Writing Proofs in Lean 4**
📁 `LeanServer/Proofs.lean`

**Concepts**: Tactics, theorem statements, proof strategies

**Reading**:
- Lean 4 documentation: Tactics chapter
- `Proofs.lean`: All 914 theorems

**Exercises**:
1. Prove: `theorem my_sha256_nonempty : (SHA256.hash data).size > 0`
2. Why can't we prove `SHA256.hash data ≠ SHA256.hash data'` for all `data ≠ data'`?
3. What is the `partial` keyword? Why do 4 functions use it? Is this a soundness concern?
4. **Challenge**: Prove a new property about HMAC: if the key changes, the output changes (for specific test vectors)

---

#### Lesson 8: **Verified Networking — Putting It All Together**
📁 `LeanServer/Server/HTTPServer.lean`

**Concepts**: IO monad, FFI, event loops, production concerns

**Reading**:
- `HTTPServer.lean`: Server main loop, TLS integration
- `src/Network.c`: C FFI for sockets and epoll

**Exercises**:
1. Why does LeanServer use C FFI for sockets instead of pure Lean?
2. What is epoll? How does it improve over blocking accept()?
3. What guarantees does the buffer pool provide? Why zero-fill on acquire and release?
4. **Final Project**: Build a simple chat server using WebSocket over TLS 1.3, with at least 3 custom proofs about your message handling logic.

---

## Grading Rubric (if used as a course)

| Component | Weight |
|-----------|--------|
| Exercises (8 lessons × 4 exercises) | 40% |
| Challenge problems (8 × 1) | 20% |
| Final project | 30% |
| Proof quality & style | 10% |

## Prerequisites

- Functional programming basics (Haskell, OCaml, or similar)
- Basic algebra (groups, fields at undergrad level)
- Familiarity with TCP/IP networking
- No prior Lean experience required (Lesson 1 includes Lean setup)

## Setup

```bash
# Install Lean 4
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Clone the project
git clone https://github.com/AfonsoBitoque/LeanServer
cd LeanServer
lake build leanserver

# Run tests to verify setup
.lake/build/bin/test_integration
# Expected: 20/20 tests passed
```
