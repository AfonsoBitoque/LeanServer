# CBMC Proof Harnesses

Bounded model checking for the C FFI layer, following the approach
used by [s2n-tls](https://github.com/aws/s2n-tls/tree/main/tests/cbmc).

## Harnesses

### `network_harnesses.c` — 10 harnesses for `Network.c`

| # | Harness | Property Verified |
|---|---------|-------------------|
| 1 | `lean_send_harness` | No buffer overflow, valid IO result |
| 2 | `lean_recv_harness` | No buffer overflow, valid IO result |
| 3 | `lean_epoll_wait_harness` | Bounded allocation (clamped to 1024), no leak |
| 4 | `lean_bind_harness` | Port fits uint16_t, correct htons |
| 5 | `lean_socket_create_harness` | Valid protocol type mapping |
| 6 | `lean_sendto_harness` | IP address parsing safety |
| 7 | `lean_set_socket_timeout_harness` | No integer overflow in ms→timeval |
| 8 | `lean_signal_harness` | Signal handler install + query safety |
| 9 | `lean_socket_connect_harness` | IPv4→IPv6 mapping correctness |
| 10 | `lean_closesocket_harness` | Double-close safety |

### `sqlite_harnesses.c` — 5 harnesses for `sqlite_ffi.c`

| # | Harness | Property Verified |
|---|---------|-------------------|
| 1 | `lean_sqlite_open_stub_harness` | Stub returns valid error |
| 2 | `lean_sqlite_exec_stub_harness` | Stub returns valid error |
| 3 | `lean_sqlite_close_stub_harness` | Double-close safety |
| 4 | `lean_sqlite_changes_stub_harness` | Stub returns valid result |
| 5 | `lean_sqlite_last_insert_rowid_stub_harness` | Stub returns valid result |

## Running

```bash
# Install CBMC
# Ubuntu: sudo apt install cbmc
# macOS:  brew install cbmc

# Run a specific harness
cbmc --function lean_send_harness \
     src/Network.c cbmc/network_harnesses.c \
     -I $(lean --print-prefix)/include \
     --unwind 10

# Run all network harnesses
for h in lean_send_harness lean_recv_harness lean_epoll_wait_harness \
         lean_bind_harness lean_socket_create_harness lean_sendto_harness \
         lean_set_socket_timeout_harness lean_signal_harness \
         lean_socket_connect_harness lean_closesocket_harness; do
  echo "=== $h ==="
  cbmc --function "$h" src/Network.c cbmc/network_harnesses.c \
       -I $(lean --print-prefix)/include --unwind 10
done

# Run all SQLite harnesses
for h in lean_sqlite_open_stub_harness lean_sqlite_exec_stub_harness \
         lean_sqlite_close_stub_harness lean_sqlite_changes_stub_harness \
         lean_sqlite_last_insert_rowid_stub_harness; do
  echo "=== $h ==="
  cbmc --function "$h" src/sqlite_ffi.c cbmc/sqlite_harnesses.c \
       -I $(lean --print-prefix)/include --unwind 10
done
```

## Approach

Each harness:
1. **Mocks the Lean runtime** — Provides stub implementations of `lean_mk_string`,
   `lean_io_result_mk_ok`, `lean_sarray_cptr`, etc. with CBMC assertions on preconditions.
2. **Uses nondeterministic inputs** — `__CPROVER_assume` constrains inputs to valid ranges.
3. **Asserts safety properties** — No null dereferences, no buffer overflows,
   valid result construction.

This mirrors the s2n-tls approach where each C function gets its own
proof harness with bounded verification.
