// Network.c — Minimal POSIX FFI bridge for Lean 4
// Only contains syscall wrappers that CANNOT be expressed in pure Lean:
//   - BSD sockets (socket, bind, listen, accept, recv, send, recvfrom, sendto)
//   - Socket options (setsockopt for timeouts, TCP_NODELAY, SO_REUSEADDR)
//   - Signal handling (SIGINT/SIGTERM for graceful shutdown)
//   - Peer address extraction (getpeername)
//   - epoll event loop primitives
//
// Threading is handled by Lean's native IO.asTask (green threads).
// No pthreads, no C-level mutexes, no thread count tracking.
// See LeanServer/Server/Concurrency.lean for the pure Lean concurrency layer.

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <lean/lean.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/epoll.h>
#include <fcntl.h>

// ==========================================
// Error Helpers
// ==========================================

static lean_obj_res lean_io_error_from_errno(const char* msg) {
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(msg)));
}

// ==========================================
// Graceful Shutdown (Signal Handling)
// ==========================================

static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile sig_atomic_t g_reload_requested = 0;

static void signal_handler(int signum) {
    (void)signum;
    g_shutdown_requested = 1;
}

static void sighup_handler(int signum) {
    (void)signum;
    g_reload_requested = 1;
}

LEAN_EXPORT lean_obj_res lean_install_signal_handlers(lean_object* _monitor) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    // SIGHUP → config reload
    struct sigaction sa_hup;
    memset(&sa_hup, 0, sizeof(sa_hup));
    sa_hup.sa_handler = sighup_handler;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
    return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lean_shutdown_requested(lean_object* _monitor) {
    return lean_io_result_mk_ok(lean_box(g_shutdown_requested ? 1 : 0));
}

LEAN_EXPORT lean_obj_res lean_reload_requested(lean_object* _monitor) {
    int val = g_reload_requested;
    if (val) g_reload_requested = 0;  /* auto-clear on read */
    return lean_io_result_mk_ok(lean_box(val ? 1 : 0));
}

// ==========================================
// TCP Socket Operations
// ==========================================

LEAN_EXPORT lean_obj_res lean_socket_create(uint32_t proto_type, lean_object* _monitor) {
    int type = (proto_type == 1) ? SOCK_DGRAM : SOCK_STREAM;
    int proto = (proto_type == 1) ? IPPROTO_UDP : IPPROTO_TCP;
    int s = socket(AF_INET6, type, proto);

    if (s < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Dual-stack: accept both IPv4 and IPv6 connections
    int v6only = 0;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)s));
}

LEAN_EXPORT lean_obj_res lean_bind(uint64_t s, uint32_t port, lean_object* _monitor) {
    struct sockaddr_in6 service;
    memset(&service, 0, sizeof(service));
    service.sin6_family = AF_INET6;
    service.sin6_addr = in6addr_any;
    service.sin6_port = htons((uint16_t)port);

    if (bind((int)s, (struct sockaddr*)&service, sizeof(service)) < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lean_listen(uint64_t s, int32_t backlog, lean_object* _monitor) {
    if (listen((int)s, (int)backlog) < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lean_accept(uint64_t s, lean_object* _monitor) {
    int clientSocket = accept((int)s, NULL, NULL);
    if (clientSocket < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }

    // TCP_NODELAY: disable Nagle's algorithm for lower latency
    int one = 1;
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // 100ms recv timeout for client sockets
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)clientSocket));
}

LEAN_EXPORT lean_obj_res lean_closesocket(uint64_t s, lean_object* _monitor) {
    close((int)s);
    return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lean_set_socket_timeout(uint64_t s, uint32_t timeout_ms, lean_object* _monitor) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt((int)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    return lean_io_result_mk_ok(lean_box(0));
}

// ==========================================
// Data Transfer
// ==========================================

LEAN_EXPORT lean_obj_res lean_recv(uint64_t s, lean_object* buf, uint32_t len, uint32_t flags, lean_object* _monitor) {
    uint8_t* rawBuf = lean_sarray_cptr(buf);
    ssize_t result = recv((int)s, rawBuf, (size_t)len, (int)flags);
    if (result < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)result));
}

LEAN_EXPORT lean_obj_res lean_send(uint64_t s, lean_object* buf, uint32_t len, uint32_t flags, lean_object* _monitor) {
    uint8_t* rawBuf = lean_sarray_cptr(buf);
    // Single send call — retry logic is in pure Lean (Concurrency.sendWithRetry)
    ssize_t result = send((int)s, rawBuf, (size_t)len, (int)flags | MSG_NOSIGNAL);
    if (result < 0) {
        if (errno == EINTR) {
            // Interrupted by signal — report 0 bytes, let Lean retry
            return lean_io_result_mk_ok(lean_box_uint32(0));
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Would block — report 0 bytes, let Lean handle backoff
            return lean_io_result_mk_ok(lean_box_uint32(0));
        }
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)result));
}

// ==========================================
// UDP Extensions (for QUIC)
// ==========================================

LEAN_EXPORT lean_obj_res lean_recvfrom(uint64_t s, lean_object* buf, uint32_t len, lean_object* _monitor) {
    uint8_t* rawBuf = lean_sarray_cptr(buf);
    struct sockaddr_in6 client_addr;
    socklen_t addr_len = sizeof(client_addr);

    ssize_t result = recvfrom((int)s, rawBuf, (size_t)len, 0, (struct sockaddr*)&client_addr, &addr_len);
    if (result < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }

    // Convert IP to string (handle both IPv6 and IPv4-mapped)
    char ipStr[INET6_ADDRSTRLEN];
    if (IN6_IS_ADDR_V4MAPPED(&client_addr.sin6_addr)) {
        struct in_addr v4addr;
        memcpy(&v4addr, &client_addr.sin6_addr.s6_addr[12], 4);
        inet_ntop(AF_INET, &v4addr, ipStr, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &(client_addr.sin6_addr), ipStr, INET6_ADDRSTRLEN);
    }

    uint16_t port = ntohs(client_addr.sin6_port);

    // Return (bytesRead, (ip, port))
    lean_object* inner_pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(inner_pair, 0, lean_mk_string(ipStr));
    lean_ctor_set(inner_pair, 1, lean_box_uint32((uint32_t)port));

    lean_object* outer_pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(outer_pair, 0, lean_box_uint32((uint32_t)result));
    lean_ctor_set(outer_pair, 1, inner_pair);

    return lean_io_result_mk_ok(outer_pair);
}

LEAN_EXPORT lean_obj_res lean_sendto(uint64_t s, lean_object* buf, uint32_t len, lean_object* ip_str, uint32_t port, lean_object* _monitor) {
    uint8_t* rawBuf = lean_sarray_cptr(buf);

    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    dest_addr.sin6_port = htons((uint16_t)port);

    const char* ip = lean_string_cstr(ip_str);
    if (inet_pton(AF_INET6, ip, &dest_addr.sin6_addr) <= 0) {
        // Try IPv4 -> IPv4-mapped IPv6 (::ffff:x.x.x.x)
        struct in_addr v4addr;
        if (inet_pton(AF_INET, ip, &v4addr) <= 0) {
            return lean_io_error_from_errno("Invalid IP address");
        }
        memset(&dest_addr.sin6_addr, 0, 10);
        dest_addr.sin6_addr.s6_addr[10] = 0xFF;
        dest_addr.sin6_addr.s6_addr[11] = 0xFF;
        memcpy(&dest_addr.sin6_addr.s6_addr[12], &v4addr, 4);
    }

    ssize_t result = sendto((int)s, rawBuf, (size_t)len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (result < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box_uint32((uint32_t)result));
}

// ==========================================
// Peer Address (for per-IP rate limiting)
// ==========================================

LEAN_EXPORT lean_obj_res lean_getpeername(uint64_t s, lean_object* _monitor) {
    struct sockaddr_in6 addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername((int)s, (struct sockaddr*)&addr, &addr_len) < 0) {
        return lean_io_result_mk_ok(lean_mk_string("0.0.0.0"));
    }
    char ipStr[INET6_ADDRSTRLEN];
    if (IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
        struct in_addr v4addr;
        memcpy(&v4addr, &addr.sin6_addr.s6_addr[12], 4);
        inet_ntop(AF_INET, &v4addr, ipStr, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &addr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
    }
    return lean_io_result_mk_ok(lean_mk_string(ipStr));
}

// ==========================================
// epoll Event Loop Primitives
// ==========================================

// epollCreate : IO UInt64
// Creates an epoll instance; returns the epoll fd.
LEAN_EXPORT lean_obj_res lean_epoll_create(lean_object* _monitor) {
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)epfd));
}

// epollAdd : UInt64 → UInt64 → UInt32 → IO Unit
// Adds fd to epoll set with given events (EPOLLIN=1, EPOLLOUT=4, EPOLLET=0x80000000).
LEAN_EXPORT lean_obj_res lean_epoll_add(uint64_t epfd, uint64_t fd, uint32_t events, lean_object* _monitor) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = (int)fd;
    if (epoll_ctl((int)epfd, EPOLL_CTL_ADD, (int)fd, &ev) < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box(0));
}

// epollModify : UInt64 → UInt64 → UInt32 → IO Unit
// Modifies the events for a fd already in the epoll set.
LEAN_EXPORT lean_obj_res lean_epoll_modify(uint64_t epfd, uint64_t fd, uint32_t events, lean_object* _monitor) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = (int)fd;
    if (epoll_ctl((int)epfd, EPOLL_CTL_MOD, (int)fd, &ev) < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box(0));
}

// epollRemove : UInt64 → UInt64 → IO Unit
// Removes a fd from the epoll set.
LEAN_EXPORT lean_obj_res lean_epoll_remove(uint64_t epfd, uint64_t fd, lean_object* _monitor) {
    if (epoll_ctl((int)epfd, EPOLL_CTL_DEL, (int)fd, NULL) < 0) {
        if (errno != ENOENT) {
            return lean_io_error_from_errno(strerror(errno));
        }
    }
    return lean_io_result_mk_ok(lean_box(0));
}

// epollWait : UInt64 → UInt32 → UInt32 → IO (Array (UInt64 × UInt32))
// Waits for events. maxEvents = max events to return, timeoutMs = timeout in ms.
// Returns array of (fd, eventMask) pairs.
LEAN_EXPORT lean_obj_res lean_epoll_wait(uint64_t epfd, uint32_t maxEvents, uint32_t timeoutMs, lean_object* _monitor) {
    if (maxEvents == 0) maxEvents = 64;
    if (maxEvents > 1024) maxEvents = 1024;

    struct epoll_event *events = (struct epoll_event *)malloc(maxEvents * sizeof(struct epoll_event));
    if (!events) {
        return lean_io_error_from_errno("epoll_wait: out of memory");
    }

    int n = epoll_wait((int)epfd, events, (int)maxEvents, (int)timeoutMs);
    if (n < 0) {
        free(events);
        if (errno == EINTR) {
            lean_obj_res arr = lean_mk_empty_array();
            return lean_io_result_mk_ok(arr);
        }
        return lean_io_error_from_errno(strerror(errno));
    }

    lean_obj_res arr = lean_mk_empty_array();
    for (int i = 0; i < n; i++) {
        lean_obj_res pair = lean_alloc_ctor(0, 2, 0);
        lean_ctor_set(pair, 0, lean_box_uint64((uint64_t)events[i].data.fd));
        lean_ctor_set(pair, 1, lean_box_uint32(events[i].events));
        arr = lean_array_push(arr, pair);
    }

    free(events);
    return lean_io_result_mk_ok(arr);
}

// setNonBlocking : UInt64 → IO Unit
// Sets a socket to non-blocking mode via fcntl.
LEAN_EXPORT lean_obj_res lean_set_nonblocking(uint64_t fd, lean_object* _monitor) {
    int flags = fcntl((int)fd, F_GETFL, 0);
    if (flags < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    if (fcntl((int)fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }
    return lean_io_result_mk_ok(lean_box(0));
}

// acceptNonBlocking : UInt64 → IO (Option UInt64)
// Non-blocking accept: returns some(clientFd) or none if EAGAIN.
LEAN_EXPORT lean_obj_res lean_accept_nonblocking(uint64_t serverSock, lean_object* _monitor) {
    struct sockaddr_in6 client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int clientFd = accept((int)serverSock, (struct sockaddr*)&client_addr, &addr_len);
    if (clientFd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return lean_io_result_mk_ok(lean_box(0)); /* Option.none */
        }
        return lean_io_error_from_errno(strerror(errno));
    }
    lean_obj_res some_obj = lean_alloc_ctor(1, 1, 0); /* Option.some */
    lean_ctor_set(some_obj, 0, lean_box_uint64((uint64_t)clientFd));
    return lean_io_result_mk_ok(some_obj);
}

// ==========================================
// Outbound TCP Connect (for reverse proxy)
// ==========================================

// socketConnect : String → UInt32 → IO UInt64
// Connects to a remote host:port and returns the connected socket fd.
LEAN_EXPORT lean_obj_res lean_socket_connect(lean_object* host_str, uint32_t port, lean_object* _monitor) {
    const char *host = lean_string_cstr(host_str);

    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        return lean_io_error_from_errno(strerror(errno));
    }

    // Disable Nagle's algorithm for proxy latency
    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)port);

    // Try IPv6 first, then IPv4-mapped
    if (inet_pton(AF_INET6, host, &addr.sin6_addr) <= 0) {
        struct in_addr v4addr;
        if (inet_pton(AF_INET, host, &v4addr) <= 0) {
            close(sock);
            return lean_io_error_from_errno("Invalid host address");
        }
        // Map IPv4 → IPv6 (::ffff:x.x.x.x)
        memset(&addr.sin6_addr, 0, 10);
        addr.sin6_addr.s6_addr[10] = 0xFF;
        addr.sin6_addr.s6_addr[11] = 0xFF;
        memcpy(&addr.sin6_addr.s6_addr[12], &v4addr, 4);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return lean_io_error_from_errno(strerror(errno));
    }

    return lean_io_result_mk_ok(lean_box_uint64((uint64_t)sock));
}
