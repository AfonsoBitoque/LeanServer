# Multi-stage build for optimized image
FROM ubuntu:24.04 AS builder

# Install Lean 4 via elan + build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    git \
    libgmp-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install elan (Lean toolchain manager)
RUN curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
ENV PATH="/root/.elan/bin:${PATH}"

# Copy source code
WORKDIR /app
COPY . .

# Build (lean-toolchain specifies the exact Lean version)
RUN lake build leanserver

# Minimal runtime image
FROM ubuntu:24.04

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libgmp10 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false leanserver

# Copy compiled binary
COPY --from=builder /app/.lake/build/bin/leanserver /usr/local/bin/leanserver

# Copy configuration
COPY server.config /etc/leanserver/server.config

# Create necessary directories
RUN mkdir -p /var/log/leanserver /etc/leanserver/ssl && \
    chown -R leanserver:leanserver /var/log/leanserver

# Note: TLS certificates must be mounted at runtime:
#   docker run -v ./cert.pem:/etc/leanserver/ssl/cert.pem \
#              -v ./key.pem:/etc/leanserver/ssl/key.pem \
#              leanserver

USER leanserver

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD test -f /proc/1/status || exit 1

CMD ["/usr/local/bin/leanserver"]
