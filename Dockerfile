# Multi-stage Rust build for TAP proxy
# Uses dummy-build trick to cache dependency compilation in a separate layer.

FROM rust:1.88-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y pkg-config libssl-dev curl && rm -rf /var/lib/apt/lists/*

# Install Node.js for Svelte dashboard build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# Step 1: Copy manifests and create dummy sources to build only dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/tap-core/Cargo.toml crates/tap-core/Cargo.toml
COPY crates/tap-bot/Cargo.toml crates/tap-bot/Cargo.toml
COPY crates/tap-proxy/Cargo.toml crates/tap-proxy/Cargo.toml
COPY crates/tap-cli/Cargo.toml crates/tap-cli/Cargo.toml
COPY crates/tap-mcp/Cargo.toml crates/tap-mcp/Cargo.toml

RUN mkdir -p crates/tap-core/src && echo "" > crates/tap-core/src/lib.rs \
 && mkdir -p crates/tap-bot/src && echo "" > crates/tap-bot/src/lib.rs \
 && mkdir -p crates/tap-proxy/src && echo "fn main(){}" > crates/tap-proxy/src/main.rs && echo "" > crates/tap-proxy/src/lib.rs \
 && mkdir -p crates/tap-cli/src && echo "fn main(){}" > crates/tap-cli/src/main.rs \
 && mkdir -p crates/tap-mcp/src && echo "fn main(){}" > crates/tap-mcp/src/main.rs && echo "" > crates/tap-mcp/src/lib.rs

# Build dependencies only (cached when only source changes)
RUN cargo build --release 2>/dev/null || true

# Step 2: Copy dashboard source and pre-build it
COPY crates/tap-proxy/dashboard/package.json crates/tap-proxy/dashboard/package-lock.json crates/tap-proxy/dashboard/
RUN cd crates/tap-proxy/dashboard && npm ci
COPY crates/tap-proxy/dashboard/ crates/tap-proxy/dashboard/
# The recipe catalog is shared: the dashboard imports it at build time and the
# proxy include_str!s it. It lives at the crate root, outside dashboard/, so it
# must be copied before the dashboard build (Step 3's COPY comes too late).
COPY crates/tap-proxy/recipes.json crates/tap-proxy/recipes.json
RUN cd crates/tap-proxy/dashboard && npm run build

# Step 3: Copy real source and build
COPY crates/ crates/
RUN find crates -name "*.rs" -exec touch {} +
RUN cargo build --release --bin tap-proxy --bin tap

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/tap-proxy /usr/local/bin/tap-proxy
COPY --from=builder /build/target/release/tap /usr/local/bin/tap

RUN useradd -r -s /bin/false tap \
 && mkdir -p /data/db && chown tap:tap /data /data/db
USER tap

ENV TAP_AUDIT_LOG=/data/audit.jsonl

EXPOSE 3100

ENTRYPOINT ["tap-proxy"]
