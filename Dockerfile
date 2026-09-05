# Dockerfile for `agency-server` (2.9.0, ADR-0041).
#
# Multi-stage build:
#   1. `rust` — full toolchain, builds release binaries.
#   2. `cc` (distroless) — minimal base with glibc + CA certs.
#
# Output: ~30 MB image with two static-ish binaries
# (`agency-server` + `agency`). The image runs as a
# non-root user; SQLite state is mounted from the host.
#
# Build (from repo root):
#   docker build -t agency-server:dev .
#
# Run:
#   docker run --rm -p 8080:8080 \
#     -v agency-data:/var/lib/agency \
#     -e AGENCY_VAULT_PASSPHRASE=... \
#     agency-server:dev
#
# See `docs/DEPLOY.md` for the full
# docker-compose stack with caddy.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:1.83-bookworm AS builder

# 1.1 — system deps. The C deps below
# are the minimum needed for
# `git2` (vendored-libgit2 uses
# libz, libssl, and the system
# libssh2) + `reqwest` (rustls-tls,
# but we still link a few system
# crates through `ring`).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        zlib1g-dev \
        libssh2-1-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# 1.2 — pre-cache the dependency
# graph. Copying just the manifests
# first means a code-only change
# does NOT re-download every crate.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/hermes-adapter/Cargo.toml crates/hermes-adapter/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml
COPY crates/server/Cargo.toml crates/server/Cargo.toml
COPY crates/tauri-app/Cargo.toml crates/tauri-app/Cargo.toml

# 1.3 — generate stub `lib.rs` /
# `main.rs` files so `cargo fetch`
# resolves every workspace member
# (the real sources are copied
# later). Without this step the
# resolver sees no source and
# refuses to index the manifests.
RUN mkdir -p crates/core/src crates/hermes-adapter/src \
        crates/cli/src crates/server/src crates/tauri-app/src && \
    for c in core hermes-adapter cli server tauri-app; do \
        printf 'fn main() {}\n' > crates/$c/src/main.rs; \
        printf '' > crates/$c/src/lib.rs; \
    done
RUN cargo fetch --locked

# 1.4 — copy the real source tree
# and build the two binaries we
# ship. The Tauri desktop app
# (`crates/tauri-app`) is for
# operator workstations only;
# skipping it here keeps the
# Docker image lean.
COPY crates ./crates
RUN cargo build --release \
        -p agency-server \
        -p agency \
    && strip target/release/agency-server \
    && strip target/release/agency

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# 2.1 — distroless ships without a
# shell, so HEALTHCHECK would
# need a static binary. The
# axum server exposes `GET /v1/health`
# — the compose file uses `wget`
# from caddy-side to probe. No
# HEALTHCHECK here.

# 2.2 — the two stripped binaries
COPY --from=builder /build/target/release/agency-server /usr/local/bin/agency-server
COPY --from=builder /build/target/release/agency         /usr/local/bin/agency

# 2.3 — non-root is the distroless
# default (`nonroot` user, uid
# 65532). Persistent state lives
# on the bind-mounted volume.
USER nonroot:nonroot
WORKDIR /var/lib/agency

EXPOSE 8080

# 2.4 — bind 0.0.0.0:8080 by default.
# Override AGENCY_BIND_IP / AGENCY_BIND_PORT
# via env, or pass `--bind` to
# the binary directly. The
# compose file maps 8080 on the
# host; the distroless base has no
# shell so entrypoint is the
# binary itself.
ENTRYPOINT ["/usr/local/bin/agency-server", "--bind", "0.0.0.0", "--port", "8080"]
