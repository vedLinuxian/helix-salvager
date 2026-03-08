# ─────────────────────────────────────────────────────────
#  Helix Salvager — Multi-stage Docker Build
# ─────────────────────────────────────────────────────────
# Build:  docker build -t helix-salvager .
# Run:    docker run -p 5001:5001 helix-salvager
# CLI:    docker run -v $(pwd):/data helix-salvager salvager recover /data/file.zip -o /data/out/

FROM rust:1.88-bookworm AS builder

WORKDIR /build

# ── Cache dependencies first ──
COPY Cargo.toml Cargo.lock ./
COPY crates/salvager-core/Cargo.toml crates/salvager-core/Cargo.toml
COPY crates/salvager-cli/Cargo.toml crates/salvager-cli/Cargo.toml
COPY crates/salvager-server/Cargo.toml crates/salvager-server/Cargo.toml

# Create dummy source files for dependency caching
RUN mkdir -p crates/salvager-core/src && echo "pub fn _dummy() {}" > crates/salvager-core/src/lib.rs && \
    mkdir -p crates/salvager-cli/src && echo "fn main() {}" > crates/salvager-cli/src/main.rs && \
    mkdir -p crates/salvager-server/src && echo "fn main() {}" > crates/salvager-server/src/main.rs && \
    cargo build --release 2>/dev/null || true

# ── Build real source ──
COPY crates/ crates/
RUN touch crates/salvager-core/src/lib.rs crates/salvager-cli/src/main.rs crates/salvager-server/src/main.rs && \
    cargo build --release

# ── Runtime image ──
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        liblzma5 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash helix
USER helix
WORKDIR /home/helix

# Copy binaries
COPY --from=builder /build/target/release/salvager /usr/local/bin/
COPY --from=builder /build/target/release/salvager-server /usr/local/bin/

# Copy static files
COPY --chown=helix:helix crates/salvager-server/static /opt/helix/static

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:5001/api/health || exit 1

EXPOSE 5001

LABEL org.opencontainers.image.title="Helix Salvager" \
      org.opencontainers.image.description="Corrupt archive recovery engine" \
      org.opencontainers.image.source="https://github.com/vedLinuxian/helix-salvager" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["salvager-server"]
CMD ["--bind", "0.0.0.0", "--port", "5001"]
