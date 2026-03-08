# ─────────────────────────────────────────────────────────
#  Helix Salvager — Makefile
# ─────────────────────────────────────────────────────────

.PHONY: all build release test lint fmt audit clean docker run bench install help

CARGO  := cargo
DOCKER := docker

# Default target
all: lint test build

# ── Build ────────────────────────────────────────────────
build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --release --workspace

# ── Test ─────────────────────────────────────────────────
test:
	$(CARGO) test --workspace

test-verbose:
	$(CARGO) test --workspace -- --nocapture

test-real:
	$(CARGO) test --test real_file_tests -- --nocapture

test-stress:
	$(CARGO) test --test stress_tests -- --nocapture

# ── Lint & Format ────────────────────────────────────────
lint:
	$(CARGO) clippy --all-targets --workspace -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# ── Security ─────────────────────────────────────────────
audit:
	cargo audit

# ── Documentation ────────────────────────────────────────
doc:
	$(CARGO) doc --workspace --no-deps --open

# ── Run ──────────────────────────────────────────────────
run-server:
	$(CARGO) run -p salvager-server

run-server-release:
	$(CARGO) run --release -p salvager-server

recover:
	@echo "Usage: make recover FILE=path/to/archive.zip OUT=./recovered/"
	$(CARGO) run -p salvager-cli -- recover $(FILE) -o $(OUT)

inspect:
	@echo "Usage: make inspect FILE=path/to/archive.zip"
	$(CARGO) run -p salvager-cli -- inspect $(FILE)

# ── Benchmark ────────────────────────────────────────────
bench:
	$(CARGO) bench --workspace

# ── Docker ───────────────────────────────────────────────
docker:
	$(DOCKER) build -t helix-salvager .

docker-run:
	$(DOCKER) run -p 5001:5001 helix-salvager

# ── Install ──────────────────────────────────────────────
install:
	$(CARGO) install --path crates/salvager-cli
	$(CARGO) install --path crates/salvager-server

# ── Clean ────────────────────────────────────────────────
clean:
	$(CARGO) clean
	rm -rf test_real_world/

# ── Cross-compile (requires cross) ──────────────────────
cross-linux:
	cross build --release --target x86_64-unknown-linux-gnu

cross-windows:
	cross build --release --target x86_64-pc-windows-gnu

cross-macos:
	cross build --release --target x86_64-apple-darwin

cross-all: cross-linux cross-windows cross-macos

# ── Help ─────────────────────────────────────────────────
help:
	@echo "Helix Salvager — Build Commands"
	@echo ""
	@echo "  make              Build + lint + test"
	@echo "  make build        Debug build"
	@echo "  make release      Release build (optimized)"
	@echo "  make test         Run all 179 tests"
	@echo "  make test-real    Run real-file tests only"
	@echo "  make lint         Clippy with zero warnings"
	@echo "  make fmt          Format code"
	@echo "  make audit        Security audit dependencies"
	@echo "  make doc          Generate & open docs"
	@echo "  make run-server   Start web UI (debug)"
	@echo "  make docker       Build Docker image"
	@echo "  make docker-run   Run Docker container"
	@echo "  make install      Install CLI + server to ~/.cargo/bin"
	@echo "  make clean        Remove build artifacts"
	@echo "  make bench        Run benchmarks"
	@echo ""
	@echo "  make recover FILE=archive.zip OUT=./out/"
	@echo "  make inspect FILE=archive.zip"
