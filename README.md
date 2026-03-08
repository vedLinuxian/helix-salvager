<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.75+-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT%2FApache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Tests-179%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Clippy-0%20warnings-brightgreen?style=flat-square" alt="Clippy">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
</p>

<br>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/banner-light.svg">
    <img alt="Helix Salvager" src="docs/assets/banner-dark.svg" width="700">
  </picture>
</p>

<p align="center">
  <strong>Corrupt archive recovery engine.</strong><br>
  Extracts files from broken ZIPs, damaged 7z archives, truncated tarballs, and raw binary blobs<br>
  when every other tool says <em>"archive is corrupted."</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#benchmarks">Benchmarks</a> •
  <a href="#web-ui">Web UI</a> •
  <a href="#api">API</a> •
  <a href="#docker">Docker</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## The Problem

You downloaded a 2 GB archive. It's corrupt. Every tool you try:

```
$ unzip backup.zip
error [backup.zip]:  reported length of central directory is
  -14 bytes too long. Aborting.

$ 7z x backup.7z
ERROR: Can not open output file : Data Error

$ tar xzf data.tar.gz
gzip: data.tar.gz: unexpected end of file
tar: Child returned status 1
```

**Your files are still in there.** The archive metadata is damaged, but the actual file data — your photos, documents, source code — is largely intact. You just need a tool smart enough to get it out.

## The Solution

**Helix Salvager** is a Rust-based recovery engine that uses three strategies simultaneously:

```
┌──────────────────────────────────────────────────────────┐
│                  CORRUPT ARCHIVE INPUT                    │
│            (ZIP, 7z, gzip, bzip2, xz, tar, raw)         │
└──────────────────────┬───────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐
   │  Engine A  │ │  Engine B  │ │  Engine C  │
   │ Fail-Fwd  │ │  Zombie   │ │  Magic     │
   │ Extractor │ │  LZMA     │ │  Carver    │
   └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
         │             │             │
         │  Per-file   │  Entropy-   │  29-sig
         │  isolation  │  guided     │  Aho-Corasick
         │  skip bad   │  fault-     │  raw byte
         │  entries    │  tolerant   │  scanning
         │             │  decoding   │
         └─────────────┼─────────────┘
                       │
                       ▼
         ┌─────────────────────────┐
         │     RECOVERED FILES     │
         │  SHA-256 integrity      │
         │  Per-type breakdown     │
         │  Taint analysis         │
         └─────────────────────────┘
```

## Quick Start

### Install from source

```bash
git clone https://github.com/vedLinuxian/helix-salvager.git
cd helix-salvager
cargo build --release
```

### Recover files from a corrupt archive

```bash
# Recover to directory
./target/release/salvager recover broken_archive.zip -o ./recovered/

# Recover as ZIP
./target/release/salvager recover damaged.7z -o recovered.zip --zip

# Inspect without extracting
./target/release/salvager inspect suspicious_file.bin

# JSON output (for scripting)
./target/release/salvager recover data.zip -o ./out/ --json --quiet
```

### Launch the Web UI

```bash
# Quick launch
./start.sh

# Custom port
./start.sh --port 8080

# Random available port
./start.sh --random-port

# Release mode (optimized)
./start.sh --release
```

### Docker

```bash
docker build -t helix-salvager .
docker run -p 5001:5001 -v ./archives:/data helix-salvager

# Or recover directly
docker run -v ./:/data helix-salvager salvager recover /data/broken.zip -o /data/recovered/
```

## How It Works

### Engine A — Fail-Forward Extraction

Standard tools abort on the first corrupted entry. Helix Salvager isolates each file in the archive and extracts them independently. If file 3 of 10 is corrupt, you get the other 9.

```
Standard:  File1 ✓ → File2 ✓ → File3 ✗ → ABORT (0 files saved)
Helix:     File1 ✓ → File2 ✓ → File3 ✗ → File4 ✓ → ... → File10 ✓ (9 files saved)
```

Supports: ZIP (deflate, store), gzip, bzip2, xz, and tar containers.

### Engine B — Zombie LZMA Decoder

A custom fault-tolerant LZMA decompression pipeline for 7z archives:

1. **Full-stream attempt** — Try standard decompression first
2. **Shannon entropy validation** — Detect if output is real data or noise
3. **Chunked retry** — On failure, slide forward byte-by-byte to find next decodable region
4. **Taint mapping** — Bit-vector marking which output bytes are trustworthy vs. reconstructed

```
Entropy Classification:
  H < 1.5  →  Padding/Empty     (discard)
  1.5–7.85 →  Structured Data   (keep — this is your file content)
  H > 7.85 →  Random Noise      (mark as tainted)
```

### Engine C — Magic Header Carver

When archive metadata is completely destroyed, the carver scans raw bytes for known file signatures using an Aho-Corasick multi-pattern automaton. It recognizes **29 file types**:

| Category | Types |
|----------|-------|
| **Images** | JPEG, PNG, GIF, BMP, WebP, TIFF, ICO, PSD |
| **Documents** | PDF |
| **Audio** | WAV, MP3, FLAC, OGG |
| **Video** | MP4, AVI |
| **Archives** | ZIP, RAR, 7z, TAR |
| **Executables** | ELF, PE/EXE, WASM |

Each carved file undergoes:
- **Size validation** — Reject implausibly small/large extractions
- **Structure validation** — Check internal consistency (e.g., ICO reserved bytes, PNG chunk structure)
- **SHA-256 deduplication** — Eliminate duplicate extractions

## Benchmarks

Tested against standard tools on intentionally corrupted archives:

| Scenario | `unzip` | `7z` | `tar` | **Helix Salvager** |
|----------|---------|------|-------|-------------------|
| 1 dead sector in 7-file ZIP | **ABORT** | **ABORT** | n/a | **6/7 files** ✓ |
| 20% sectors zeroed | **ABORT** | **ABORT** | n/a | **3/7 files** ✓ |
| Central directory destroyed | **ABORT** | 0 files | n/a | **5/7 files** ✓ |
| Truncated at 50% | **ABORT** | **ABORT** | **ABORT** | **4/7 files** ✓ |
| Heavy bitrot (100 bit flips) | **ABORT** | **ABORT** | n/a | **2/7 files** ✓ |
| NAND flash degradation | **ABORT** | **ABORT** | n/a | **4/7 files** ✓ |
| Truncated gzip tarball at 60% | n/a | n/a | **ABORT** | **Partial** ✓ |
| CVE-2018-0986 exploit RAR | n/a | ⚠️ | n/a | **Safe** ✓ |

### Test Suite

```
179 tests, 0 failures, 0 clippy warnings

──────────────────────────────────────────────────
  29  unit tests (core engine)
  35  integration tests (real-life archive files)
  21  real-world corruption simulation tests
  12  stress tests (edge cases, zip bombs, 100MB)
  42  regression tests
   1  doc test
──────────────────────────────────────────────────
```

Real-life tests use files downloaded from:
- **[corkami/pocs](https://github.com/corkami/pocs)** — Ange Albertini's file format PoCs (ZIP, RAR v4/v5, CVE exploits)
- **GNU hello tarball** — Real gzip compressed tar
- **7-Zip official distribution** — Real XZ archive
- **W3C test files** — Real PDF and PNG documents

Corruption patterns tested: sector death, bitrot, USB transfer errors, NAND flash degradation, truncation, header destruction, TCP reorder, power loss, and combinations.

## Web UI

The built-in web interface provides:

- **Drag-and-drop upload** — Drop any file, see instant hex preview with magic byte detection
- **Real-time progress** — Live recovery progress with phase indicators
- **Dashboard** — Server metrics, uptime, task history
- **Hex inspector** — View raw bytes with automatic format identification
- **Theme switching** — Dark/light mode
- **Download recovered files** — Get results as ZIP

Launch with `./start.sh` or `cargo run -p salvager-server`.

## CLI Reference

```
salvager — Corrupt archive recovery engine

USAGE:
    salvager <COMMAND>

COMMANDS:
    recover    Recover files from a corrupt archive
    inspect    Analyze without extracting (dry run)
    version    Show version and engine info

OPTIONS:
    -h, --help    Print help

── recover ──────────────────────────────────────
    salvager recover <INPUT> -o <OUTPUT> [OPTIONS]

    -o, --output <PATH>    Output directory or file
    --zip                  Output as ZIP archive
    --json                 Machine-readable JSON output
    --quiet                Suppress progress output

── inspect ──────────────────────────────────────
    salvager inspect <INPUT> [OPTIONS]

    --json                 JSON output
```

## API

### Rust Library

```rust
use salvager_core::SalvageEngine;

let data = std::fs::read("corrupt_archive.zip")?;
let engine = SalvageEngine::new();

// With progress callback
let report = engine.salvage(&data, Some(&|phase, pct| {
    println!("[{pct}%] {phase}");
}));

println!("Recovered {} files ({} bytes)",
    report.files_salvaged, report.bytes_recovered);

for file in &report.files {
    println!("  {} — {} bytes (SHA-256: {})",
        file.name, file.data.len(), file.sha256);
}
```

### HTTP API

```bash
# Upload and recover
curl -X POST http://localhost:5001/api/salvage \
  -F "file=@broken_archive.zip" \
  -H "X-Session-Id: my-session"

# Check task status
curl http://localhost:5001/api/task/{task_id}

# Download recovered ZIP
curl -O http://localhost:5001/api/download/{task_id}

# Server health
curl http://localhost:5001/api/health

# Dashboard metrics
curl http://localhost:5001/api/dashboard
```

## Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y liblzma5 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/salvager /usr/local/bin/
COPY --from=builder /app/target/release/salvager-server /usr/local/bin/
COPY --from=builder /app/crates/salvager-server/static /opt/helix/static
EXPOSE 5001
CMD ["salvager-server", "--bind", "0.0.0.0", "--port", "5001"]
```

```bash
# Build
docker build -t helix-salvager .

# Run web UI
docker run -p 5001:5001 helix-salvager

# Recover files
docker run -v $(pwd):/data helix-salvager \
  salvager recover /data/broken.zip -o /data/recovered/
```

## Project Structure

```
helix-salvager/
├── crates/
│   ├── salvager-core/          # Recovery engine library (2,120 lines)
│   │   ├── src/
│   │   │   ├── salvager.rs     # Main engine: fail-forward + carver + reporter
│   │   │   ├── zombie_lzma.rs  # Fault-tolerant LZMA decoder
│   │   │   └── lib.rs          # Public API
│   │   └── tests/
│   │       ├── real_file_tests.rs        # 35 tests with REAL downloaded archives
│   │       ├── real_world_tests.rs       # 21 corruption simulation tests
│   │       ├── stress_tests.rs           # 12 stress/edge-case tests
│   │       └── salvager_integration.rs   # 29 integration tests
│   ├── salvager-cli/           # Command-line interface (431 lines)
│   └── salvager-server/        # Web UI server (981 lines)
│       └── static/             # Frontend (HTML/CSS/JS — 1,715 lines)
├── .github/workflows/
│   ├── ci.yml                  # Clippy + test + build on every push
│   └── release.yml             # Cross-platform binaries on tag push
├── Dockerfile
├── Makefile
├── start.sh                    # Launcher with ASCII art & port management
└── docs/                       # Architecture docs & assets
```

## Architecture Deep Dive

### Recovery Pipeline

```
Input Bytes
    │
    ├─ Magic Detection ──────────────────────────────────────┐
    │   PK\x03\x04  →  ZIP path                             │
    │   \x1f\x8b    →  gzip path                            │
    │   BZh         →  bzip2 path                            │
    │   \xfd7zXZ    →  xz path                              │
    │   7z\xbc\xaf  →  7z path (Zombie LZMA)                │
    │   Otherwise   →  Unknown (raw carving only)            │
    │                                                        │
    │   ZIP Path                                             │
    │   ├─ Open with zip crate (lenient mode)                │
    │   ├─ For each entry:                                   │
    │   │   ├─ Try decompress (catch_unwind isolation)       │
    │   │   ├─ Success → SHA-256 + add to results            │
    │   │   └─ Failure → log CRC error, continue             │
    │   └─ If total extraction fails → fall through          │
    │                                                        │
    │   7z Path                                              │
    │   ├─ Locate LZMA stream headers                        │
    │   ├─ ZombieLzmaDecoder::decode_stream()                │
    │   │   ├─ Full-stream attempt                           │
    │   │   ├─ Entropy validation (Shannon H)                │
    │   │   ├─ Chunked retry with byte-slide                 │
    │   │   └─ TaintMap generation                           │
    │   └─ Carve from decoded output                         │
    │                                                        │
    │   Compression Pipelines                                │
    │   ├─ gzip  → flate2::read::GzDecoder                  │
    │   ├─ bzip2 → bzip2::read::BzDecoder                   │
    │   ├─ xz    → xz2::read::XzDecoder                     │
    │   └─ Each: decompress → check for tar → carve         │
    │                                                        │
    ├─ Raw Carving (always runs on unknown) ─────────────────┤
    │   AhoCorasick automaton with 29 signatures             │
    │   ├─ Find all magic byte offsets                       │
    │   ├─ For each match:                                   │
    │   │   ├─ Extract candidate region                      │
    │   │   ├─ Validate structure (if applicable)            │
    │   │   ├─ SHA-256 for dedup                             │
    │   │   └─ Add to results                                │
    │                                                        │
    └─ Report Generation ────────────────────────────────────┘
        ├─ files_salvaged count
        ├─ bytes_recovered total
        ├─ Per-type breakdown (3 JPEG, 1 PDF, 2 PNG, ...)
        ├─ CRC errors ignored count
        ├─ Recovery method used
        ├─ SHA-256 per recovered file
        └─ Elapsed time
```

### Zombie LZMA — Entropy-Guided Fault Tolerance

```
LZMA Stream (potentially corrupt)
    │
    ▼
┌─────────────────────────┐
│  Full-Stream Attempt    │
│  lzma_rs::decompress()  │
└───────┬──────┬──────────┘
   OK   │      │  Error
        │      │
        ▼      ▼
  Validate   Chunked Retry
  Entropy    ┌─────────────────┐
  H ∈ [1.5,  │ Slide 1 byte    │
    7.85]?   │ Try decompress   │ ← repeat up to N times
        │    │ Validate chunk   │
   Yes  │    └────────┬────────┘
        │             │
        ▼             ▼
  ┌───────────────────────┐
  │  TaintMap Assembly    │
  │  Mark clean regions   │
  │  Mark uncertain bytes │
  └───────────┬───────────┘
              │
              ▼
      Recovered Output
      + Confidence Map
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/vedLinuxian/helix-salvager.git
cd helix-salvager
cargo build
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -p salvager-server

# Run specific test suite
cargo test --test real_file_tests
cargo test --test stress_tests

# Clippy (must pass with zero warnings)
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all
```

## Roadmap

- [ ] WASM build — Run in browser, no server needed
- [x] RAR extraction — Native RAR v4/v5 header parsing + fallback carving
- [x] Parallel recovery — Multi-threaded SHA-256 hashing with rayon
- [x] Plugin system — User-defined file signatures via JSON config
- [x] Disk image support — Scan .img/.dd/.raw with MBR/GPT partition detection
- [x] Confidence scoring — Per-file recovery confidence percentage with deep validation
- [x] Streaming mode — Process files larger than RAM via mmap sliding window
- [ ] Python bindings — `pip install helix-salvager`

## FAQ

**Q: How is this different from `photorec`?**
A: Photorec is a raw disk carver — it scans block devices for file signatures. Helix Salvager is archive-aware. It understands ZIP/7z/tar structure and extracts files that photorec would miss because they're compressed inside a container. When the container structure is too damaged, Helix falls back to photorec-style carving.

**Q: Can this recover encrypted archives?**
A: No. If the archive is encrypted, the file data is meaningless without the key. Helix Salvager works on damaged-but-unencrypted archives.

**Q: Will this work on a 10 GB file?**
A: The CLI can process files of any size (reads into memory). For very large files, ensure you have enough RAM. The web UI has a configurable upload limit (default 500 MB).

**Q: Is the recovered data always perfect?**
A: No. If the actual file bytes are corrupted (not just the archive metadata), the recovered file will contain those corrupted bytes. The SHA-256 hash and taint map help you assess integrity. Helix recovers what's there — it can't reconstruct destroyed data.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

---

<p align="center">
  Built with 🧬 by <a href="https://github.com/vedLinuxian">Ved Prakash Pandey</a>
</p>
