# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-03-08

### Added

#### Core Engine
- **Fail-Forward ZIP Extraction** — Per-file isolation with CRC error bypass
- **Zombie LZMA Decoder** — Fault-tolerant LZMA1 stream recovery with Shannon entropy validation and TaintMap confidence tracking
- **Magic Header Carver** — Aho-Corasick multi-pattern scanner recognizing 29 file signatures (JPEG, PNG, PDF, MP4, GIF, BMP, WebP, ZIP, RAR, 7z, EXE, ELF, WAV, AVI, MP3, FLAC, OGG, WASM, TAR, ICO, PSD, TIFF)
- **Compression Pipelines** — gzip, bzip2, xz, and tar container support
- **SHA-256 Integrity** — Per-file hash for recovered content
- **Deduplication** — SHA-256 based duplicate removal in raw carving mode
- **Zip Bomb Protection** — 512 MB per-file decompression limit

#### CLI
- `salvager recover` — Extract files with progress bar, ZIP output option, JSON reporting
- `salvager inspect` — Dry-run analysis with optional JSON output
- `salvager version` — Engine information display

#### Web Server
- Actix-Web 4 based server with file upload and recovery
- Task queue with async processing
- Dashboard with metrics (uptime, uploads, recovery stats)
- Task history with retention policy
- Port management (custom, random, auto-detect, kill conflicting)
- Verbose colored terminal logging with timestamps
- ASCII art banner

#### Web UI
- Dark/light theme with CSS custom properties
- Drag-and-drop file upload
- Hex inspector with magic byte detection
- Real-time recovery progress
- Recovery results with per-file breakdown
- Task history sidebar

#### Infrastructure
- GitHub Actions CI (format, clippy, test on 3 platforms, security audit, MSRV)
- GitHub Actions Release (cross-platform binaries: Linux, macOS Intel/ARM, Windows)
- Docker support with multi-stage build
- Makefile with common development commands
- Bash launcher with port management and system info

#### Testing
- 179 tests, 0 failures, 0 clippy warnings
- 35 real-file tests using downloaded archives from corkami/pocs, GNU, 7-Zip, W3C
- 21 real-world corruption simulation tests (sector death, bitrot, USB corruption, NAND degradation, truncation, header destruction, TCP reorder, power loss)
- 12 stress tests (edge cases, large inputs, zip bombs)
- 29 unit + 42 regression tests

### Security
- Zero unsafe code
- Decompression bomb protection (512 MB limit)
- CVE-2018-0986 exploit RAR tested — handled safely
- Path traversal prevention in extracted filenames
- Weekly automated dependency security audit

### Requirements
- **MSRV: Rust 1.88** (required by actix-web 4.13, rayon 1.11)
- System libraries: liblzma-dev, libbz2-dev (Linux); xz (macOS)
