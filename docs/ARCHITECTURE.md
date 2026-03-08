# Architecture

This document describes the internal architecture of **Helix Salvager v1.0.0**.

---

## Crate Structure

```
helix-salvager (workspace)
├── salvager-core     # Library — all recovery logic
│   ├── salvager.rs   #   Main engine: detection, extraction, carving, RAR
│   ├── zombie_lzma.rs#   Fault-tolerant LZMA1 decoder
│   ├── plugin.rs     #   User-defined file signature system
│   ├── disk.rs       #   Disk image scanning (MBR/GPT)
│   ├── stream.rs     #   Streaming mode (mmap + sliding window)
│   ├── validate.rs   #   Deep structural validation (14 types)
│   └── lib.rs        #   Public API surface & re-exports
├── salvager-cli      # Binary — command-line interface (8 subcommands)
└── salvager-server   # Binary — Actix-Web 4 server + web UI
```

---

## Data Flow Overview

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│ Input Bytes  │───▶│  Detection   │───▶│  Extraction  │───▶│  Raw Carve   │
│  (corrupt    │    │  (magic      │    │  (format-    │    │  (29-sig     │
│   archive)   │    │   bytes)     │    │   specific)  │    │   Aho-       │
└─────────────┘    └──────────────┘    └─────────────┘    │   Corasick)  │
                                                          └──────┬───────┘
                                                                 │
                                       ┌─────────────┐    ┌─────▼──────┐
                                       │  Validation  │◀───│  Dedup     │
                                       │  (deep       │    │  (SHA-256) │
                                       │   struct)    │    └────────────┘
                                       └──────┬───────┘
                                              │
                                       ┌──────▼───────┐
                                       │ SalvageReport │
                                       │ (files +      │
                                       │  confidence)  │
                                       └───────────────┘
```

---

## salvager-core

### Entry Point

The core library exports a single primary entry point:

```rust
SalvageEngine::salvage(&[u8], Option<ProgressCb>) -> SalvageReport
```

Additional entry points for specialized modes:

```rust
scan_disk_image(path, engine, cb) -> DiskImageReport  // Disk images
stream_salvage(path, config, cb)  -> StreamReport     // Streaming / large files
validate_file(file)               -> ValidationResult // Structural validation
```

### Module: `salvager.rs` — Main Engine

The largest module (~1800 lines). Implements a **four-stage pipeline**:

#### Stage 1 — Format Detection

Reads the first bytes to classify the input container:

| Magic Bytes | Detection |
|---|---|
| `PK\x03\x04` | ZIP |
| `\x1f\x8b` | gzip |
| `BZh` | bzip2 |
| `\xfd7zXZ\x00` | XZ |
| `7z\xbc\xaf\x27\x1c` | 7z |
| `Rar!\x1a\x07\x00` | RAR v4 |
| `Rar!\x1a\x07\x01\x00` | RAR v5 |
| `ustar` at offset 257 | TAR |
| Otherwise | Unknown (raw blob) |

#### Stage 2 — Format-Specific Extraction

Each format has its own extraction strategy with **fail-forward** error handling:

- **ZIP** — Opens with `zip` crate. Iterates entries in a `catch_unwind` boundary per file. CRC errors are logged and skipped. Files that decompress successfully are added to results. Supports encrypted entries (skipped with diagnostic).

- **7z** — Scans for LZMA stream headers. Each stream goes through the `ZombieLzmaDecoder` which attempts full decompression, validates with Shannon entropy, and falls back to chunked retry with byte-sliding on failure. Outputs include a `TaintMap` marking byte-level confidence.

- **gzip / bzip2 / xz** — Decompresses the outer container, then checks if the result is a tar archive. If tar, iterates tar entries recursively. If not, runs Stage 3 carving on the decompressed content.

- **RAR** — Header-aware carving engine supporting both RAR v4 and v5 formats:
  - **v5**: Parses vint-encoded block headers (header type, flags, extra area, data area). Extracts stored files with names, sizes, and CRC32 when available.
  - **v4**: Parses legacy fixed-size block headers (HEAD_TYPE, HEAD_FLAGS, HEAD_SIZE). Handles file headers (type 0x74), extracts raw stored data.
  - Falls back to raw carving on parse failure.

- **TAR** — Iterates entries with graceful error handling. Supports nested tar-in-compressed scenarios.

- **Unknown** — Skips directly to Stage 3 (raw carving).

#### Stage 3 — Raw Carving

An Aho-Corasick automaton loaded with **29 file signatures** scans the raw bytes (or decompressed output). For each match:

1. Extract a candidate region based on file type heuristics (end markers, size fields, max lengths)
2. Validate internal structure where possible (header checks)
3. SHA-256 hash for **deduplication** — identical content across multiple carve hits is collapsed
4. Assign a **confidence score** (0.0–1.0) based on extraction method quality
5. Assign a suggested **filename** based on detected type and sequence number

#### Stage 4 — Validation & Confidence Scoring

After recovery, each file receives a confidence score reflecting extraction quality:

| Method | Base Confidence |
|---|---|
| Native extraction (ZIP/tar entry) | 0.95 |
| Decompressed container content | 0.85 |
| Raw carve with end-marker match | 0.80 |
| RAR header-parsed entry | 0.75 |
| Raw carve without end-marker | 0.60 |
| LZMA zombie-recovered chunk | 0.50 |
| Partial/truncated extraction | 0.40 |

Files are then optionally run through the `validate` module for deep structural analysis which can further adjust confidence scores.

#### Parallel Processing

File-level operations use **Rayon** for parallel processing:
- SHA-256 hashing runs concurrently across recovered files
- Independent extraction attempts for multi-stream 7z archives run in parallel
- Carving results are collected via parallel iterators

### Module: `zombie_lzma.rs` — Fault-Tolerant LZMA Decoder

The most technically complex component. Wraps `lzma_rs` with aggressive error recovery.

#### Problem

LZMA compression is stateful — a single corrupted byte can cause the entire remaining stream to produce garbage. Standard decoders abort on the first error.

#### Solution

1. **Try full decompression** — If it works, validate output entropy
2. **Shannon entropy check** — Classify output:
   - H < 1.5: Padding / repetitive data (discard)
   - 1.5 ≤ H ≤ 7.85: Structured data (keep)
   - H > 7.85: Random noise / failed decompression (mark tainted)
3. **Chunked retry** — On failure, skip forward 1 byte and try again, up to N times
4. **TaintMap** — Bit-vector marking each output byte as clean or uncertain

#### TaintMap

A memory-efficient `Vec<u8>` where each bit represents one output byte's trust status:

```
Bit 0 = clean (decompressed successfully)
Bit 1 = tainted (from a failed/partial region)
```

This allows downstream consumers to make granular decisions about which parts of a recovered file are trustworthy.

### Module: `plugin.rs` — User-Defined Signatures

Extensible file signature system for adding custom file types at runtime.

#### Key Types

```rust
CustomSignature {
    name: String,         // e.g. "Photoshop Document"
    extension: String,    // e.g. "psd"
    magic_hex: String,    // e.g. "38425053" (hex-encoded magic bytes)
    offset: usize,        // Byte offset where magic appears
    max_size: usize,      // Maximum file size to carve
    end_marker_hex: Option<String>,  // Optional end-of-file marker
}

PluginRegistry {
    load_json(path) -> Self     // Load from JSON config file
    load_json_str(json) -> Self // Load from JSON string
    add_signature(sig)          // Add individual signatures
    merge(other)                // Combine registries
    template_config() -> PluginConfig  // Generate example config
}
```

#### Config Format

```json
{
  "name": "My Custom Signatures",
  "version": "1.0.0",
  "signatures": [
    {
      "name": "Custom Format",
      "extension": "cust",
      "magic_hex": "CAFEBABE",
      "offset": 0,
      "max_size": 10485760,
      "end_marker_hex": null
    }
  ]
}
```

Plugins are validated on load — duplicate names, empty magic bytes, and oversized max_size values are rejected with descriptive `PluginError` variants.

### Module: `disk.rs` — Disk Image Scanning

Recovers files from raw disk images (`.img`, `.dd`, `.raw`) with partition table awareness.

#### Partition Detection

```rust
enum PartitionScheme {
    Mbr,    // Master Boot Record (offset 0x1FE: 55 AA)
    Gpt,    // GUID Partition Table (offset 0x200: "EFI PART")
    Raw,    // No recognized partition table — treat as single blob
}
```

#### Pipeline

1. **Memory-map** the disk image via `memmap2`
2. **Detect** partition scheme (MBR → parse 4 primary entries, GPT → parse header + entries, or fallback to Raw)
3. **For each partition**: extract byte range, run `SalvageEngine::salvage()` on partition data
4. **Aggregate** results into `DiskImageReport` with partition metadata

#### Key Types

```rust
Partition {
    index: usize,
    scheme: PartitionScheme,
    offset: u64,         // Byte offset in image
    size: u64,           // Partition size
    type_id: u8,         // MBR type byte or GPT type
    label: String,       // Human-readable label
}

DiskImageReport {
    partitions: Vec<Partition>,
    results: Vec<(Partition, SalvageReport)>,  // Per-partition recovery
    total_files: usize,
    total_bytes: u64,
    elapsed: Duration,
}
```

### Module: `stream.rs` — Streaming Mode

Processes files larger than available RAM using memory-mapped I/O with a sliding window approach.

#### Design

```rust
StreamConfig {
    window_size: usize,   // Size of each scan window (default: 64 MB)
    overlap: usize,       // Overlap between windows (default: 1 MB)
    max_file_size: usize, // Maximum individual carved file size
}
```

Presets:
- `StreamConfig::low_memory()` — 16 MB windows, 256 KB overlap
- `StreamConfig::high_performance()` — 128 MB windows, 4 MB overlap

#### Pipeline

1. **Memory-map** the input file
2. **Slide** a window across the file with configurable overlap (ensures files at window boundaries aren't missed)
3. **For each window**: run the carving engine on the window bytes
4. **Deduplicate** cross-window hits using SHA-256
5. **Merge** results into `StreamReport`

#### Key Types

```rust
StreamReport {
    files: Vec<SalvagedFile>,
    windows_processed: usize,
    total_bytes_scanned: u64,
    unique_files: usize,
    duplicate_files_skipped: usize,
    elapsed: Duration,
}
```

### Module: `validate.rs` — Deep Structural Validation

Validates recovered files by parsing their internal structure, not just checking magic bytes. Supports **14 file types** with format-specific checks.

#### Validated Formats

| Format | Checks Performed |
|---|---|
| JPEG | SOI marker, APP0/APP1 segments, SOF markers, valid Huffman tables |
| PNG | IHDR chunk present, valid chunk CRC sequence, IEND terminator |
| PDF | `%PDF` header, `%%EOF` trailer, `xref` table presence |
| GIF | Header version (87a/89a), logical screen descriptor, trailer byte |
| BMP | File size field matches data, valid DIB header size |
| ZIP | Central directory present, local file headers consistent |
| ELF | Valid e_ident, reasonable section/program header counts |
| PE/EXE | MZ header + PE signature, valid section alignment |
| MP4 | Valid box structure, `ftyp` box at start |
| FLAC | Stream info block present, valid frame sync codes |
| WAV | RIFF header + fmt chunk + data chunk, consistent sizes |
| WebP | RIFF header + VP8/VP8L/VP8X chunk |
| OGG | Page structure, valid capture pattern |
| WASM | Magic + version field (0x01), valid section IDs |

#### Confidence Adjustment

`validate_and_adjust()` runs validation across all recovered files and adjusts confidence:
- **Perfect structure**: confidence boosted by up to +0.10
- **Minor issues** (e.g. missing trailer): no adjustment
- **Major structural errors**: confidence reduced by up to -0.20
- **Critical failures** (invalid magic): confidence drops to 0.25

---

## salvager-cli

Command-line interface built with `clap` (derive mode), `indicatif` (progress bars), and `colored` (terminal styling).

### Subcommands

| Command | Description |
|---|---|
| `recover` | Main recovery: extract files from corrupt archives |
| `inspect` | Dry-run analysis — show what would be recovered without extracting |
| `version` | Display version, engine capabilities, and build info |
| `formats` | List all 29+ supported file signatures and archive types |
| `disk-image` | Scan disk images (.img/.dd/.raw) with partition detection |
| `stream` | Process large files via sliding window carving |
| `plugin` | Load custom signatures from JSON and recover with extended types |
| `validate` | Run deep structural validation on recovered files |

### Output Modes

- **Human-readable**: Colored tables, progress bars, emoji indicators, summary statistics
- **JSON mode** (`--json`): Machine-readable output for scripting/piping
- **Quiet mode** (`--quiet`): Suppress all output except errors

---

## salvager-server

Actix-Web 4 server providing a web-based recovery interface.

### Architecture

```
┌─────────────┐     ┌──────────────────────┐
│  Browser UI  │────▶│  Actix-Web 4 Server  │
│  (SPA)       │◀────│                      │
└─────────────┘     │  Routes:             │
                    │  POST /upload        │
                    │  GET  /status/{id}   │
                    │  GET  /download/{id} │
                    │  GET  /dashboard     │
                    │  GET  /              │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  SalvageEngine       │
                    │  (salvager-core)     │
                    └──────────────────────┘
```

### Key Components

- **Upload handler** — Receives multipart file uploads, validates size, assigns task ID
- **Async task queue** — Recovery tasks stored in `Arc<RwLock<HashMap<TaskId, TaskState>>>`. Processing runs on a background thread to avoid blocking the event loop.
- **Dashboard** — Atomic counters for real-time metrics: uploads processed, total bytes, files recovered, success rate
- **File serving** — Static files embedded for the web UI (HTML/CSS/JS)
- **Port management** — Auto-detect free ports, detect and handle port conflicts
- **Verbose logging** — Server startup banner with feature summary, request logging

### Response Format

All API responses include:
- `files[]` — Recovered files with `name`, `size`, `file_type`, `confidence`, `sha256`
- `method` — Recovery strategy used
- `taint_summary` — Byte-level corruption information (when applicable)

---

## File Signatures (29 Types)

The carver recognizes these magic byte patterns via Aho-Corasick automaton:

### Images
| Type | Magic Bytes |
|---|---|
| JPEG | `FF D8 FF E0` / `FF D8 FF E1` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` (GIF8) |
| BMP | `42 4D` (BM) |
| WebP | `52 49 46 46 xx xx xx xx 57 45 42 50` |
| TIFF | `49 49 2A 00` / `4D 4D 00 2A` |
| ICO | `00 00 01 00` |
| PSD | `38 42 50 53` (8BPS) |

### Audio / Video
| Type | Magic Bytes |
|---|---|
| MP4 | `00 00 00 xx 66 74 79 70` (ftyp) |
| AVI | `52 49 46 46 xx xx xx xx 41 56 49 20` |
| WAV | `52 49 46 46 xx xx xx xx 57 41 56 45` |
| MP3 | `FF FB` / `49 44 33` (ID3) |
| FLAC | `66 4C 61 43` (fLaC) |
| OGG | `4F 67 67 53` (OggS) |

### Archives
| Type | Magic Bytes |
|---|---|
| ZIP | `50 4B 03 04` (PK) |
| RAR | `52 61 72 21 1A 07` (Rar!) |
| 7z | `37 7A BC AF 27 1C` |
| TAR | `75 73 74 61 72` at offset 257 |

### Documents
| Type | Magic Bytes |
|---|---|
| PDF | `25 50 44 46` (%PDF) |

### Executables
| Type | Magic Bytes |
|---|---|
| ELF | `7F 45 4C 46` |
| PE/EXE | `4D 5A` (MZ) |
| WASM | `00 61 73 6D` (\0asm) |

Plus 7 additional signatures for less common formats, bringing the total to **29**.

---

## Test Suite

**179 tests** organized across multiple test files:

| Test File | Count | Focus |
|---|---|---|
| `salvager.rs` (unit tests) | 68 | Engine logic, format detection, extraction, RAR parsing, carving, deduplication, confidence scoring |
| `salvager_integration.rs` | 35 | End-to-end recovery: corrupt ZIPs, nested archives, plugin loading, disk image scanning |
| `real_file_tests.rs` | 21 | Real-world archive recovery (skipped on CI when test data unavailable) |
| `real_world_tests.rs` | 12 | Downloaded real archives (network-dependent, gracefully skipped) |
| `stress_tests.rs` | 42 | Fuzzing, random corruption, truncation, large archives, performance |
| Doc tests | 1 | API example in lib.rs |

### CI Compatibility

Tests that require external data (real archive files, network downloads) use a `skip_if_missing!()` macro that gracefully returns when data is unavailable, ensuring CI always passes without requiring test fixtures.

---

## Dependencies

### Core
| Crate | Purpose |
|---|---|
| `aho-corasick` | Multi-pattern signature scanning |
| `zip` | ZIP archive extraction with per-entry isolation |
| `lzma-rs` | LZMA1/2 decompression (wrapped by ZombieLzma) |
| `xz2` | XZ container decompression |
| `flate2` | gzip decompression |
| `bzip2` | bzip2 decompression |
| `tar` | TAR archive iteration |
| `sha2` | SHA-256 file integrity hashing |
| `rayon` | Parallel processing |
| `memmap2` | Memory-mapped file I/O |
| `serde` + `serde_json` | Plugin config serialization |

### CLI
| Crate | Purpose |
|---|---|
| `clap` | Argument parsing (derive mode) |
| `indicatif` | Progress bars |
| `colored` | Terminal colors |

### Server
| Crate | Purpose |
|---|---|
| `actix-web` | HTTP server framework |
| `actix-multipart` | File upload handling |
| `tokio` | Async runtime |
| `uuid` | Task IDs |

---

## Build Requirements

- **Rust ≥ 1.88** (required by actix-web 4.13, rayon 1.11)
- **System libraries**: liblzma-dev, libbz2-dev, pkg-config (Linux); xz (macOS via Homebrew)
- **Dual licensed**: MIT OR Apache-2.0
