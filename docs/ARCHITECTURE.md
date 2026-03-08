# Architecture

This document describes the internal architecture of Helix Salvager.

## Crate Structure

```
helix-salvager (workspace)
├── salvager-core     # Library — all recovery logic
├── salvager-cli      # Binary — command-line interface
└── salvager-server   # Binary — web server + frontend
```

### salvager-core

The core library exports a single entry point: `SalvageEngine::salvage(&[u8]) -> SalvageReport`.

Internally it runs a three-stage pipeline:

#### Stage 1 — Format Detection

Reads the first few bytes to classify the input:

| Magic Bytes | Detection |
|------------|-----------|
| `PK\x03\x04` | ZIP |
| `\x1f\x8b` | gzip |
| `BZh` | bzip2 |
| `\xfd7zXZ\x00` | XZ |
| `7z\xbc\xaf\x27\x1c` | 7z |
| Otherwise | Unknown (raw blob) |

#### Stage 2 — Format-Specific Extraction

Each format has its own extraction strategy:

- **ZIP**: Opens with `zip` crate. Iterates entries in a `catch_unwind` boundary per file. CRC errors are logged and skipped. Files that decompress successfully are added to results.

- **7z**: Scans for LZMA stream headers. Each stream goes through the `ZombieLzmaDecoder` which attempts full decompression, validates with Shannon entropy, and falls back to chunked retry with byte-sliding on failure. Outputs include a `TaintMap` marking byte-level confidence.

- **gzip/bzip2/xz**: Decompresses the outer container, then checks if the result is a tar archive. If yes, iterates tar entries. If not, carves the decompressed content.

- **Unknown**: Skips directly to Stage 3 (raw carving).

#### Stage 3 — Raw Carving

An Aho-Corasick automaton loaded with 29 file signatures scans the raw bytes (or decompressed output). For each match:

1. Extract a candidate region based on file type heuristics
2. Validate internal structure where possible
3. SHA-256 hash for deduplication
4. Add to results

### salvager-cli

Thin wrapper around `salvager-core`. Uses `clap` for argument parsing, `indicatif` for progress bars, `colored` for terminal output.

### salvager-server

Actix-Web 4 server. Key components:

- **Upload handler** — Receives multipart file uploads
- **Task queue** — Async recovery tasks stored in `Arc<RwLock<HashMap>>`
- **Dashboard** — Atomic counters for metrics (uploads, bytes, recoveries)
- **File serving** — Static files for the web UI
- **Port management** — Auto-detect free ports, kill conflicting processes

## Zombie LZMA Decoder

The most technically complex component. Located in `zombie_lzma.rs`.

### Problem

LZMA compression is stateful — a single corrupted byte can cause the entire remaining stream to produce garbage. Standard decoders abort on the first error.

### Solution

1. **Try full decompression** — If it works, validate output entropy
2. **Shannon entropy check** — Classify output:
   - H < 1.5: Padding (discard)
   - 1.5 ≤ H ≤ 7.85: Structured data (keep)
   - H > 7.85: Random noise / failed decompression (mark tainted)
3. **Chunked retry** — On failure, skip forward 1 byte and try again, up to N times
4. **TaintMap** — Bit-vector marking each output byte as clean or uncertain

### TaintMap

A memory-efficient `Vec<u8>` where each bit represents one output byte's trust status:

```
Bit 0 = clean (decompressed successfully)
Bit 1 = tainted (from a failed/partial region)
```

This allows downstream consumers to make decisions about which parts of a recovered file are trustworthy.

## File Signatures

The carver recognizes these magic byte patterns:

```
JPEG:  FF D8 FF E0/E1
PNG:   89 50 4E 47 0D 0A 1A 0A
PDF:   25 50 44 46 (%PDF)
GIF:   47 49 46 38 (GIF8)
BMP:   42 4D (BM)
WebP:  52 49 46 46 xx xx xx xx 57 45 42 50 (RIFF....WEBP)
TIFF:  49 49 2A 00 / 4D 4D 00 2A
ICO:   00 00 01 00
PSD:   38 42 50 53 (8BPS)
MP4:   00 00 00 xx 66 74 79 70 (....ftyp)
AVI:   52 49 46 46 xx xx xx xx 41 56 49 20 (RIFF....AVI )
WAV:   52 49 46 46 xx xx xx xx 57 41 56 45 (RIFF....WAVE)
MP3:   FF FB / 49 44 33 (ID3)
FLAC:  66 4C 61 43 (fLaC)
OGG:   4F 67 67 53 (OggS)
ZIP:   50 4B 03 04
RAR:   52 61 72 21 1A 07 (Rar!..)
7z:    37 7A BC AF 27 1C
TAR:   75 73 74 61 72 at offset 257 (ustar)
ELF:   7F 45 4C 46
EXE:   4D 5A (MZ)
WASM:  00 61 73 6D (\0asm)
```
