//! # Salvager Core
//!
//! Corrupt archive recovery engine — the core library behind `salvager-cli` and
//! `salvager-server`.
//!
//! ## Architecture
//!
//! - **`salvager`** — `SalvageEngine`: fail-forward ZIP extraction (per-file
//!   isolation via the `zip` crate), Aho-Corasick 29-signature magic-header
//!   carving, SHA-256 integrity reporting, per-file confidence scoring.
//! - **`zombie_lzma`** — Fault-tolerant LZMA1 recovery pipeline wrapping
//!   `lzma_rs` with chunked retry, byte-slide resynchronisation, Shannon
//!   entropy gating, and a TaintMap bit-vector for output quality metadata.
//! - **`plugin`** — User-defined file signature system. Load custom magic
//!   patterns from JSON configuration files at runtime.
//! - **`disk`** — Disk image support for scanning .img/.dd/.raw files with
//!   MBR/GPT partition table detection and per-partition recovery.
//! - **`stream`** — Streaming mode for files larger than RAM using memory-mapped
//!   I/O and sliding window carving.
//! - **`validate`** — Deep structural validation of recovered files (JPEG, PNG,
//!   PDF, ZIP, ELF, PE, FLAC, etc.) with confidence score adjustment.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use salvager_core::SalvageEngine;
//!
//! let corrupt_data = std::fs::read("broken_archive.zip").unwrap();
//! let engine = SalvageEngine::new();
//! let report = engine.salvage(&corrupt_data, None);
//!
//! println!("Recovered {} files ({} bytes, {:.0}% confidence)",
//!     report.files_salvaged, report.total_salvaged_bytes,
//!     report.overall_confidence * 100.0);
//!
//! // Pack into a downloadable ZIP
//! let zip_bytes = engine.pack_salvaged_zip(&report.files);
//! std::fs::write("recovered.zip", zip_bytes).unwrap();
//! ```

pub mod disk;
pub mod plugin;
pub mod salvager;
pub mod stream;
pub mod validate;
pub mod zombie_lzma;

// Re-export the most commonly used types at crate root for ergonomic access.
pub use salvager::{
    CarvedFileType, ProgressCb, SalvageEngine, SalvageReport, SalvagedFile, TypeCount,
};
pub use zombie_lzma::{
    EntropyClass, TaintMap, ZombieLzmaDecoder, ZombieStats,
    classify_entropy, shannon_entropy,
};
pub use plugin::{CustomSignature, PluginConfig, PluginError, PluginRegistry};
pub use disk::{DiskImageError, DiskImageReport, Partition, PartitionScheme, scan_disk_image, collect_all_files};
pub use stream::{StreamConfig, StreamError, StreamReport, stream_salvage};
pub use validate::{ValidationResult, ValidationIssue, IssueSeverity, validate_file, validate_and_adjust};
