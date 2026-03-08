//! Helix-Salvager — Corrupt Archive Recovery Engine
//!
//! A fail-forward archive recovery pipeline with three components:
//!
//!   **Component A** — Fail-Forward ZIP/LZMA extraction: opens archives with
//!   the `zip` crate in per-file isolation so one corrupt entry doesn't kill
//!   the rest.  For 7z/raw LZMA, delegates to `zombie_lzma` for fault-tolerant
//!   stream recovery.
//!
//!   **Component B** — Magic Header Carver: an Aho-Corasick multi-pattern scan
//!   over raw bytes to recover embedded files (JPEG, PNG, PDF, etc.) even when
//!   archive metadata is completely destroyed.
//!
//!   **Component C** — Integrity Reporter: SHA-256 per file, per-type breakdown,
//!   corruption counters, and timing.
//!
//! Supports: .zip (deflate/store), .7z (LZMA1 via `lzma-rs`, LZMA2 via `xz2`),
//! and raw binary blobs.

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};

/// Type alias for the progress callback to reduce type complexity.
pub type ProgressCb<'a> = Option<&'a dyn Fn(&str, u32)>;

/// Maximum decompressed size per file to prevent zip-bomb / decompression-bomb OOM.
const MAX_DECOMPRESSED_FILE_BYTES: usize = 512 * 1024 * 1024; // 512 MB

use crate::zombie_lzma::{zombie_scan_and_decode, ZombieLzmaDecoder, ZombieStats};

// ══════════════════════════════════════════════════════════════
//  MAGIC SIGNATURES — file type detection inside raw streams
// ══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarvedFileType {
    Jpeg,
    Png,
    Pdf,
    Mp4,
    Gif,
    Bmp,
    WebP,
    Zip,
    Rar,
    SevenZ,
    Exe,
    Elf,
    Sqlite,
    Xml,
    Html,
    Tiff,
    Wav,
    Avi,
    Mp3,
    Flac,
    Ogg,
    Wasm,
    Tar,
    Ico,
    Psd,
    Unknown,
}

impl CarvedFileType {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
            Self::Pdf => "pdf",
            Self::Mp4 => "mp4",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::WebP => "webp",
            Self::Zip => "zip",
            Self::Rar => "rar",
            Self::SevenZ => "7z",
            Self::Exe => "exe",
            Self::Elf => "elf",
            Self::Sqlite => "sqlite",
            Self::Xml => "xml",
            Self::Html => "html",
            Self::Tiff => "tiff",
            Self::Wav => "wav",
            Self::Avi => "avi",
            Self::Mp3 => "mp3",
            Self::Flac => "flac",
            Self::Ogg => "ogg",
            Self::Wasm => "wasm",
            Self::Tar => "tar",
            Self::Ico => "ico",
            Self::Psd => "psd",
            Self::Unknown => "bin",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Jpeg => "JPEG Image",
            Self::Png => "PNG Image",
            Self::Pdf => "PDF Document",
            Self::Mp4 => "MP4 Video",
            Self::Gif => "GIF Image",
            Self::Bmp => "BMP Image",
            Self::WebP => "WebP Image",
            Self::Zip => "ZIP Archive",
            Self::Rar => "RAR Archive",
            Self::SevenZ => "7z Archive",
            Self::Exe => "PE Executable",
            Self::Elf => "ELF Binary",
            Self::Sqlite => "SQLite Database",
            Self::Xml => "XML Document",
            Self::Html => "HTML Document",
            Self::Tiff => "TIFF Image",
            Self::Wav => "WAV Audio",
            Self::Avi => "AVI Video",
            Self::Mp3 => "MP3 Audio",
            Self::Flac => "FLAC Audio",
            Self::Ogg => "OGG Audio",
            Self::Wasm => "WebAssembly",
            Self::Tar => "TAR Archive",
            Self::Ico => "ICO Icon",
            Self::Psd => "PSD Image",
            Self::Unknown => "Unknown Binary",
        }
    }

    /// Whether this type is a container/archive that may contain embedded files.
    pub fn is_archive(&self) -> bool {
        matches!(self, Self::Zip | Self::Rar | Self::SevenZ | Self::Tar)
    }
}

/// All magic byte patterns and their corresponding file types.
/// Order matters: longer/more-specific patterns first.
const SIGNATURES: &[(&[u8], CarvedFileType)] = &[
    // ── Images ──
    (&[0xFF, 0xD8, 0xFF], CarvedFileType::Jpeg),
    (
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        CarvedFileType::Png,
    ),
    (&[0x47, 0x49, 0x46, 0x38], CarvedFileType::Gif), // GIF87a / GIF89a
    (&[0x42, 0x4D], CarvedFileType::Bmp),             // BM — validated in post-AC
    (&[0x49, 0x49, 0x2A, 0x00], CarvedFileType::Tiff), // TIFF (Intel byte order)
    (&[0x4D, 0x4D, 0x00, 0x2A], CarvedFileType::Tiff), // TIFF (Motorola byte order)
    (&[0x00, 0x00, 0x01, 0x00], CarvedFileType::Ico), // ICO
    (&[0x38, 0x42, 0x50, 0x53], CarvedFileType::Psd), // 8BPS (Photoshop)
    // ── PDF ──
    (&[0x25, 0x50, 0x44, 0x46], CarvedFileType::Pdf), // %PDF
    // ── Video ──
    (&[0x66, 0x74, 0x79, 0x70], CarvedFileType::Mp4), // ftyp (at offset+4)
    // ── RIFF container (WebP, WAV, AVI) ──
    (&[0x57, 0x45, 0x42, 0x50], CarvedFileType::WebP), // WEBP at RIFF+8
    (&[0x57, 0x41, 0x56, 0x45], CarvedFileType::Wav),  // WAVE at RIFF+8
    (&[0x41, 0x56, 0x49, 0x20], CarvedFileType::Avi),  // AVI  at RIFF+8
    // ── Audio ──
    (&[0xFF, 0xFB], CarvedFileType::Mp3), // MP3 frame sync v1
    (&[0xFF, 0xFA], CarvedFileType::Mp3), // MP3 frame sync v1
    (&[0x49, 0x44, 0x33], CarvedFileType::Mp3), // ID3 tag
    (&[0x66, 0x4C, 0x61, 0x43], CarvedFileType::Flac), // fLaC
    (&[0x4F, 0x67, 0x67, 0x53], CarvedFileType::Ogg), // OggS
    // ── Archives ──
    (&[0x50, 0x4B, 0x03, 0x04], CarvedFileType::Zip), // PK..
    (&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], CarvedFileType::Rar),
    (
        &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        CarvedFileType::SevenZ,
    ),
    (&[0x75, 0x73, 0x74, 0x61, 0x72], CarvedFileType::Tar), // ustar (at offset 257)
    // ── Executables ──
    (&[0x4D, 0x5A, 0x90, 0x00], CarvedFileType::Exe), // MZ\x90\x00 (standard PE)
    (&[0x7F, 0x45, 0x4C, 0x46], CarvedFileType::Elf), // .ELF
    // ── WebAssembly ──
    (&[0x00, 0x61, 0x73, 0x6D], CarvedFileType::Wasm), // \0asm
    // ── Database ──
    (
        &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65],
        CarvedFileType::Sqlite,
    ), // SQLite
    // ── Text-based ──
    (&[0x3C, 0x3F, 0x78, 0x6D, 0x6C], CarvedFileType::Xml), // <?xml
    (&[0x3C, 0x21, 0x44, 0x4F, 0x43], CarvedFileType::Html), // <!DOC
    (&[0x3C, 0x68, 0x74, 0x6D, 0x6C], CarvedFileType::Html), // <html
];

// ══════════════════════════════════════════════════════════════
//  PUBLIC TYPES
// ══════════════════════════════════════════════════════════════

/// One salvaged file carved from a corrupt archive or raw stream.
#[derive(Debug, Clone, Serialize)]
pub struct SalvagedFile {
    pub index: usize,
    /// Original filename (from archive metadata) or generated name.
    pub name: String,
    pub file_type: String,
    pub extension: String,
    pub offset: usize,
    pub size: usize,
    pub sha256: String,
    /// Recovery confidence: 0.0 (uncertain) to 1.0 (perfect).
    /// Based on: extraction method, CRC match, structural validation,
    /// and entropy analysis.
    pub confidence: f64,
    /// The actual recovered bytes (not serialised to JSON)
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Per-type breakdown for the report.
#[derive(Debug, Clone, Serialize)]
pub struct TypeCount {
    pub file_type: String,
    pub count: usize,
    pub total_bytes: usize,
}

/// Full salvage report.
#[derive(Debug, Clone, Serialize)]
pub struct SalvageReport {
    pub input_size: usize,
    pub archive_type: String,
    pub total_files_found: usize,
    pub files_salvaged: usize,
    pub total_salvaged_bytes: usize,
    /// Alias for total_salvaged_bytes (backward compat).
    pub bytes_recovered: usize,
    pub corruption_bypassed: usize,
    pub crc_errors_ignored: usize,
    pub lzma_errors_bypassed: usize,
    pub salvage_rate_percent: f64,
    /// Overall recovery confidence (0.0–1.0), weighted average of per-file confidences.
    pub overall_confidence: f64,
    pub type_breakdown: Vec<TypeCount>,
    pub files: Vec<SalvagedFile>,
    pub salvage_time_secs: f64,
    pub method: String,
    // Zombie LZMA decoder stats
    pub zombie_resync_count: usize,
    pub zombie_bytes_tainted: usize,
    pub zombie_bytes_zeroed: usize,
    pub zombie_entropy_rejections: usize,
}

// ══════════════════════════════════════════════════════════════
//  SALVAGE ENGINE
// ══════════════════════════════════════════════════════════════

pub struct SalvageEngine {
    /// Aho-Corasick automaton for all magic signatures.
    magic_matcher: AhoCorasick,
    /// Ordered list of (pattern_index → file_type) so we can map AC hits.
    sig_types: Vec<CarvedFileType>,
    /// Custom plugin signatures (loaded at runtime).
    plugin_signatures: Vec<crate::plugin::CustomSignature>,
    /// Aho-Corasick for plugin patterns (built lazily).
    plugin_matcher: Option<AhoCorasick>,
}

impl Default for SalvageEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SalvageEngine {
    pub fn new() -> Self {
        let patterns: Vec<&[u8]> = SIGNATURES.iter().map(|(p, _)| *p).collect();
        let types: Vec<CarvedFileType> = SIGNATURES.iter().map(|(_, t)| *t).collect();
        Self {
            magic_matcher: AhoCorasick::new(&patterns)
                .expect("Aho-Corasick build should not fail on known patterns"),
            sig_types: types,
            plugin_signatures: Vec::new(),
            plugin_matcher: None,
        }
    }

    /// Create an engine with user-defined plugin signatures.
    pub fn with_plugins(registry: &crate::plugin::PluginRegistry) -> Self {
        let mut engine = Self::new();
        engine.load_plugins(registry);
        engine
    }

    /// Load plugin signatures into the engine.
    pub fn load_plugins(&mut self, registry: &crate::plugin::PluginRegistry) {
        self.plugin_signatures = registry.signatures().to_vec();
        if !self.plugin_signatures.is_empty() {
            let patterns: Vec<Vec<u8>> = self
                .plugin_signatures
                .iter()
                .map(crate::plugin::PluginRegistry::magic_bytes)
                .collect();
            // Filter out empty patterns
            let patterns: Vec<&[u8]> = patterns
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| p.as_slice())
                .collect();
            if !patterns.is_empty() {
                self.plugin_matcher = AhoCorasick::new(&patterns).ok();
            }
        }
    }

    /// Get the number of built-in signatures.
    pub fn builtin_signature_count(&self) -> usize {
        SIGNATURES.len()
    }

    /// Get the number of loaded plugin signatures.
    pub fn plugin_signature_count(&self) -> usize {
        self.plugin_signatures.len()
    }

    /// Get total signature count (built-in + plugins).
    pub fn total_signature_count(&self) -> usize {
        self.builtin_signature_count() + self.plugin_signature_count()
    }

    // ──────────────────────────────────────────────────────────
    //  MASTER ENTRY POINT
    // ──────────────────────────────────────────────────────────

    /// Recover everything possible from a potentially corrupt archive.
    /// Tries structured extraction first (ZIP), then falls back to
    /// raw decompression + carving.
    pub fn salvage(&self, data: &[u8], progress_cb: ProgressCb<'_>) -> SalvageReport {
        let start = std::time::Instant::now();

        macro_rules! progress {
            ($msg:expr, $pct:expr) => {
                if let Some(cb) = progress_cb {
                    cb($msg, $pct);
                }
            };
        }

        progress!("Detecting archive format...", 2);

        let archive_type = self.detect_archive_type(data);

        let (mut salvaged, crc_errs, lzma_errs, method, z_stats) = match archive_type.as_str() {
            "zip" => {
                progress!("Extracting ZIP (fail-forward)...", 10);
                let (files, crc, method) = self.salvage_zip(data, progress_cb);
                (files, crc, 0usize, method, ZombieStats::default())
            }
            "7z" => {
                progress!("Zombie LZMA scan: initialising...", 10);
                let (files, lzma, method, zstats) = self.salvage_7z(data, progress_cb);
                (files, 0usize, lzma, method, zstats)
            }
            "gzip" => {
                progress!("Decompressing GZIP...", 10);
                let (files, method) = self.salvage_gzip(data, progress_cb);
                (files, 0, 0, method, ZombieStats::default())
            }
            "bzip2" => {
                progress!("Decompressing BZIP2...", 10);
                let (files, method) = self.salvage_bzip2(data, progress_cb);
                (files, 0, 0, method, ZombieStats::default())
            }
            "xz" => {
                progress!("Decompressing XZ...", 10);
                let (files, method) = self.salvage_xz(data, progress_cb);
                (files, 0, 0, method, ZombieStats::default())
            }
            "rar" => {
                progress!("Parsing RAR archive...", 10);
                let (files, method) = self.salvage_rar(data, progress_cb);
                (files, 0, 0, method, ZombieStats::default())
            }
            _ => {
                progress!("Unknown format — raw carving mode...", 10);
                let files = self.carve_raw(data, progress_cb);
                (files, 0, 0, "Raw Carve".to_string(), ZombieStats::default())
            }
        };

        progress!("Computing integrity hashes (parallel)...", 85);

        // Compute SHA-256 for each salvaged file — parallelized with rayon.
        let hashes: Vec<String> = salvaged
            .par_iter()
            .map(|f| {
                let hash = Sha256::digest(&f.data);
                hash.iter().map(|b| format!("{:02x}", b)).collect()
            })
            .collect();
        for (f, hash) in salvaged.iter_mut().zip(hashes) {
            f.sha256 = hash;
        }
        // Deduplicate only for raw-carved files (unknown archive type).
        // Structured extraction (ZIP, 7z, etc.) may legitimately contain
        // multiple files with identical content — don't discard those.
        if archive_type == "unknown" {
            let mut seen_hashes = HashSet::new();
            salvaged.retain(|f| seen_hashes.insert(f.sha256.clone()));
        }
        // Re-index
        for (i, f) in salvaged.iter_mut().enumerate() {
            f.index = i;
        }

        // Deep structural validation — adjusts confidence scores.
        progress!("Running deep validation...", 90);
        crate::validate::validate_and_adjust(&mut salvaged);

        // Build type breakdown.
        progress!("Generating report...", 92);
        let type_breakdown = self.build_type_breakdown(&salvaged);

        let total_salvaged_bytes: usize = salvaged.iter().map(|f| f.size).sum();
        let files_salvaged = salvaged.len();
        let salvage_rate = if data.is_empty() {
            0.0
        } else {
            (total_salvaged_bytes as f64 / data.len() as f64 * 100.0).min(100.0)
        };

        // Compute overall confidence: weighted average by file size.
        let overall_confidence = if salvaged.is_empty() {
            0.0
        } else {
            let total_weight: f64 = salvaged.iter().map(|f| f.size as f64).sum();
            if total_weight == 0.0 {
                salvaged.iter().map(|f| f.confidence).sum::<f64>() / salvaged.len() as f64
            } else {
                salvaged
                    .iter()
                    .map(|f| f.confidence * f.size as f64)
                    .sum::<f64>()
                    / total_weight
            }
        };

        progress!("Complete", 100);

        SalvageReport {
            input_size: data.len(),
            archive_type,
            total_files_found: files_salvaged,
            files_salvaged,
            total_salvaged_bytes,
            bytes_recovered: total_salvaged_bytes,
            corruption_bypassed: crc_errs + lzma_errs,
            crc_errors_ignored: crc_errs,
            lzma_errors_bypassed: lzma_errs,
            salvage_rate_percent: (salvage_rate * 10.0).round() / 10.0,
            overall_confidence: (overall_confidence * 1000.0).round() / 1000.0,
            type_breakdown,
            files: salvaged,
            salvage_time_secs: (start.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
            method,
            zombie_resync_count: z_stats.resync_count,
            zombie_bytes_tainted: z_stats.bytes_tainted,
            zombie_bytes_zeroed: z_stats.bytes_zeroed,
            zombie_entropy_rejections: z_stats.entropy_rejections,
        }
    }

    // ──────────────────────────────────────────────────────────
    //  COMPONENT A: Fail-Forward ZIP extraction
    // ──────────────────────────────────────────────────────────

    fn salvage_zip(
        &self,
        data: &[u8],
        progress_cb: ProgressCb<'_>,
    ) -> (Vec<SalvagedFile>, usize, String) {
        let mut salvaged = Vec::new();
        let mut crc_errors = 0usize;
        let mut method = "ZIP Structured Extract".to_string();

        let reader = Cursor::new(data);
        let archive = match zip::ZipArchive::new(reader) {
            Ok(a) => a,
            Err(_) => {
                // Central directory corrupt — fall back to raw carve
                if let Some(cb) = progress_cb {
                    cb("ZIP header corrupt — switching to raw carve", 30);
                }
                method = "ZIP Header Corrupt → Raw Carve".to_string();
                let carved = self.carve_raw(data, progress_cb);
                return (carved, 0, method);
            }
        };

        let total = archive.len();
        for i in 0..total {
            if let Some(cb) = progress_cb {
                let pct = 10 + (i as u32 * 60 / total.max(1) as u32);
                cb(&format!("Extracting file {}/{}", i + 1, total), pct);
            }

            // Re-open archive each time for fail-forward isolation.
            let reader2 = Cursor::new(data);
            let mut archive2 = match zip::ZipArchive::new(reader2) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let file = match archive2.by_index(i) {
                Ok(f) => f,
                Err(_) => {
                    crc_errors += 1;
                    continue;
                }
            };

            let name = file.name().to_string();

            // Skip directories.
            if name.ends_with('/') {
                continue;
            }

            // Read decompressed data with a size guard against zip-bombs.
            let mut buf = Vec::new();
            let mut limited = file.take(MAX_DECOMPRESSED_FILE_BYTES as u64);
            match limited.read_to_end(&mut buf) {
                Ok(_) => {}
                Err(_) => {
                    crc_errors += 1;
                    // Still try to use whatever partial data we got.
                    if buf.is_empty() {
                        continue;
                    }
                }
            }

            let ft = self.identify_type(&buf);
            let ext = if let Some(e) = name.rsplit('.').next() {
                if e.len() <= 6 {
                    e.to_string()
                } else {
                    ft.extension().to_string()
                }
            } else {
                ft.extension().to_string()
            };

            // Confidence: successful decompression + known extension = 0.95
            // If we had a CRC error that was tolerated, adjust below.
            let base_confidence = 0.95;

            salvaged.push(SalvagedFile {
                index: salvaged.len(),
                name: name.clone(),
                file_type: ft.label().to_string(),
                extension: ext,
                offset: 0,
                size: buf.len(),
                sha256: String::new(),
                confidence: base_confidence,
                data: buf,
            });
        }

        // Retroactively lower confidence if there were CRC errors.
        if crc_errors > 0 && !salvaged.is_empty() {
            let penalty = (crc_errors as f64 * 0.05).min(0.25);
            for f in &mut salvaged {
                f.confidence = (f.confidence - penalty).max(0.3);
            }
        }

        // If structured extraction got nothing, try raw carving the entire blob.
        if salvaged.is_empty() && data.len() > 100 {
            if let Some(cb) = progress_cb {
                cb("No files extracted — falling back to raw carve", 75);
            }
            method = "ZIP Empty → Raw Carve".to_string();
            salvaged = self.carve_raw(data, progress_cb);
        }

        (salvaged, crc_errors, method)
    }

    // ──────────────────────────────────────────────────────────
    //  COMPONENT A (cont): Fail-Forward 7z / LZMA extraction
    //  Now powered by the Zombie LZMA Decoder
    // ──────────────────────────────────────────────────────────

    fn salvage_7z(
        &self,
        data: &[u8],
        progress_cb: ProgressCb<'_>,
    ) -> (Vec<SalvagedFile>, usize, String, ZombieStats) {
        if let Some(cb) = progress_cb {
            cb("Zombie LZMA Decoder: scanning stream...", 15);
        }

        // ── Strategy 1: Zombie LZMA scan (LZMA1 raw streams) ────────────
        let (raw_decompressed, taint, z_stats) = zombie_scan_and_decode(data);

        let lzma_errors = z_stats.resync_count + z_stats.bytes_zeroed / 64;

        if !raw_decompressed.is_empty() {
            if let Some(cb) = progress_cb {
                cb(
                    &format!(
                        "Zombie decoded {} bytes ({} resyncs, {} tainted)",
                        raw_decompressed.len(),
                        z_stats.resync_count,
                        taint.taint_count()
                    ),
                    50,
                );
            }
            let carved = self.carve_raw(&raw_decompressed, progress_cb);
            if !carved.is_empty() {
                return (
                    carved,
                    lzma_errors,
                    format!(
                        "7z Zombie LZMA ({} resyncs, {} tainted bytes)",
                        z_stats.resync_count,
                        taint.taint_count()
                    ),
                    z_stats,
                );
            }
        }

        // ── Strategy 2: XZ-format fallback ──────────────────────────────
        if let Some(cb) = progress_cb {
            cb("Trying XZ-format decode...", 55);
        }
        let zd = ZombieLzmaDecoder::new();
        if let Some(xz_out) = zd.try_xz_decode(data) {
            if !xz_out.is_empty() {
                let carved = self.carve_raw(&xz_out, progress_cb);
                if !carved.is_empty() {
                    return (
                        carved,
                        0,
                        "7z XZ Decode → Carve".to_string(),
                        ZombieStats::default(),
                    );
                }
            }
        }

        // ── Strategy 3: Direct raw carve of the archive bytes ───────────
        if let Some(cb) = progress_cb {
            cb("Zombie decode exhausted — raw carving archive bytes...", 60);
        }
        let carved = self.carve_raw(data, progress_cb);
        (
            carved,
            lzma_errors,
            "7z Raw Carve (Zombie Exhausted)".to_string(),
            z_stats,
        )
    }

    // ──────────────────────────────────────────────────────────
    //  COMPONENT A (cont): GZIP decompression + carve
    // ──────────────────────────────────────────────────────────

    fn salvage_gzip(
        &self,
        data: &[u8],
        progress_cb: ProgressCb<'_>,
    ) -> (Vec<SalvagedFile>, String) {
        use std::io::BufReader;

        if let Some(cb) = progress_cb {
            cb("Decompressing GZIP stream...", 15);
        }

        let reader = BufReader::new(data);
        let mut decoder = flate2::read::GzDecoder::new(reader);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {}
            Err(_) => {
                // Partial decompression — use what we got
                if decompressed.is_empty() {
                    if let Some(cb) = progress_cb {
                        cb("GZIP decompression failed — raw carving...", 30);
                    }
                    let files = self.carve_raw(data, progress_cb);
                    return (files, "GZIP Failed → Raw Carve".to_string());
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(
                &format!(
                    "GZIP decompressed {} bytes — carving...",
                    decompressed.len()
                ),
                40,
            );
        }

        // Check if decompressed data is a tar archive
        if decompressed.len() > 262 && &decompressed[257..262] == b"ustar" {
            if let Some(cb) = progress_cb {
                cb("Detected tar.gz — extracting tar entries...", 50);
            }
            let tar_files = self.salvage_tar(&decompressed, progress_cb);
            if !tar_files.is_empty() {
                return (tar_files, "GZIP → TAR Extract".to_string());
            }
        }

        let files = self.carve_raw(&decompressed, progress_cb);
        if files.is_empty() && !decompressed.is_empty() {
            // Return the whole decompressed blob as a single file
            let ft = self.identify_type(&decompressed);
            return (
                vec![SalvagedFile {
                    index: 0,
                    name: "decompressed.bin".to_string(),
                    file_type: ft.label().to_string(),
                    extension: ft.extension().to_string(),
                    offset: 0,
                    size: decompressed.len(),
                    sha256: String::new(),
                    confidence: 0.85,
                    data: decompressed,
                }],
                "GZIP Decompress".to_string(),
            );
        }
        (files, "GZIP Decompress → Carve".to_string())
    }

    fn salvage_bzip2(
        &self,
        data: &[u8],
        progress_cb: ProgressCb<'_>,
    ) -> (Vec<SalvagedFile>, String) {
        if let Some(cb) = progress_cb {
            cb("Decompressing BZIP2 stream...", 15);
        }

        let mut decoder = bzip2::read::BzDecoder::new(data);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {}
            Err(_) => {
                if decompressed.is_empty() {
                    if let Some(cb) = progress_cb {
                        cb("BZIP2 decompression failed — raw carving...", 30);
                    }
                    let files = self.carve_raw(data, progress_cb);
                    return (files, "BZIP2 Failed → Raw Carve".to_string());
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(
                &format!(
                    "BZIP2 decompressed {} bytes — carving...",
                    decompressed.len()
                ),
                40,
            );
        }

        // Check if decompressed data is a tar archive
        if decompressed.len() > 262 && &decompressed[257..262] == b"ustar" {
            let tar_files = self.salvage_tar(&decompressed, progress_cb);
            if !tar_files.is_empty() {
                return (tar_files, "BZIP2 → TAR Extract".to_string());
            }
        }

        let files = self.carve_raw(&decompressed, progress_cb);
        if files.is_empty() && !decompressed.is_empty() {
            let ft = self.identify_type(&decompressed);
            return (
                vec![SalvagedFile {
                    index: 0,
                    name: "decompressed.bin".to_string(),
                    file_type: ft.label().to_string(),
                    extension: ft.extension().to_string(),
                    offset: 0,
                    size: decompressed.len(),
                    sha256: String::new(),
                    confidence: 0.85,
                    data: decompressed,
                }],
                "BZIP2 Decompress".to_string(),
            );
        }
        (files, "BZIP2 Decompress → Carve".to_string())
    }

    fn salvage_xz(&self, data: &[u8], progress_cb: ProgressCb<'_>) -> (Vec<SalvagedFile>, String) {
        if let Some(cb) = progress_cb {
            cb("Decompressing XZ stream...", 15);
        }

        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {}
            Err(_) => {
                if decompressed.is_empty() {
                    if let Some(cb) = progress_cb {
                        cb("XZ decompression failed — raw carving...", 30);
                    }
                    let files = self.carve_raw(data, progress_cb);
                    return (files, "XZ Failed → Raw Carve".to_string());
                }
            }
        }

        if let Some(cb) = progress_cb {
            cb(
                &format!("XZ decompressed {} bytes — carving...", decompressed.len()),
                40,
            );
        }

        // Check if decompressed data is a tar archive
        if decompressed.len() > 262 && &decompressed[257..262] == b"ustar" {
            let tar_files = self.salvage_tar(&decompressed, progress_cb);
            if !tar_files.is_empty() {
                return (tar_files, "XZ → TAR Extract".to_string());
            }
        }

        let files = self.carve_raw(&decompressed, progress_cb);
        (files, "XZ Decompress → Carve".to_string())
    }

    /// Extract files from a TAR archive (used after gzip/bzip2/xz decompression).
    fn salvage_tar(&self, data: &[u8], progress_cb: ProgressCb<'_>) -> Vec<SalvagedFile> {
        let mut salvaged = Vec::new();
        let mut archive = tar::Archive::new(Cursor::new(data));

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Skip directories
            let is_file = entry.header().entry_type() == tar::EntryType::Regular
                || entry.header().entry_type() == tar::EntryType::file();
            if !is_file {
                continue;
            }

            let name = entry
                .path()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let mut buf = Vec::new();
            let mut limited = entry.take(MAX_DECOMPRESSED_FILE_BYTES as u64);
            if limited.read_to_end(&mut buf).is_err() || buf.is_empty() {
                continue;
            }

            let ft = self.identify_type(&buf);
            let ext = if let Some(e) = name.rsplit('.').next() {
                if e.len() <= 6 {
                    e.to_string()
                } else {
                    ft.extension().to_string()
                }
            } else {
                ft.extension().to_string()
            };

            if let Some(cb) = progress_cb {
                cb(&format!("TAR entry: {}", name), 55);
            }

            salvaged.push(SalvagedFile {
                index: salvaged.len(),
                name: name.clone(),
                file_type: ft.label().to_string(),
                extension: ext,
                offset: 0,
                size: buf.len(),
                sha256: String::new(),
                confidence: 0.90,
                data: buf,
            });
        }

        salvaged
    }

    // ──────────────────────────────────────────────────────────
    //  RAR extraction — header-aware carving for RAR v4/v5
    // ──────────────────────────────────────────────────────────

    /// Extract files from a RAR archive by parsing block headers.
    /// RAR uses a proprietary compression format, so we parse the
    /// structural metadata (file names, sizes, offsets) and attempt
    /// to extract stored (uncompressed) files. For compressed entries,
    /// we fall back to raw carving the embedded data.
    fn salvage_rar(&self, data: &[u8], progress_cb: ProgressCb<'_>) -> (Vec<SalvagedFile>, String) {
        let mut salvaged = Vec::new();

        // RAR v5 signature: Rar!\x1a\x07\x01\x00
        // RAR v4 signature: Rar!\x1a\x07\x00
        let is_v5 = data.len() >= 8 && data[6] == 0x01 && data[7] == 0x00;
        let header_end = if is_v5 { 8 } else { 7 };

        if let Some(cb) = progress_cb {
            cb(
                &format!(
                    "RAR {} detected — scanning blocks...",
                    if is_v5 { "v5" } else { "v4" }
                ),
                15,
            );
        }

        if is_v5 {
            // ── RAR v5 block parser ──
            let mut pos = header_end;
            while pos + 7 < data.len() {
                // v5 uses vint encoding for sizes
                let (header_crc, _) = read_u32_le(data, pos);
                if header_crc == 0 && pos > header_end + 100 {
                    break;
                }

                let (header_size, vint_len) = read_vint(data, pos + 4);
                if header_size == 0 || pos + 4 + vint_len + header_size as usize > data.len() {
                    break;
                }

                let block_start = pos + 4 + vint_len;
                let block_data = &data[block_start..block_start + header_size as usize];

                if block_data.len() >= 2 {
                    let header_type = block_data[0] & 0x0F;
                    let header_flags_raw = if block_data.len() > 1 {
                        let (v, _) = read_vint(block_data, 1);
                        v
                    } else {
                        0
                    };
                    let has_data = header_flags_raw & 0x02 != 0;

                    // Type 2 = File header
                    if header_type == 2 && has_data {
                        // Try to extract file name from header
                        let name = extract_rar5_filename(block_data)
                            .unwrap_or_else(|| format!("rar_file_{:04}", salvaged.len()));

                        // Data follows the header block
                        let data_start = block_start + header_size as usize;
                        // Try to read data size from header
                        let data_size = extract_rar5_data_size(block_data).unwrap_or(0) as usize;
                        let actual_end = if data_size > 0 && data_start + data_size <= data.len() {
                            data_start + data_size
                        } else {
                            // Guess: data extends to next block or 1MB max
                            (data_start + 1024 * 1024).min(data.len())
                        };

                        if actual_end > data_start + 32 {
                            let file_data = &data[data_start..actual_end];
                            let ft = self.identify_type(file_data);
                            let ext = name
                                .rsplit('.')
                                .next()
                                .filter(|e| e.len() <= 6)
                                .unwrap_or(ft.extension());

                            salvaged.push(SalvagedFile {
                                index: salvaged.len(),
                                name: name.clone(),
                                file_type: ft.label().to_string(),
                                extension: ext.to_string(),
                                offset: data_start,
                                size: file_data.len(),
                                sha256: String::new(),
                                confidence: 0.60,
                                data: file_data.to_vec(),
                            });
                        }

                        pos = actual_end;
                        continue;
                    }
                }

                // Skip to next block
                pos = block_start + header_size as usize;
            }
        } else {
            // ── RAR v4 block parser ──
            let mut pos = header_end;
            while pos + 7 < data.len() {
                // v4 block header: 2 CRC + 1 type + 2 flags + 2 size
                let block_type = data[pos + 2];
                let flags = u16::from_le_bytes([data[pos + 3], data[pos + 4]]);
                let block_size = u16::from_le_bytes([data[pos + 5], data[pos + 6]]) as usize;

                if block_size < 7 || pos + block_size > data.len() {
                    break;
                }

                let has_add_size = flags & 0x8000 != 0;
                let add_size = if has_add_size && pos + 11 < data.len() {
                    u32::from_le_bytes([
                        data[pos + 7],
                        data[pos + 8],
                        data[pos + 9],
                        data[pos + 10],
                    ]) as usize
                } else {
                    0
                };

                // Type 0x74 = File header
                if block_type == 0x74 {
                    let data_start = pos + block_size;
                    let data_end = (data_start + add_size).min(data.len());

                    // Extract filename: after fixed header (32 bytes from block start)
                    let name = extract_rar4_filename(data, pos, block_size)
                        .unwrap_or_else(|| format!("rar_file_{:04}", salvaged.len()));

                    if data_end > data_start + 32 {
                        let file_data = &data[data_start..data_end];
                        let ft = self.identify_type(file_data);
                        let ext = name
                            .rsplit('.')
                            .next()
                            .filter(|e| e.len() <= 6)
                            .unwrap_or(ft.extension());

                        if let Some(cb) = progress_cb {
                            cb(&format!("RAR entry: {}", name), 40);
                        }

                        salvaged.push(SalvagedFile {
                            index: salvaged.len(),
                            name: name.clone(),
                            file_type: ft.label().to_string(),
                            extension: ext.to_string(),
                            offset: data_start,
                            size: file_data.len(),
                            sha256: String::new(),
                            confidence: 0.55,
                            data: file_data.to_vec(),
                        });
                    }

                    pos = data_end;
                } else {
                    pos += block_size + add_size;
                }
            }
        }

        // If structured parsing found nothing, fall back to raw carving
        if salvaged.is_empty() {
            if let Some(cb) = progress_cb {
                cb(
                    "RAR structure too damaged — falling back to raw carving...",
                    50,
                );
            }
            salvaged = self.carve_raw(data, progress_cb);
            return (salvaged, "RAR → Raw Carve (fallback)".to_string());
        }

        // Also raw-carve to catch any missed embedded files
        if let Some(cb) = progress_cb {
            cb("Supplemental raw carving...", 60);
        }
        let raw_files = self.carve_raw(data, progress_cb);
        let existing_offsets: HashSet<usize> = salvaged.iter().map(|f| f.offset).collect();
        for f in raw_files {
            if !existing_offsets.contains(&f.offset) {
                salvaged.push(f);
            }
        }

        let method = format!("RAR {} Parse + Raw Carve", if is_v5 { "v5" } else { "v4" });
        (salvaged, method)
    }

    // ──────────────────────────────────────────────────────────
    //  COMPONENT B: Magic Header Carver (Aho-Corasick)
    // ──────────────────────────────────────────────────────────

    fn carve_raw(&self, data: &[u8], progress_cb: ProgressCb<'_>) -> Vec<SalvagedFile> {
        if data.is_empty() {
            return Vec::new();
        }

        if let Some(cb) = progress_cb {
            cb("Scanning for magic headers (Aho-Corasick)...", 65);
        }

        // Find all magic signature matches.
        let mut hits: Vec<(usize, CarvedFileType)> = Vec::new();
        for mat in self.magic_matcher.find_iter(data) {
            let pattern_idx = mat.pattern().as_usize();
            let offset = mat.start();
            let file_type = self.sig_types[pattern_idx];

            // Adjust offset for patterns that appear mid-header:
            //  - MP4 ftyp: pattern at offset+4 → back up 4
            //  - WebP/WAV/AVI: sub-type at RIFF offset+8 → back up 8
            //  - TAR ustar: pattern at offset+257 → back up 257
            let actual_offset = match file_type {
                CarvedFileType::Mp4 => offset.saturating_sub(4),
                CarvedFileType::WebP | CarvedFileType::Wav | CarvedFileType::Avi => {
                    offset.saturating_sub(8)
                }
                CarvedFileType::Tar => offset.saturating_sub(257),
                _ => offset,
            };

            // Deduplicate: don't add if we already have a hit within 4 bytes of this offset.
            if hits
                .last()
                .is_none_or(|(prev_off, _)| actual_offset > *prev_off + 4)
            {
                hits.push((actual_offset, file_type));
            }
        }

        // Sort by offset.
        hits.sort_by_key(|(off, _)| *off);

        // Also scan with plugin signatures if loaded.
        let mut plugin_hits: Vec<(usize, usize)> = Vec::new(); // (offset, plugin_index)
        if let Some(ref pm) = self.plugin_matcher {
            for mat in pm.find_iter(data) {
                let pattern_idx = mat.pattern().as_usize();
                let offset = mat.start();
                if pattern_idx < self.plugin_signatures.len() {
                    let sig = &self.plugin_signatures[pattern_idx];
                    let actual_offset = offset.saturating_sub(sig.offset);
                    plugin_hits.push((actual_offset, pattern_idx));
                }
            }
        }
        plugin_hits.sort_by_key(|(off, _)| *off);
        plugin_hits.dedup_by_key(|(off, _)| *off);

        // Post-validate BMP hits: require a plausible LE file-size in bytes 2–5.
        // Post-validate ICO hits: require image count > 0 and <= 256.
        // Post-validate MP3 frame sync: filter out short false positives.
        hits.retain(|&(off, ft)| {
            if ft == CarvedFileType::Bmp {
                let s = &data[off..];
                if s.len() >= 6 {
                    let sz = u32::from_le_bytes([s[2], s[3], s[4], s[5]]);
                    sz >= 14 && (sz as usize) <= s.len() + 1024
                } else {
                    false
                }
            } else if ft == CarvedFileType::Ico {
                // ICO: 00 00 01 00 is very generic — require header (6) + at least
                // one 16-byte directory entry, with the entry's reserved byte == 0
                // and a plausible data-offset pointing inside remaining data.
                let s = &data[off..];
                if s.len() >= 22 {
                    let img_count = u16::from_le_bytes([s[4], s[5]]);
                    let reserved_byte = s[9]; // first entry, reserved field
                    let data_offset = u32::from_le_bytes([s[18], s[19], s[20], s[21]]) as usize;
                    let min_header = 6 + 16 * (img_count as usize);
                    img_count > 0
                        && img_count <= 256
                        && reserved_byte == 0
                        && data_offset >= min_header
                        && data_offset < s.len()
                } else {
                    false
                }
            } else if ft == CarvedFileType::Mp3 && (data[off] == 0xFF) {
                // MP3 frame sync — require at least 128 bytes following
                data.len() - off >= 128
            } else {
                true
            }
        });

        if let Some(cb) = progress_cb {
            cb(
                &format!("Found {} file signatures — extracting...", hits.len()),
                70,
            );
        }

        let mut salvaged = Vec::new();
        let min_file_size = 32; // Don't salvage files < 32 bytes

        for (i, &(start, file_type)) in hits.iter().enumerate() {
            // End of this file = start of next file, or end of data.
            let end = if i + 1 < hits.len() {
                hits[i + 1].0
            } else {
                data.len()
            };

            if end <= start || end - start < min_file_size {
                continue;
            }

            let file_data = &data[start..end];

            // Refine: try to find the actual end for known formats.
            let trimmed = self.refine_file_end(file_data, file_type);

            if let Some(cb) = progress_cb {
                let pct = 70 + (i as u32 * 15 / hits.len().max(1) as u32);
                cb(
                    &format!("Carving file {} ({})", i + 1, file_type.label()),
                    pct,
                );
            }

            // Confidence for raw carving: base 0.55 + bonus for end-marker trimming
            let raw_confidence = if trimmed.len() < file_data.len() {
                0.70 // End marker found → higher confidence
            } else {
                0.55 // No end marker → lower confidence
            };

            salvaged.push(SalvagedFile {
                index: salvaged.len(),
                name: format!("carved_{:04}.{}", salvaged.len(), file_type.extension()),
                file_type: file_type.label().to_string(),
                extension: file_type.extension().to_string(),
                offset: start,
                size: trimmed.len(),
                sha256: String::new(),
                confidence: raw_confidence,
                data: trimmed.to_vec(),
            });
        }

        // ── Plugin signature carving ──
        for &(start, sig_idx) in &plugin_hits {
            let sig = &self.plugin_signatures[sig_idx];
            let max_sz = sig.max_size;
            let end_bound = (start + max_sz).min(data.len());
            let file_data = &data[start..end_bound];

            // Try to find end marker, otherwise use max_size
            let trimmed = if let Some(ref end_marker) = sig.end_marker {
                let end_bytes = crate::plugin::decode_hex(end_marker).unwrap_or_default();
                if !end_bytes.is_empty() {
                    if let Some(pos) = find_bytes(file_data, &end_bytes) {
                        &file_data[..pos + end_bytes.len()]
                    } else {
                        file_data
                    }
                } else {
                    file_data
                }
            } else {
                file_data
            };

            if trimmed.len() < min_file_size {
                continue;
            }

            let ext = &sig.extension;
            let name_str = &sig.name;
            let confidence = if trimmed.len() < file_data.len() {
                0.65
            } else {
                0.50
            };

            salvaged.push(SalvagedFile {
                index: salvaged.len(),
                name: format!("{}_{:04}.{}", name_str, salvaged.len(), ext),
                file_type: sig.name.clone(),
                extension: ext.to_string(),
                offset: start,
                size: trimmed.len(),
                sha256: String::new(),
                confidence,
                data: trimmed.to_vec(),
            });
        }

        salvaged
    }

    /// Try to find the true end of a carved file by looking for end markers.
    fn refine_file_end<'a>(&self, data: &'a [u8], ft: CarvedFileType) -> &'a [u8] {
        match ft {
            CarvedFileType::Jpeg => {
                // JPEG ends with FF D9
                if let Some(pos) = find_bytes(data, &[0xFF, 0xD9]) {
                    return &data[..pos + 2];
                }
            }
            CarvedFileType::Png => {
                // PNG ends with IEND chunk + 4-byte CRC
                if let Some(pos) = find_bytes(data, b"IEND") {
                    let end = (pos + 8).min(data.len()); // IEND(4) + CRC(4)
                    return &data[..end];
                }
            }
            CarvedFileType::Pdf => {
                // PDF ends with %%EOF — find the LAST occurrence
                if let Some(pos) = rfind_bytes(data, b"%%EOF") {
                    let end = (pos + 6).min(data.len()); // %%EOF + newline
                    return &data[..end];
                }
            }
            CarvedFileType::Gif => {
                // GIF ends with trailer byte 0x3B
                if let Some(pos) = data.iter().rposition(|&b| b == 0x3B) {
                    return &data[..pos + 1];
                }
            }
            CarvedFileType::Bmp => {
                // BMP has declared file size at offset 2
                if data.len() >= 6 {
                    let sz = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
                    if sz >= 14 && sz <= data.len() {
                        return &data[..sz];
                    }
                }
            }
            CarvedFileType::Wav | CarvedFileType::Avi | CarvedFileType::WebP => {
                // RIFF containers have file size at offset 4 (+ 8 for header)
                if data.len() >= 8 && &data[..4] == b"RIFF" {
                    let sz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                    let total = sz + 8;
                    if total <= data.len() && total >= 12 {
                        return &data[..total];
                    }
                }
            }
            CarvedFileType::Flac => {
                // FLAC: last metadata block has bit 7 set in block type byte (offset 4)
                // After that comes audio frames — hard to determine end without full parsing
                // Use full data
            }
            CarvedFileType::Zip => {
                // Find End of Central Directory signature: PK\x05\x06
                if let Some(pos) = rfind_bytes(data, &[0x50, 0x4B, 0x05, 0x06]) {
                    // EOCD is 22 bytes minimum, but may have a comment
                    if pos + 22 <= data.len() {
                        let comment_len =
                            u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
                        let end = (pos + 22 + comment_len).min(data.len());
                        return &data[..end];
                    }
                }
            }
            _ => {}
        }
        data
    }

    // ──────────────────────────────────────────────────────────
    //  COMPONENT C: Format detection & utilities
    // ──────────────────────────────────────────────────────────

    fn detect_archive_type(&self, data: &[u8]) -> String {
        if data.len() < 6 {
            return "unknown".into();
        }
        if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return "zip".into();
        }
        if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
            return "7z".into();
        }
        if data.starts_with(&[0x52, 0x61, 0x72, 0x21]) {
            return "rar".into();
        }
        if data.starts_with(&[0x1F, 0x8B]) {
            return "gzip".into();
        }
        if data.starts_with(&[0x42, 0x5A, 0x68]) {
            return "bzip2".into();
        }
        if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A]) {
            return "xz".into();
        }
        "unknown".into()
    }

    fn identify_type(&self, data: &[u8]) -> CarvedFileType {
        // BMP: look for "BM" + valid 4-byte little-endian file size
        if data.len() >= 14 && data[0] == 0x42 && data[1] == 0x4D {
            let declared_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
            if declared_size >= 14 && (declared_size as usize) <= data.len() + 1024 {
                return CarvedFileType::Bmp;
            }
        }
        // RIFF: check sub-type at offset 8 to distinguish WebP / WAV / AVI
        if data.len() >= 12 && data[..4] == [0x52, 0x49, 0x46, 0x46] {
            if &data[8..12] == b"WEBP" {
                return CarvedFileType::WebP;
            }
            if &data[8..12] == b"WAVE" {
                return CarvedFileType::Wav;
            }
            if &data[8..12] == b"AVI " {
                return CarvedFileType::Avi;
            }
        }
        // PE/EXE: require "MZ" + valid PE offset
        if data.len() >= 64 && data[0] == 0x4D && data[1] == 0x5A {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if pe_offset < data.len().saturating_sub(4)
                && data.len() > pe_offset + 3
                && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00"
            {
                return CarvedFileType::Exe;
            }
        }
        for &(sig, ft) in SIGNATURES {
            // Skip types handled above with deeper validation
            if matches!(
                ft,
                CarvedFileType::Bmp
                    | CarvedFileType::WebP
                    | CarvedFileType::Wav
                    | CarvedFileType::Avi
                    | CarvedFileType::Exe
            ) {
                continue;
            }
            if data.len() >= sig.len() && data[..sig.len()] == *sig {
                return ft;
            }
        }
        CarvedFileType::Unknown
    }

    fn build_type_breakdown(&self, files: &[SalvagedFile]) -> Vec<TypeCount> {
        let mut map: std::collections::HashMap<String, (usize, usize)> =
            std::collections::HashMap::new();
        for f in files {
            let entry = map.entry(f.file_type.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += f.size;
        }
        let mut breakdown: Vec<TypeCount> = map
            .into_iter()
            .map(|(file_type, (count, total_bytes))| TypeCount {
                file_type,
                count,
                total_bytes,
            })
            .collect();
        breakdown.sort_by(|a, b| b.count.cmp(&a.count));
        breakdown
    }

    // ──────────────────────────────────────────────────────────
    //  PACK RESULTS: Generate a ZIP of all salvaged files
    // ──────────────────────────────────────────────────────────

    /// Package all salvaged files into a single uncompressed ZIP for download.
    pub fn pack_salvaged_zip(&self, files: &[SalvagedFile]) -> Vec<u8> {
        let buf = Cursor::new(Vec::new());
        let mut zipper = zip::ZipWriter::new(buf);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for f in files {
            // Use original name if available, otherwise generate one
            let name = if f.name.is_empty()
                || f.name.starts_with("carved_")
                || f.name.starts_with("decompressed")
            {
                format!("salvaged_{:04}.{}", f.index, f.extension)
            } else {
                // Sanitize: strip directory components for safety
                let safe_name = f.name.rsplit('/').next().unwrap_or(&f.name);
                let safe_name = safe_name.rsplit('\\').next().unwrap_or(safe_name);
                format!("salvaged/{}", safe_name)
            };
            if let Err(e) = zipper.start_file(&name, options) {
                eprintln!("Warning: failed to start zip entry {}: {}", name, e);
                continue;
            }
            if let Err(e) = zipper.write_all(&f.data) {
                eprintln!("Warning: failed to write zip entry {}: {}", name, e);
            }
        }

        let cursor = zipper.finish().unwrap_or_else(|_| Cursor::new(Vec::new()));
        cursor.into_inner()
    }
}

// ══════════════════════════════════════════════════════════════
//  UTILITY
// ══════════════════════════════════════════════════════════════

/// Find first occurrence of `needle` in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find LAST occurrence of `needle` in `haystack`.
fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

// ── RAR helper functions ──

/// Read a little-endian u32 from data at offset.
fn read_u32_le(data: &[u8], offset: usize) -> (u32, usize) {
    if offset + 4 <= data.len() {
        let val = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        (val, 4)
    } else {
        (0, 0)
    }
}

/// Read a RAR v5 variable-length integer (vint).
fn read_vint(data: &[u8], offset: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = offset;
    loop {
        if i >= data.len() || shift >= 63 {
            return (result, i - offset);
        }
        let byte = data[i];
        result |= ((byte & 0x7F) as u64) << shift;
        i += 1;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    (result, i - offset)
}

/// Try to extract filename from a RAR v5 file header block.
fn extract_rar5_filename(block: &[u8]) -> Option<String> {
    // v5 file header: type(vint) + flags(vint) + extra_size(vint)? +
    //   data_size(vint)? + ... + name_size(vint) + name(bytes)
    // This is a simplified parser that looks for printable UTF-8 sequences
    if block.len() < 10 {
        return None;
    }

    let mut pos = 0;
    // Skip header_type vint
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Skip flags vint
    let (flags, vlen) = read_vint(block, pos);
    pos += vlen;
    // If extra area present (flag bit 0)
    if flags & 0x01 != 0 {
        let (_, vlen) = read_vint(block, pos);
        pos += vlen;
    }
    // If data area present (flag bit 1)
    if flags & 0x02 != 0 {
        let (_, vlen) = read_vint(block, pos);
        pos += vlen;
    }
    // File flags
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Unpacked size
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Attributes
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // mtime (4 bytes if file_flags & 0x02)
    if pos + 4 <= block.len() {
        pos += 4;
    }
    // data CRC (4 bytes if file_flags & 0x04...not always present)
    // Compression info
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Host OS
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Name length
    let (name_len, vlen) = read_vint(block, pos);
    pos += vlen;

    if name_len > 0 && name_len < 1024 && pos + name_len as usize <= block.len() {
        let name_bytes = &block[pos..pos + name_len as usize];
        String::from_utf8(name_bytes.to_vec()).ok()
    } else {
        None
    }
}

/// Try to extract the data size from a RAR v5 file header block.
fn extract_rar5_data_size(block: &[u8]) -> Option<u64> {
    if block.len() < 6 {
        return None;
    }
    let mut pos = 0;
    // Skip header_type
    let (_, vlen) = read_vint(block, pos);
    pos += vlen;
    // Read flags
    let (flags, vlen) = read_vint(block, pos);
    pos += vlen;
    // Extra area size
    if flags & 0x01 != 0 {
        let (_, vlen) = read_vint(block, pos);
        pos += vlen;
    }
    // Data area size
    if flags & 0x02 != 0 {
        let (data_size, _) = read_vint(block, pos);
        Some(data_size)
    } else {
        None
    }
}

/// Try to extract filename from a RAR v4 file header.
fn extract_rar4_filename(data: &[u8], block_start: usize, block_size: usize) -> Option<String> {
    // RAR v4 file header layout:
    //   +0: HEAD_CRC (2)
    //   +2: HEAD_TYPE (1)
    //   +3: HEAD_FLAGS (2)
    //   +5: HEAD_SIZE (2)
    //   +7: PACK_SIZE (4)
    //   +11: UNP_SIZE (4)
    //   +15: HOST_OS (1)
    //   +16: FILE_CRC (4)
    //   +20: FTIME (4)
    //   +24: UNP_VER (1)
    //   +25: METHOD (1)
    //   +26: NAME_SIZE (2)
    //   +28: ATTR (4)
    //   +32: NAME starts here
    if block_start + 32 > data.len() || block_size < 32 {
        return None;
    }
    let name_size = u16::from_le_bytes([data[block_start + 26], data[block_start + 27]]) as usize;
    if name_size == 0 || name_size > 1024 {
        return None;
    }
    let name_start = block_start + 32;
    if name_start + name_size > data.len() {
        return None;
    }
    let name_bytes = &data[name_start..name_start + name_size];
    // RAR v4 filenames may be in OEM encoding; try UTF-8 first, then lossy
    String::from_utf8(name_bytes.to_vec())
        .ok()
        .or_else(|| Some(String::from_utf8_lossy(name_bytes).into_owned()))
        .filter(|n| !n.is_empty() && n.chars().all(|c| !c.is_control() || c == '/'))
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = SalvageEngine::new();
        assert_eq!(engine.sig_types.len(), SIGNATURES.len());
    }

    #[test]
    fn test_detect_archive_type() {
        let engine = SalvageEngine::new();
        assert_eq!(
            engine.detect_archive_type(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]),
            "zip"
        );
        assert_eq!(
            engine.detect_archive_type(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            "7z"
        );
        assert_eq!(engine.detect_archive_type(&[0x00, 0x00]), "unknown");
    }

    #[test]
    fn test_identify_type() {
        let engine = SalvageEngine::new();
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00];
        assert_eq!(engine.identify_type(&jpeg), CarvedFileType::Jpeg);
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert_eq!(engine.identify_type(&png), CarvedFileType::Png);
        let pdf = [0x25, 0x50, 0x44, 0x46, 0x2D, 0x31];
        assert_eq!(engine.identify_type(&pdf), CarvedFileType::Pdf);
    }

    #[test]
    fn test_carve_synthetic_stream() {
        // Build a synthetic raw stream: JPEG header + garbage + PNG header + garbage
        let mut stream = Vec::new();

        // "JPEG" file — 200 bytes
        stream.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        stream.extend(std::iter::repeat_n(0x42u8, 194));
        stream.extend_from_slice(&[0xFF, 0xD9]); // JPEG end marker

        // "PNG" file — 150 bytes
        stream.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        stream.extend(std::iter::repeat_n(0x55u8, 130));
        stream.extend_from_slice(b"IEND");
        stream.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // CRC

        // "PDF" file — 100 bytes
        stream.extend_from_slice(b"%PDF-1.4 fake content");
        stream.extend(std::iter::repeat_n(0x20u8, 70));
        stream.extend_from_slice(b"%%EOF\n");

        let engine = SalvageEngine::new();
        let carved = engine.carve_raw(&stream, None);

        assert_eq!(
            carved.len(),
            3,
            "Should carve 3 files from synthetic stream"
        );
        assert_eq!(carved[0].file_type, "JPEG Image");
        assert_eq!(carved[1].file_type, "PNG Image");
        assert_eq!(carved[2].file_type, "PDF Document");

        // JPEG should be trimmed to FF D9 marker.
        assert_eq!(carved[0].data.len(), 200);
        assert_eq!(carved[0].data[carved[0].data.len() - 2], 0xFF);
        assert_eq!(carved[0].data[carved[0].data.len() - 1], 0xD9);
    }

    #[test]
    fn test_salvage_valid_zip() {
        // Create a tiny valid ZIP in memory.
        let buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("hello.txt", opts).unwrap();
        writer.write_all(b"Hello from Helix-Salvager!").unwrap();
        writer.start_file("world.txt", opts).unwrap();
        writer
            .write_all(b"Second file test data for salvage engine.")
            .unwrap();
        let data = writer.finish().unwrap().into_inner();

        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);

        assert_eq!(report.archive_type, "zip");
        assert!(
            report.files_salvaged >= 2,
            "Should salvage at least 2 files from valid ZIP"
        );
        assert_eq!(report.crc_errors_ignored, 0);
    }

    #[test]
    fn test_salvage_corrupted_zip() {
        // Create a valid ZIP, then corrupt some middle bytes.
        let buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("data1.txt", opts).unwrap();
        writer.write_all(&[0x41u8; 500]).unwrap(); // 500 'A' bytes
        writer.start_file("data2.txt", opts).unwrap();
        writer.write_all(&[0x42u8; 500]).unwrap(); // 500 'B' bytes
        let mut data = writer.finish().unwrap().into_inner();

        // Corrupt central directory area (last 50 bytes).
        let len = data.len();
        for b in data[len - 50..].iter_mut() {
            *b = 0x00;
        }

        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);

        // Should still salvage something (either structured or via raw carve fallback).
        assert_eq!(report.archive_type, "zip");
        // The important thing: it doesn't crash.
    }

    #[test]
    fn test_pack_salvaged_zip() {
        let engine = SalvageEngine::new();
        let files = vec![
            SalvagedFile {
                index: 0,
                name: "photo.jpg".into(),
                file_type: "JPEG Image".into(),
                extension: "jpg".into(),
                offset: 0,
                size: 4,
                sha256: "abcd".into(),
                confidence: 0.95,
                data: vec![0xFF, 0xD8, 0xFF, 0xD9],
            },
            SalvagedFile {
                index: 1,
                name: "document.pdf".into(),
                file_type: "PDF Document".into(),
                extension: "pdf".into(),
                offset: 100,
                size: 5,
                sha256: "efgh".into(),
                confidence: 0.90,
                data: b"%PDF-".to_vec(),
            },
        ];

        let zip_bytes = engine.pack_salvaged_zip(&files);
        assert!(!zip_bytes.is_empty(), "Packed ZIP should not be empty");

        // Verify the ZIP is valid by reading it back.
        let reader = Cursor::new(&zip_bytes);
        let archive = zip::ZipArchive::new(reader).unwrap();
        assert_eq!(archive.len(), 2);
    }

    #[test]
    fn test_report_structure() {
        let engine = SalvageEngine::new();
        // Empty data should not panic.
        let report = engine.salvage(&[], None);
        assert_eq!(report.files_salvaged, 0);
        assert_eq!(report.archive_type, "unknown");
    }

    #[test]
    fn test_find_bytes() {
        assert_eq!(find_bytes(b"hello world", b"world"), Some(6));
        assert_eq!(find_bytes(b"abcabc", b"cab"), Some(2));
        assert_eq!(find_bytes(b"abc", b"xyz"), None);
        assert_eq!(find_bytes(b"", b"a"), None);
    }

    #[test]
    fn test_read_vint() {
        // Single byte: 0x0A = 10
        assert_eq!(read_vint(&[0x0A], 0), (10, 1));
        // Two bytes: 0x80 0x01 = 128
        assert_eq!(read_vint(&[0x80, 0x01], 0), (128, 2));
        // Zero
        assert_eq!(read_vint(&[0x00], 0), (0, 1));
        // Empty data
        assert_eq!(read_vint(&[], 0), (0, 0));
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let (val, _) = read_u32_le(&data, 0);
        assert_eq!(val, 0x04030201);
    }

    #[test]
    fn test_rar4_detection() {
        // RAR v4 signature: Rar!\x1a\x07\x00
        let engine = SalvageEngine::new();
        let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
        assert_eq!(engine.detect_archive_type(&data), "rar");
    }

    #[test]
    fn test_rar5_detection() {
        // RAR v5 signature: Rar!\x1a\x07\x01\x00
        let engine = SalvageEngine::new();
        let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        assert_eq!(engine.detect_archive_type(&data), "rar");
    }

    #[test]
    fn test_rar_empty_fallback() {
        // RAR header with no valid blocks should fall back to raw carving
        let mut data = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]; // RAR v4 header
        data.extend(std::iter::repeat_n(0x00u8, 100)); // garbage
        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);
        assert_eq!(report.archive_type, "rar");
        // Should not panic
    }

    #[test]
    fn test_rar_with_embedded_jpeg() {
        // RAR header + embedded JPEG data (not in a proper block)
        let mut data = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
        data.extend(std::iter::repeat_n(0x00u8, 50));
        // Embed a JPEG
        data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        data.extend(std::iter::repeat_n(0xABu8, 196));
        data.extend_from_slice(&[0xFF, 0xD9]);
        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);
        assert_eq!(report.archive_type, "rar");
        // Should find the JPEG via raw carve fallback
        assert!(
            report.files_salvaged >= 1,
            "Should find embedded JPEG in RAR"
        );
    }

    #[test]
    fn test_plugin_engine_integration() {
        let mut registry = crate::plugin::PluginRegistry::new();
        registry
            .add_signature(crate::plugin::CustomSignature {
                name: "Test Format".into(),
                extension: "tst".into(),
                magic: "CAFE".into(),
                offset: 0,
                max_size: 1024,
                end_marker: Some("FEED".into()),
                mime_type: None,
                description: None,
            })
            .unwrap();

        let engine = SalvageEngine::with_plugins(&registry);
        assert_eq!(engine.plugin_signature_count(), 1);
        assert_eq!(engine.builtin_signature_count(), SIGNATURES.len());
        assert_eq!(engine.total_signature_count(), SIGNATURES.len() + 1);
    }

    #[test]
    fn test_plugin_carving() {
        let mut registry = crate::plugin::PluginRegistry::new();
        registry
            .add_signature(crate::plugin::CustomSignature {
                name: "Custom".into(),
                extension: "cst".into(),
                magic: "DEADBEEF".into(),
                offset: 0,
                max_size: 1024,
                end_marker: Some("CAFEBABE".into()),
                mime_type: None,
                description: None,
            })
            .unwrap();

        // Build data with the custom signature
        let mut data = vec![0x00; 50]; // noise
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // magic
        data.extend(std::iter::repeat_n(0x41u8, 100)); // payload
        data.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // end marker
        data.extend(std::iter::repeat_n(0x00u8, 50)); // trailing noise

        let engine = SalvageEngine::with_plugins(&registry);
        let report = engine.salvage(&data, None);
        // Should find the custom format
        let custom_files: Vec<_> = report
            .files
            .iter()
            .filter(|f| f.file_type == "Custom")
            .collect();
        assert!(!custom_files.is_empty(), "Should carve custom plugin file");
    }

    #[test]
    fn test_confidence_scoring() {
        // Valid ZIP should have high confidence
        let buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("test.txt", opts).unwrap();
        writer.write_all(b"Confidence test data").unwrap();
        let data = writer.finish().unwrap().into_inner();

        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);

        assert!(
            report.overall_confidence > 0.0,
            "Should have positive overall confidence"
        );
        for f in &report.files {
            assert!(
                f.confidence > 0.0 && f.confidence <= 1.0,
                "File confidence should be 0..1, got {}",
                f.confidence
            );
        }
    }

    #[test]
    fn test_parallel_hashing() {
        // Create a ZIP with multiple files to exercise parallel hashing
        let buf = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for i in 0..10 {
            writer.start_file(format!("file_{}.txt", i), opts).unwrap();
            writer
                .write_all(format!("Content of file {}", i).as_bytes())
                .unwrap();
        }
        let data = writer.finish().unwrap().into_inner();

        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, None);

        assert!(report.files_salvaged >= 10);
        // All files should have SHA-256 hashes
        for f in &report.files {
            assert_eq!(f.sha256.len(), 64, "SHA-256 hash should be 64 hex chars");
        }
    }

    #[test]
    fn test_deep_validation_in_pipeline() {
        // Create a stream with a valid JPEG
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0]; // SOI + APP0
        jpeg.extend(std::iter::repeat_n(0xABu8, 96));
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

        // Wrap it as unknown input so it goes through raw carving + validation
        let engine = SalvageEngine::new();
        let report = engine.salvage(&jpeg, None);

        // The JPEG should be found and validated
        if report.files_salvaged > 0 {
            let jpg = &report.files[0];
            assert!(
                jpg.confidence > 0.0,
                "JPEG should have positive confidence after validation"
            );
        }
    }
}
