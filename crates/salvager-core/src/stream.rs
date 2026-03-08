//! Streaming mode — process files larger than available RAM.
//!
//! Instead of loading the entire file into memory, the streaming engine
//! memory-maps the file and processes it in overlapping windows. This allows
//! recovery from disk images and archives that are many gigabytes in size.
//!
//! ## Strategy
//!
//! 1. Memory-map the file (zero-copy, OS manages paging)
//! 2. Slide a configurable window across the file
//! 3. Run the magic-header carver on each window
//! 4. Merge results, deduplicating files that span window boundaries
//!
//! For structured archives (ZIP, 7z), the full file is still needed for
//! metadata parsing. Streaming mode is most effective for raw carving.

use crate::salvager::{ProgressCb, SalvageEngine, SalvagedFile};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

/// Configuration for streaming recovery.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Size of each processing window in bytes.
    /// Default: 64 MB.
    pub window_size: usize,
    /// Overlap between consecutive windows, to catch files that straddle
    /// window boundaries. Default: 1 MB.
    pub overlap: usize,
    /// Minimum file size to salvage (bytes). Default: 32.
    pub min_file_size: usize,
    /// Whether to attempt structured archive extraction on the full file
    /// if the header looks like a known archive. Default: true.
    pub try_structured: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            window_size: 64 * 1024 * 1024, // 64 MB
            overlap: 1024 * 1024,          // 1 MB
            min_file_size: 32,
            try_structured: true,
        }
    }
}

impl StreamConfig {
    /// Small window preset for memory-constrained environments.
    pub fn low_memory() -> Self {
        Self {
            window_size: 16 * 1024 * 1024,
            overlap: 512 * 1024,
            ..Default::default()
        }
    }

    /// Large window preset for high-performance systems.
    pub fn high_performance() -> Self {
        Self {
            window_size: 256 * 1024 * 1024,
            overlap: 4 * 1024 * 1024,
            ..Default::default()
        }
    }
}

/// Result of streaming recovery.
#[derive(Debug, Clone)]
pub struct StreamReport {
    /// Total input file size.
    pub input_size: u64,
    /// Number of windows processed.
    pub windows_processed: usize,
    /// All recovered files (deduplicated).
    pub files: Vec<SalvagedFile>,
    /// Total files recovered.
    pub files_salvaged: usize,
    /// Total bytes recovered.
    pub bytes_recovered: usize,
    /// Method description.
    pub method: String,
    /// Processing time in seconds.
    pub scan_time_secs: f64,
}

/// Process a large file using streaming (memory-mapped, windowed) recovery.
///
/// This is the recommended method for files > 500 MB.
pub fn stream_salvage<P: AsRef<Path>>(
    path: P,
    engine: &SalvageEngine,
    config: &StreamConfig,
    progress_cb: ProgressCb<'_>,
) -> Result<StreamReport, StreamError> {
    let start = std::time::Instant::now();
    let path = path.as_ref();

    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    if file_size == 0 {
        return Ok(StreamReport {
            input_size: 0,
            windows_processed: 0,
            files: Vec::new(),
            files_salvaged: 0,
            bytes_recovered: 0,
            method: "Streaming (empty file)".into(),
            scan_time_secs: 0.0,
        });
    }

    // Memory-map the file
    let mmap =
        unsafe { memmap2::Mmap::map(&file).map_err(|e| StreamError::MmapFailed(e.to_string()))? };

    let data = &mmap[..];

    if let Some(cb) = progress_cb {
        cb(
            &format!(
                "Streaming scan: {} bytes, {} MB windows",
                file_size,
                config.window_size / (1024 * 1024)
            ),
            2,
        );
    }

    // If the file is small enough, just do a regular salvage
    if (file_size as usize) <= config.window_size {
        if let Some(cb) = progress_cb {
            cb("File fits in single window — using standard recovery", 5);
        }
        let report = engine.salvage(data, progress_cb);
        return Ok(StreamReport {
            input_size: file_size,
            windows_processed: 1,
            files: report.files.clone(),
            files_salvaged: report.files_salvaged,
            bytes_recovered: report.total_salvaged_bytes,
            method: format!("Streaming → {}", report.method),
            scan_time_secs: start.elapsed().as_secs_f64(),
        });
    }

    // Try structured extraction first if the header matches a known archive
    let mut structured_files: Vec<SalvagedFile> = Vec::new();
    if config.try_structured && file_size <= 2 * 1024 * 1024 * 1024 {
        // Only try structured for files < 2 GB (needs header parsing)
        let archive_type = detect_archive_header(data);
        if archive_type != "unknown" {
            if let Some(cb) = progress_cb {
                cb(
                    &format!("Trying structured {} extraction...", archive_type),
                    5,
                );
            }
            let report = engine.salvage(data, progress_cb);
            structured_files = report.files;
        }
    }

    // Sliding window carving
    let mut all_files: Vec<SalvagedFile> = Vec::new();
    let mut seen_hashes = HashSet::new();

    // Add structured files first (higher confidence)
    for f in &structured_files {
        if !f.sha256.is_empty() {
            seen_hashes.insert(f.sha256.clone());
        }
    }
    all_files.extend(structured_files);

    let step = config.window_size - config.overlap;
    let total_windows = ((file_size as usize).saturating_sub(1) / step) + 1;
    let mut window_idx = 0usize;
    let mut offset = 0usize;

    while offset < data.len() {
        let window_end = (offset + config.window_size).min(data.len());
        let window = &data[offset..window_end];

        if let Some(cb) = progress_cb {
            let pct = 10 + (window_idx as u32 * 80 / total_windows.max(1) as u32);
            cb(
                &format!(
                    "Window {}/{} @ offset {:#X}",
                    window_idx + 1,
                    total_windows,
                    offset
                ),
                pct,
            );
        }

        // Run raw carving on this window
        let report = engine.salvage(window, None);

        for mut f in report.files {
            // Adjust offset to be relative to the full file
            f.offset += offset;

            // Compute hash if not already done
            if f.sha256.is_empty() {
                let hash = Sha256::digest(&f.data);
                f.sha256 = hash.iter().map(|b| format!("{:02x}", b)).collect();
            }

            // Deduplicate
            if seen_hashes.insert(f.sha256.clone()) {
                all_files.push(f);
            }
        }

        window_idx += 1;

        // Advance by step (not full window, so we overlap)
        if offset + step >= data.len() {
            break;
        }
        offset += step;
    }

    // Re-index all files
    for (i, f) in all_files.iter_mut().enumerate() {
        f.index = i;
    }

    let bytes_recovered: usize = all_files.iter().map(|f| f.size).sum();

    if let Some(cb) = progress_cb {
        cb("Streaming scan complete", 100);
    }

    Ok(StreamReport {
        input_size: file_size,
        windows_processed: window_idx,
        files: all_files.clone(),
        files_salvaged: all_files.len(),
        bytes_recovered,
        method: format!(
            "Streaming ({} windows, {} MB each)",
            window_idx,
            config.window_size / (1024 * 1024)
        ),
        scan_time_secs: (start.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
    })
}

/// Quick archive header detection (just first 6 bytes).
fn detect_archive_header(data: &[u8]) -> &'static str {
    if data.len() < 6 {
        return "unknown";
    }
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return "zip";
    }
    if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return "7z";
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return "gzip";
    }
    if data.starts_with(&[0x42, 0x5A, 0x68]) {
        return "bzip2";
    }
    if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A]) {
        return "xz";
    }
    "unknown"
}

/// Errors from streaming operations.
#[derive(Debug)]
pub enum StreamError {
    Io(std::io::Error),
    MmapFailed(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::MmapFailed(e) => write!(f, "Memory mapping failed: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_config_defaults() {
        let config = StreamConfig::default();
        assert_eq!(config.window_size, 64 * 1024 * 1024);
        assert_eq!(config.overlap, 1024 * 1024);
        assert!(config.try_structured);
    }

    #[test]
    fn test_stream_config_low_memory() {
        let config = StreamConfig::low_memory();
        assert_eq!(config.window_size, 16 * 1024 * 1024);
    }

    #[test]
    fn test_stream_config_high_perf() {
        let config = StreamConfig::high_performance();
        assert_eq!(config.window_size, 256 * 1024 * 1024);
    }

    #[test]
    fn test_detect_archive_header() {
        assert_eq!(
            detect_archive_header(&[0x50, 0x4B, 0x03, 0x04, 0, 0]),
            "zip"
        );
        assert_eq!(detect_archive_header(&[0x1F, 0x8B, 0, 0, 0, 0]), "gzip");
        assert_eq!(detect_archive_header(&[0x00, 0x00, 0, 0, 0, 0]), "unknown");
    }
}
