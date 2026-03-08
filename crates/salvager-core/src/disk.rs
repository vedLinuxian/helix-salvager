//! Disk image support — scan raw .img/.dd/disk image files.
//!
//! Supports:
//! - Raw disk images (.img, .dd, .raw)
//! - Memory-mapped I/O for large images (via memmap2)
//! - Partition table detection (MBR/GPT)
//! - Automatic scanning of each partition for embedded files
//!
//! This module provides a thin layer over the core SalvageEngine that
//! handles disk geometry and partition boundaries.

use crate::salvager::{ProgressCb, SalvageEngine, SalvageReport, SalvagedFile};
use serde::Serialize;
use std::path::Path;

/// Recognized partition types.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
    Unknown,
}

/// A detected partition within a disk image.
#[derive(Debug, Clone, Serialize)]
pub struct Partition {
    /// Partition index (0-based).
    pub index: usize,
    /// Human-readable label or type name.
    pub label: String,
    /// Start offset in the disk image (bytes).
    pub start_offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Detected filesystem type (if recognizable).
    pub filesystem: String,
}

/// Result of scanning a disk image.
#[derive(Debug, Clone, Serialize)]
pub struct DiskImageReport {
    /// Total disk image size in bytes.
    pub image_size: usize,
    /// Detected partition scheme.
    pub partition_scheme: PartitionScheme,
    /// All detected partitions.
    pub partitions: Vec<Partition>,
    /// Per-partition salvage reports.
    pub partition_reports: Vec<SalvageReport>,
    /// Files from whole-disk raw carving (catches files spanning partitions).
    pub raw_carve_report: Option<SalvageReport>,
    /// Total files recovered across all strategies.
    pub total_files_recovered: usize,
    /// Processing time in seconds.
    pub scan_time_secs: f64,
}

/// Errors from disk image operations.
#[derive(Debug)]
pub enum DiskImageError {
    Io(std::io::Error),
    TooSmall,
    MmapFailed(String),
}

impl std::fmt::Display for DiskImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::TooSmall => write!(f, "Image file too small to contain partitions"),
            Self::MmapFailed(e) => write!(f, "Memory mapping failed: {}", e),
        }
    }
}

impl std::error::Error for DiskImageError {}

impl From<std::io::Error> for DiskImageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Maximum size to read fully into memory (256 MB). Larger files use mmap.
const MMAP_THRESHOLD: u64 = 256 * 1024 * 1024;

/// Scan a disk image file for recoverable files.
///
/// Detects partitions, scans each one, and also performs whole-image raw carving.
pub fn scan_disk_image<P: AsRef<Path>>(
    path: P,
    engine: &SalvageEngine,
    progress_cb: ProgressCb<'_>,
) -> Result<DiskImageReport, DiskImageError> {
    let start = std::time::Instant::now();
    let path = path.as_ref();

    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len() as usize;

    if file_size < 512 {
        return Err(DiskImageError::TooSmall);
    }

    // Read or mmap the file
    let data = if metadata.len() > MMAP_THRESHOLD {
        DiskData::Mmap(mmap_file(path)?)
    } else {
        DiskData::Owned(std::fs::read(path)?)
    };

    let bytes = data.as_slice();

    if let Some(cb) = progress_cb {
        cb(&format!("Scanning disk image ({} bytes)...", file_size), 5);
    }

    // Detect partition scheme
    let (scheme, partitions) = detect_partitions(bytes);

    if let Some(cb) = progress_cb {
        cb(
            &format!("Found {} partitions ({:?})", partitions.len(), scheme),
            10,
        );
    }

    // Scan each partition
    let mut partition_reports = Vec::new();
    let total_parts = partitions.len().max(1);

    for (i, part) in partitions.iter().enumerate() {
        if let Some(cb) = progress_cb {
            let pct = 10 + (i as u32 * 60 / total_parts as u32);
            cb(
                &format!("Scanning partition {} ({})...", i, part.label),
                pct,
            );
        }

        let end = (part.start_offset + part.size).min(bytes.len());
        if part.start_offset >= bytes.len() || end <= part.start_offset {
            continue;
        }

        let partition_data = &bytes[part.start_offset..end];
        let report = engine.salvage(partition_data, progress_cb);
        partition_reports.push(report);
    }

    // Also do a whole-image raw carve to catch files that span partition boundaries
    // or exist in unpartitioned space
    if let Some(cb) = progress_cb {
        cb("Raw carving entire disk image...", 75);
    }

    let raw_report = engine.salvage(bytes, progress_cb);
    let raw_files = raw_report.files_salvaged;

    let total_files = partition_reports
        .iter()
        .map(|r| r.files_salvaged)
        .sum::<usize>()
        .max(raw_files);

    if let Some(cb) = progress_cb {
        cb("Disk image scan complete", 100);
    }

    Ok(DiskImageReport {
        image_size: file_size,
        partition_scheme: scheme,
        partitions,
        partition_reports,
        raw_carve_report: Some(raw_report),
        total_files_recovered: total_files,
        scan_time_secs: (start.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
    })
}

/// Collect all unique salvaged files from a disk image report.
pub fn collect_all_files(report: &DiskImageReport) -> Vec<&SalvagedFile> {
    use std::collections::HashSet;
    let mut seen_hashes = HashSet::new();
    let mut files = Vec::new();

    // Partition files first (higher confidence)
    for pr in &report.partition_reports {
        for f in &pr.files {
            if f.sha256.is_empty() || seen_hashes.insert(f.sha256.clone()) {
                files.push(f);
            }
        }
    }

    // Then raw carve files (deduped against partition files)
    if let Some(ref raw) = report.raw_carve_report {
        for f in &raw.files {
            if !f.sha256.is_empty() && seen_hashes.insert(f.sha256.clone()) {
                files.push(f);
            }
        }
    }

    files
}

// ──────────────────────────────────────────────────────────
//  Internal: Partition detection
// ──────────────────────────────────────────────────────────

/// Detect partition table type and extract partition entries.
fn detect_partitions(data: &[u8]) -> (PartitionScheme, Vec<Partition>) {
    // Check for GPT first (takes priority over protective MBR)
    if data.len() >= 1024 && &data[512..520] == b"EFI PART" {
        return parse_gpt(data);
    }

    // Check for MBR (boot signature 0x55AA at offset 510)
    if data.len() >= 512 && data[510] == 0x55 && data[511] == 0xAA {
        let partitions = parse_mbr(data);
        if !partitions.is_empty() {
            return (PartitionScheme::Mbr, partitions);
        }
    }

    (PartitionScheme::Unknown, Vec::new())
}

/// Parse MBR partition table (4 primary entries at offset 446).
fn parse_mbr(data: &[u8]) -> Vec<Partition> {
    let mut partitions = Vec::new();

    for i in 0..4 {
        let entry_offset = 446 + i * 16;
        if entry_offset + 16 > data.len() {
            break;
        }

        let entry = &data[entry_offset..entry_offset + 16];
        let type_byte = entry[4];

        // Skip empty partitions
        if type_byte == 0x00 {
            continue;
        }

        let lba_start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
        let sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;

        let start_offset = lba_start * 512;
        let size = sectors * 512;

        // Sanity check: partition must be within image bounds
        if start_offset == 0 || size == 0 || start_offset >= data.len() {
            continue;
        }

        let label = mbr_type_name(type_byte);
        let filesystem = detect_filesystem(data, start_offset);

        partitions.push(Partition {
            index: partitions.len(),
            label,
            start_offset,
            size,
            filesystem,
        });
    }

    partitions
}

/// Parse GPT partition table.
fn parse_gpt(data: &[u8]) -> (PartitionScheme, Vec<Partition>) {
    let mut partitions = Vec::new();

    // GPT header at LBA 1 (offset 512)
    if data.len() < 1024 {
        return (PartitionScheme::Gpt, partitions);
    }

    // Number of partition entries (at header offset 80, 4 bytes LE)
    let num_entries = if data.len() >= 512 + 84 {
        u32::from_le_bytes([data[592], data[593], data[594], data[595]]) as usize
    } else {
        128 // default GPT entry count
    };

    // Size of each entry (at header offset 84, 4 bytes LE)
    let entry_size = if data.len() >= 512 + 88 {
        u32::from_le_bytes([data[596], data[597], data[598], data[599]]) as usize
    } else {
        128 // default
    };

    // Partition entries start at LBA 2 (offset 1024)
    let entries_start = 1024;

    let max_entries = num_entries.min(128); // safety limit
    for i in 0..max_entries {
        let offset = entries_start + i * entry_size;
        if offset + 128 > data.len() {
            break;
        }

        let entry = &data[offset..offset + 128];

        // Check if entry is empty (type GUID is all zeros)
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }

        // Starting LBA (offset 32 in entry, 8 bytes LE)
        let start_lba = u64::from_le_bytes([
            entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38], entry[39],
        ]) as usize;

        // Ending LBA (offset 40 in entry, 8 bytes LE)
        let end_lba = u64::from_le_bytes([
            entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46], entry[47],
        ]) as usize;

        if start_lba == 0 || end_lba <= start_lba {
            continue;
        }

        let start_offset = start_lba * 512;
        let size = (end_lba - start_lba + 1) * 512;

        // Read partition name (UTF-16LE at offset 56, 72 bytes)
        let name_bytes = &entry[56..128];
        let name: String = name_bytes
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    let ch = u16::from_le_bytes([c[0], c[1]]);
                    if ch == 0 {
                        None
                    } else {
                        char::from_u32(ch as u32)
                    }
                } else {
                    None
                }
            })
            .collect();

        let label = if name.is_empty() {
            format!("GPT Partition {}", i)
        } else {
            name
        };

        let filesystem = if start_offset < data.len() {
            detect_filesystem(data, start_offset)
        } else {
            "unknown".into()
        };

        partitions.push(Partition {
            index: partitions.len(),
            label,
            start_offset,
            size,
            filesystem,
        });
    }

    (PartitionScheme::Gpt, partitions)
}

/// Detect filesystem type at a given offset by checking magic bytes.
fn detect_filesystem(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return "unknown".into();
    }

    let s = &data[offset..];

    // FAT16/FAT32: "FAT" at offset 54 or 82
    if s.len() > 90 {
        if &s[54..57] == b"FAT" {
            return "FAT16".into();
        }
        if &s[82..85] == b"FAT" {
            return "FAT32".into();
        }
    }

    // NTFS: "NTFS" at offset 3
    if s.len() > 8 && &s[3..7] == b"NTFS" {
        return "NTFS".into();
    }

    // ext2/3/4: magic 0xEF53 at offset 1080
    if s.len() > 1082 && s[1080] == 0x53 && s[1081] == 0xEF {
        return "ext2/3/4".into();
    }

    // HFS+: "H+" at offset 1024
    if s.len() > 1026 && &s[1024..1026] == b"H+" {
        return "HFS+".into();
    }

    // exFAT: "EXFAT" at offset 3
    if s.len() > 8 && &s[3..8] == b"EXFAT" {
        return "exFAT".into();
    }

    "unknown".into()
}

/// Map MBR partition type byte to human-readable name.
fn mbr_type_name(type_byte: u8) -> String {
    match type_byte {
        0x01 => "FAT12".into(),
        0x04 | 0x06 | 0x0E => "FAT16".into(),
        0x0B | 0x0C => "FAT32".into(),
        0x07 => "NTFS/exFAT".into(),
        0x0F | 0x05 => "Extended".into(),
        0x82 => "Linux swap".into(),
        0x83 => "Linux".into(),
        0x8E => "Linux LVM".into(),
        0xA5 => "FreeBSD".into(),
        0xAF => "HFS+".into(),
        0xEE => "GPT Protective".into(),
        0xEF => "EFI System".into(),
        0xFD => "Linux RAID".into(),
        _ => format!("Type 0x{:02X}", type_byte),
    }
}

/// Memory-map a file for zero-copy access.
fn mmap_file(path: &Path) -> Result<memmap2::Mmap, DiskImageError> {
    let file = std::fs::File::open(path)?;
    // SAFETY: We only read the mapped region, and the file is kept open.
    unsafe { memmap2::Mmap::map(&file).map_err(|e| DiskImageError::MmapFailed(e.to_string())) }
}

/// Internal wrapper to handle owned vs mmap'd data.
enum DiskData {
    Owned(Vec<u8>),
    Mmap(memmap2::Mmap),
}

impl DiskData {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(v) => v,
            Self::Mmap(m) => m,
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_partitions_empty() {
        let data = vec![0u8; 512];
        let (scheme, parts) = detect_partitions(&data);
        // No valid boot sig → unknown
        assert_eq!(scheme, PartitionScheme::Unknown);
        assert!(parts.is_empty());
    }

    #[test]
    fn test_detect_mbr_signature() {
        let mut data = vec![0u8; 1024];
        // Set MBR boot signature
        data[510] = 0x55;
        data[511] = 0xAA;
        // No valid partition entries → should return Mbr with no partitions
        // (all type bytes are 0x00)
        let (scheme, parts) = detect_partitions(&data);
        assert_eq!(scheme, PartitionScheme::Unknown); // no valid partitions
        assert!(parts.is_empty());
    }

    #[test]
    fn test_detect_mbr_with_partition() {
        let mut data = vec![0u8; 65536]; // 128 sectors
                                         // Set MBR boot signature
        data[510] = 0x55;
        data[511] = 0xAA;
        // Create a FAT32 partition entry at slot 0 (offset 446)
        data[446] = 0x80; // active
        data[450] = 0x0C; // FAT32 LBA
                          // Start LBA = 1 (sector 1 = offset 512)
        data[454] = 1; // LBA start LE
                       // Size = 64 sectors
        data[458] = 64; // sectors LE
        let (scheme, parts) = detect_partitions(&data);
        assert_eq!(scheme, PartitionScheme::Mbr);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].label, "FAT32");
        assert_eq!(parts[0].start_offset, 512);
        assert_eq!(parts[0].size, 64 * 512);
    }

    #[test]
    fn test_detect_gpt_signature() {
        let mut data = vec![0u8; 4096];
        // GPT magic at LBA 1
        data[512..520].copy_from_slice(b"EFI PART");
        let (scheme, parts) = detect_partitions(&data);
        assert_eq!(scheme, PartitionScheme::Gpt);
        // No valid entries → empty
        assert!(parts.is_empty());
    }

    #[test]
    fn test_mbr_type_names() {
        assert_eq!(mbr_type_name(0x07), "NTFS/exFAT");
        assert_eq!(mbr_type_name(0x83), "Linux");
        assert_eq!(mbr_type_name(0xEF), "EFI System");
        assert!(mbr_type_name(0xFF).starts_with("Type"));
    }

    #[test]
    fn test_detect_filesystem_ntfs() {
        let mut data = vec![0u8; 2048];
        data[3..7].copy_from_slice(b"NTFS");
        assert_eq!(detect_filesystem(&data, 0), "NTFS");
    }

    #[test]
    fn test_detect_filesystem_ext() {
        let mut data = vec![0u8; 2048];
        data[1080] = 0x53;
        data[1081] = 0xEF;
        assert_eq!(detect_filesystem(&data, 0), "ext2/3/4");
    }

    #[test]
    fn test_collect_all_files_dedup() {
        let report = DiskImageReport {
            image_size: 1024,
            partition_scheme: PartitionScheme::Unknown,
            partitions: vec![],
            partition_reports: vec![],
            raw_carve_report: None,
            total_files_recovered: 0,
            scan_time_secs: 0.0,
        };
        let files = collect_all_files(&report);
        assert!(files.is_empty());
    }
}
