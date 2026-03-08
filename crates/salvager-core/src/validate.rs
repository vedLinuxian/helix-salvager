//! Deep file validation — structural integrity checks for recovered files.
//!
//! Goes beyond magic-byte detection to validate internal structure of
//! recovered files. This helps distinguish genuinely recovered files from
//! false-positive carving hits and adjusts confidence scores.
//!
//! Supports deep validation for: JPEG, PNG, PDF, ZIP, GIF, BMP, SQLITE,
//! ELF, PE/EXE, FLAC, OGG, MP3, TIFF, WASM.

use crate::salvager::SalvagedFile;

/// Validation result for a single file.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the file passed structural validation.
    pub valid: bool,
    /// Confidence adjustment: positive = increase, negative = decrease.
    pub confidence_delta: f64,
    /// Human-readable validation notes.
    pub notes: Vec<String>,
    /// Specific structural issues found.
    pub issues: Vec<ValidationIssue>,
}

/// A specific structural issue found during validation.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub offset: usize,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
}

impl ValidationResult {
    fn ok() -> Self {
        Self {
            valid: true,
            confidence_delta: 0.05,
            notes: vec!["Structure validated".into()],
            issues: Vec::new(),
        }
    }

    fn partial(notes: Vec<String>, issues: Vec<ValidationIssue>) -> Self {
        Self {
            valid: true,
            confidence_delta: -0.05,
            notes,
            issues,
        }
    }

    fn invalid(reason: &str) -> Self {
        Self {
            valid: false,
            confidence_delta: -0.20,
            notes: vec![reason.into()],
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Error,
                offset: 0,
                description: reason.into(),
            }],
        }
    }

    fn skip() -> Self {
        Self {
            valid: true,
            confidence_delta: 0.0,
            notes: vec!["No deep validation available for this type".into()],
            issues: Vec::new(),
        }
    }
}

/// Run deep structural validation on a salvaged file.
///
/// Returns a validation result with confidence adjustment.
pub fn validate_file(file: &SalvagedFile) -> ValidationResult {
    let data = &file.data;
    if data.is_empty() {
        return ValidationResult::invalid("Empty file");
    }

    match file.extension.as_str() {
        "jpg" | "jpeg" => validate_jpeg(data),
        "png" => validate_png(data),
        "pdf" => validate_pdf(data),
        "gif" => validate_gif(data),
        "bmp" => validate_bmp(data),
        "zip" => validate_zip(data),
        "sqlite" => validate_sqlite(data),
        "elf" => validate_elf(data),
        "exe" => validate_pe(data),
        "flac" => validate_flac(data),
        "ogg" => validate_ogg(data),
        "mp3" => validate_mp3(data),
        "tiff" => validate_tiff(data),
        "wasm" => validate_wasm(data),
        _ => ValidationResult::skip(),
    }
}

/// Validate all files in a batch, adjusting their confidence scores.
pub fn validate_and_adjust(files: &mut [SalvagedFile]) {
    for file in files.iter_mut() {
        let result = validate_file(file);
        file.confidence = (file.confidence + result.confidence_delta).clamp(0.0, 1.0);
    }
}

// ──────────────────────────────────────────────────────────
//  Per-type validators
// ──────────────────────────────────────────────────────────

fn validate_jpeg(data: &[u8]) -> ValidationResult {
    if data.len() < 4 {
        return ValidationResult::invalid("JPEG too small");
    }

    // Must start with FF D8 FF
    if data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return ValidationResult::invalid("Invalid JPEG SOI marker");
    }

    let mut issues = Vec::new();
    let mut notes = Vec::new();

    // Check for APP0 (JFIF) or APP1 (Exif) marker
    let marker = data[3];
    if marker == 0xE0 {
        notes.push("JFIF format detected".into());
    } else if marker == 0xE1 {
        notes.push("Exif format detected".into());
    } else if marker == 0xDB {
        notes.push("Starts with DQT (no JFIF/Exif header)".into());
    }

    // Scan for SOF (Start of Frame) marker
    let mut has_sof = false;
    let mut has_sos = false;
    let mut pos = 2;
    while pos + 1 < data.len() {
        if data[pos] == 0xFF {
            let m = data[pos + 1];
            if (0xC0..=0xCF).contains(&m) && m != 0xC4 && m != 0xC8 && m != 0xCC {
                has_sof = true;
                // Read dimensions if possible
                if pos + 9 < data.len() {
                    let height = u16::from_be_bytes([data[pos + 5], data[pos + 6]]);
                    let width = u16::from_be_bytes([data[pos + 7], data[pos + 8]]);
                    notes.push(format!("Dimensions: {}x{}", width, height));
                }
            }
            if m == 0xDA {
                has_sos = true;
                break; // SOS found, rest is entropy-coded data
            }
            // Skip marker segment
            if pos + 3 < data.len() && m != 0x00 && m != 0xD8 && m != 0xD9 {
                let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 2 + seg_len;
            } else {
                pos += 2;
            }
        } else {
            pos += 1;
        }
    }

    if !has_sof {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: 0,
            description: "No SOF marker found — may be truncated".into(),
        });
    }

    // Check for EOI (FF D9) at end
    let has_eoi = data.len() >= 2
        && data[data.len() - 2] == 0xFF
        && data[data.len() - 1] == 0xD9;

    if !has_eoi {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: data.len(),
            description: "Missing EOI marker — may be truncated".into(),
        });
    }

    if has_sof && has_sos && has_eoi {
        notes.push("Complete JPEG structure verified".into());
        ValidationResult {
            valid: true,
            confidence_delta: 0.10,
            notes,
            issues,
        }
    } else if has_sof {
        ValidationResult::partial(notes, issues)
    } else {
        ValidationResult {
            valid: true,
            confidence_delta: -0.10,
            notes,
            issues,
        }
    }
}

fn validate_png(data: &[u8]) -> ValidationResult {
    if data.len() < 8 {
        return ValidationResult::invalid("PNG too small");
    }

    // Check PNG signature
    if data[..8] != [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return ValidationResult::invalid("Invalid PNG signature");
    }

    let mut notes = Vec::new();
    let mut issues = Vec::new();
    let mut has_ihdr = false;
    let mut has_iend = false;
    let mut chunk_count = 0;
    let mut pos = 8;

    while pos + 8 <= data.len() {
        if pos + 8 > data.len() {
            break;
        }
        let length = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];

        if chunk_type == b"IHDR" && pos + 12 + 8 <= data.len() {
            has_ihdr = true;
            let width = u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
            let height = u32::from_be_bytes([data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]]);
            notes.push(format!("Dimensions: {}x{}", width, height));
        }

        if chunk_type == b"IEND" {
            has_iend = true;
        }

        chunk_count += 1;

        // Move to next chunk: 4 (len) + 4 (type) + length + 4 (CRC)
        let next = pos + 12 + length;
        if next > data.len() || next <= pos {
            break;
        }
        pos = next;
    }

    notes.push(format!("{} chunks parsed", chunk_count));

    if !has_ihdr {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Error,
            offset: 8,
            description: "Missing IHDR chunk".into(),
        });
    }

    if !has_iend {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: data.len(),
            description: "Missing IEND chunk — may be truncated".into(),
        });
    }

    if has_ihdr && has_iend {
        notes.push("Complete PNG structure verified".into());
        ValidationResult {
            valid: true,
            confidence_delta: 0.10,
            notes,
            issues,
        }
    } else if has_ihdr {
        ValidationResult::partial(notes, issues)
    } else {
        ValidationResult::invalid("PNG missing critical IHDR chunk")
    }
}

fn validate_pdf(data: &[u8]) -> ValidationResult {
    if data.len() < 5 {
        return ValidationResult::invalid("PDF too small");
    }

    if &data[..5] != b"%PDF-" {
        return ValidationResult::invalid("Invalid PDF header");
    }

    let mut notes = Vec::new();

    // Extract version
    if data.len() >= 8 {
        let version = String::from_utf8_lossy(&data[5..8.min(data.len())]);
        notes.push(format!("PDF version: {}", version.trim()));
    }

    // Check for %%EOF
    let has_eof = data.windows(5).any(|w| w == b"%%EOF");

    // Check for xref table
    let has_xref = data.windows(4).any(|w| w == b"xref");

    // Check for startxref
    let has_startxref = data.windows(9).any(|w| w == b"startxref");

    if has_eof {
        notes.push("EOF marker found".into());
    }
    if has_xref {
        notes.push("Cross-reference table present".into());
    }

    let mut issues = Vec::new();
    if !has_eof {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: data.len(),
            description: "Missing %%EOF — may be truncated".into(),
        });
    }

    if has_eof && has_xref && has_startxref {
        notes.push("Complete PDF structure verified".into());
        ValidationResult {
            valid: true,
            confidence_delta: 0.10,
            notes,
            issues,
        }
    } else if has_eof {
        ValidationResult::partial(notes, issues)
    } else {
        ValidationResult {
            valid: true,
            confidence_delta: -0.05,
            notes,
            issues,
        }
    }
}

fn validate_gif(data: &[u8]) -> ValidationResult {
    if data.len() < 13 {
        return ValidationResult::invalid("GIF too small");
    }

    if &data[..4] != b"GIF8" || (data[4] != b'7' && data[4] != b'9') {
        return ValidationResult::invalid("Invalid GIF signature");
    }

    let version = if data[4] == b'9' { "GIF89a" } else { "GIF87a" };
    let width = u16::from_le_bytes([data[6], data[7]]);
    let height = u16::from_le_bytes([data[8], data[9]]);

    let has_trailer = data.last() == Some(&0x3B);

    let mut notes = vec![
        format!("{} format", version),
        format!("Dimensions: {}x{}", width, height),
    ];

    let mut issues = Vec::new();
    if has_trailer {
        notes.push("Trailer byte found — complete".into());
    } else {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: data.len(),
            description: "Missing GIF trailer (0x3B)".into(),
        });
    }

    ValidationResult {
        valid: true,
        confidence_delta: if has_trailer { 0.08 } else { -0.03 },
        notes,
        issues,
    }
}

fn validate_bmp(data: &[u8]) -> ValidationResult {
    if data.len() < 54 {
        return ValidationResult::invalid("BMP too small for header");
    }

    if data[0] != 0x42 || data[1] != 0x4D {
        return ValidationResult::invalid("Invalid BMP signature");
    }

    let file_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
    let data_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
    let height = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
    let bpp = u16::from_le_bytes([data[28], data[29]]);

    let notes = vec![
        format!("Dimensions: {}x{}", width, height.abs()),
        format!("Bits per pixel: {}", bpp),
        format!("Declared size: {} bytes", file_size),
        format!("Data starts at offset: {}", data_offset),
    ];

    let size_match = file_size <= data.len() + 1024; // allow small discrepancy
    let issues = if !size_match {
        vec![ValidationIssue {
            severity: IssueSeverity::Warning,
            offset: 2,
            description: format!("Declared size {} doesn't match actual {}", file_size, data.len()),
        }]
    } else {
        Vec::new()
    };

    ValidationResult {
        valid: true,
        confidence_delta: if size_match { 0.08 } else { -0.05 },
        notes,
        issues,
    }
}

fn validate_zip(data: &[u8]) -> ValidationResult {
    if data.len() < 30 {
        return ValidationResult::invalid("ZIP too small");
    }

    if data[..4] != [0x50, 0x4B, 0x03, 0x04] {
        return ValidationResult::invalid("Invalid ZIP signature");
    }

    // Check for End of Central Directory
    let has_eocd = data.windows(4).rposition(|w| w == [0x50, 0x4B, 0x05, 0x06]);

    let mut notes = vec!["ZIP local file header found".into()];

    if has_eocd.is_some() {
        notes.push("End of Central Directory found".into());
        ValidationResult {
            valid: true,
            confidence_delta: 0.10,
            notes,
            issues: Vec::new(),
        }
    } else {
        ValidationResult {
            valid: true,
            confidence_delta: -0.05,
            notes,
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Warning,
                offset: data.len(),
                description: "Missing EOCD — archive may be truncated".into(),
            }],
        }
    }
}

fn validate_sqlite(data: &[u8]) -> ValidationResult {
    if data.len() < 100 {
        return ValidationResult::invalid("SQLite too small for header");
    }

    if &data[..16] != b"SQLite format 3\x00" {
        return ValidationResult::invalid("Invalid SQLite header");
    }

    let page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
    let page_size = if page_size == 1 { 65536 } else { page_size };

    let notes = vec![
        format!("Page size: {} bytes", page_size),
        format!("Database size: {} pages", u32::from_be_bytes([data[28], data[29], data[30], data[31]])),
    ];

    ValidationResult {
        valid: true,
        confidence_delta: 0.10,
        notes,
        issues: Vec::new(),
    }
}

fn validate_elf(data: &[u8]) -> ValidationResult {
    if data.len() < 52 {
        return ValidationResult::invalid("ELF too small for header");
    }

    if data[..4] != [0x7F, 0x45, 0x4C, 0x46] {
        return ValidationResult::invalid("Invalid ELF magic");
    }

    let class = match data[4] {
        1 => "32-bit",
        2 => "64-bit",
        _ => "unknown class",
    };

    let endian = match data[5] {
        1 => "little-endian",
        2 => "big-endian",
        _ => "unknown endian",
    };

    let elf_type = match u16::from_le_bytes([data[16], data[17]]) {
        1 => "Relocatable",
        2 => "Executable",
        3 => "Shared object",
        4 => "Core dump",
        _ => "Unknown",
    };

    ValidationResult {
        valid: true,
        confidence_delta: 0.08,
        notes: vec![
            format!("ELF {} {}", class, endian),
            format!("Type: {}", elf_type),
        ],
        issues: Vec::new(),
    }
}

fn validate_pe(data: &[u8]) -> ValidationResult {
    if data.len() < 64 {
        return ValidationResult::invalid("PE too small for DOS header");
    }

    if data[0] != 0x4D || data[1] != 0x5A {
        return ValidationResult::invalid("Invalid MZ signature");
    }

    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    if pe_offset + 24 > data.len() {
        return ValidationResult {
            valid: true,
            confidence_delta: -0.05,
            notes: vec!["PE header offset points beyond file".into()],
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Warning,
                offset: 60,
                description: "PE header not reachable".into(),
            }],
        };
    }

    if &data[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
        return ValidationResult {
            valid: true,
            confidence_delta: -0.10,
            notes: vec!["PE magic not found at declared offset".into()],
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Error,
                offset: pe_offset,
                description: "Expected 'PE\\0\\0' not found".into(),
            }],
        };
    }

    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
    let machine_name = match machine {
        0x14c => "x86",
        0x8664 => "x86-64",
        0xAA64 => "ARM64",
        0x1c0 => "ARM",
        _ => "Unknown",
    };

    ValidationResult {
        valid: true,
        confidence_delta: 0.10,
        notes: vec![
            "Valid PE signature".into(),
            format!("Architecture: {}", machine_name),
        ],
        issues: Vec::new(),
    }
}

fn validate_flac(data: &[u8]) -> ValidationResult {
    if data.len() < 42 {
        return ValidationResult::invalid("FLAC too small");
    }

    if &data[..4] != b"fLaC" {
        return ValidationResult::invalid("Invalid FLAC magic");
    }

    // First metadata block should be STREAMINFO (type 0)
    let block_type = data[4] & 0x7F;
    if block_type != 0 {
        return ValidationResult {
            valid: true,
            confidence_delta: -0.05,
            notes: vec!["First metadata block is not STREAMINFO".into()],
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Warning,
                offset: 4,
                description: "Expected STREAMINFO as first block".into(),
            }],
        };
    }

    let block_size = u32::from_be_bytes([0, data[5], data[6], data[7]]) as usize;
    if block_size >= 34 && data.len() >= 8 + block_size {
        let sample_rate = ((data[18] as u32) << 12) | ((data[19] as u32) << 4) | ((data[20] as u32) >> 4);
        let channels = ((data[20] >> 1) & 0x07) + 1;
        let bps = ((data[20] & 1) as u32) << 4 | (data[21] >> 4) as u32;

        ValidationResult {
            valid: true,
            confidence_delta: 0.08,
            notes: vec![
                format!("Sample rate: {} Hz", sample_rate),
                format!("Channels: {}", channels),
                format!("Bits per sample: {}", bps + 1),
            ],
            issues: Vec::new(),
        }
    } else {
        ValidationResult::ok()
    }
}

fn validate_ogg(data: &[u8]) -> ValidationResult {
    if data.len() < 27 {
        return ValidationResult::invalid("OGG too small");
    }

    if &data[..4] != b"OggS" {
        return ValidationResult::invalid("Invalid OGG magic");
    }

    let version = data[4];
    if version != 0 {
        return ValidationResult {
            valid: true,
            confidence_delta: -0.10,
            notes: vec![format!("Unexpected OGG version: {}", version)],
            issues: vec![ValidationIssue {
                severity: IssueSeverity::Error,
                offset: 4,
                description: "OGG version should be 0".into(),
            }],
        };
    }

    let granule_pos = u64::from_le_bytes([
        data[6], data[7], data[8], data[9],
        data[10], data[11], data[12], data[13],
    ]);

    let serial = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);

    ValidationResult {
        valid: true,
        confidence_delta: 0.08,
        notes: vec![
            "Valid OGG container".into(),
            format!("Serial: {}", serial),
            format!("Granule position: {}", granule_pos),
        ],
        issues: Vec::new(),
    }
}

fn validate_mp3(data: &[u8]) -> ValidationResult {
    if data.len() < 4 {
        return ValidationResult::invalid("MP3 too small");
    }

    let mut notes = Vec::new();

    // Check for ID3v2 tag
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let version_major = data[3];
        let version_minor = data[4];
        notes.push(format!("ID3v2.{}.{} tag present", version_major, version_minor));

        // Calculate tag size (syncsafe integer)
        let tag_size = ((data[6] as usize) << 21)
            | ((data[7] as usize) << 14)
            | ((data[8] as usize) << 7)
            | (data[9] as usize);
        notes.push(format!("ID3 tag size: {} bytes", tag_size));
    }

    // Check for frame sync
    let has_sync = data.windows(2).any(|w| w[0] == 0xFF && (w[1] & 0xE0) == 0xE0);

    if has_sync {
        notes.push("Frame sync found".into());
    }

    ValidationResult {
        valid: true,
        confidence_delta: if has_sync { 0.05 } else { -0.05 },
        notes,
        issues: Vec::new(),
    }
}

fn validate_tiff(data: &[u8]) -> ValidationResult {
    if data.len() < 8 {
        return ValidationResult::invalid("TIFF too small");
    }

    let big_endian = &data[..2] == b"MM";
    let little_endian = &data[..2] == b"II";

    if !big_endian && !little_endian {
        return ValidationResult::invalid("Invalid TIFF byte order");
    }

    let magic = if big_endian {
        u16::from_be_bytes([data[2], data[3]])
    } else {
        u16::from_le_bytes([data[2], data[3]])
    };

    if magic != 42 {
        return ValidationResult::invalid("Invalid TIFF magic number (expected 42)");
    }

    let ifd_offset = if big_endian {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize
    } else {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize
    };

    let endian_str = if big_endian { "big-endian (Motorola)" } else { "little-endian (Intel)" };

    ValidationResult {
        valid: true,
        confidence_delta: 0.08,
        notes: vec![
            format!("TIFF {}", endian_str),
            format!("First IFD at offset: {}", ifd_offset),
        ],
        issues: Vec::new(),
    }
}

fn validate_wasm(data: &[u8]) -> ValidationResult {
    if data.len() < 8 {
        return ValidationResult::invalid("WASM too small");
    }

    if data[..4] != [0x00, 0x61, 0x73, 0x6D] {
        return ValidationResult::invalid("Invalid WASM magic");
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    ValidationResult {
        valid: true,
        confidence_delta: 0.08,
        notes: vec![format!("WASM version: {}", version)],
        issues: Vec::new(),
    }
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(ext: &str, data: Vec<u8>) -> SalvagedFile {
        SalvagedFile {
            index: 0,
            name: format!("test.{}", ext),
            file_type: ext.to_uppercase(),
            extension: ext.into(),
            offset: 0,
            size: data.len(),
            sha256: String::new(),
            confidence: 0.5,
            data,
        }
    }

    #[test]
    fn test_validate_jpeg_valid() {
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        data.extend(vec![0x00; 14]); // JFIF segment
        data.extend(vec![0xFF, 0xC0, 0x00, 0x11]); // SOF0
        data.extend(vec![0x08, 0x01, 0x00, 0x01, 0x00, 0x03]); // 256x256
        data.extend(vec![0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
        data.extend(vec![0xFF, 0xDA]); // SOS
        data.extend(vec![0x00; 50]); // compressed data
        data.extend(vec![0xFF, 0xD9]); // EOI
        let result = validate_jpeg(&data);
        assert!(result.valid);
        assert!(result.confidence_delta > 0.0);
    }

    #[test]
    fn test_validate_png_valid() {
        let mut data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR chunk: length=13, type=IHDR, content, CRC
        data.extend(vec![0x00, 0x00, 0x00, 0x0D]); // length 13
        data.extend(b"IHDR");
        data.extend(vec![0x00, 0x00, 0x01, 0x00]); // width 256
        data.extend(vec![0x00, 0x00, 0x01, 0x00]); // height 256
        data.extend(vec![0x08, 0x02, 0x00, 0x00, 0x00]); // bit depth, color type, etc.
        data.extend(vec![0x00, 0x00, 0x00, 0x00]); // CRC (fake)
        // IEND chunk
        data.extend(vec![0x00, 0x00, 0x00, 0x00]); // length 0
        data.extend(b"IEND");
        data.extend(vec![0x00, 0x00, 0x00, 0x00]); // CRC (fake)
        let result = validate_png(&data);
        assert!(result.valid);
        assert!(result.confidence_delta > 0.0);
    }

    #[test]
    fn test_validate_pdf_valid() {
        let data = b"%PDF-1.4 test content xref startxref %%EOF".to_vec();
        let result = validate_pdf(&data);
        assert!(result.valid);
        assert!(result.confidence_delta > 0.0);
    }

    #[test]
    fn test_validate_gif_valid() {
        let mut data = b"GIF89a".to_vec();
        data.extend(vec![0x00, 0x01, 0x00, 0x01]); // 256x256
        data.extend(vec![0x80, 0x00, 0x00]); // flags
        data.extend(vec![0x00; 10]); // padding
        data.push(0x3B); // trailer
        let result = validate_gif(&data);
        assert!(result.valid);
        assert!(result.confidence_delta > 0.0);
    }

    #[test]
    fn test_validate_invalid_data() {
        let result = validate_jpeg(&[0x00, 0x00, 0x00]);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_and_adjust() {
        let mut files = vec![
            make_file("pdf", b"%PDF-1.4 test content xref startxref %%EOF".to_vec()),
        ];
        let original_confidence = files[0].confidence;
        validate_and_adjust(&mut files);
        assert!(files[0].confidence > original_confidence);
    }

    #[test]
    fn test_validate_unknown_extension() {
        let result = validate_file(&make_file("xyz", vec![1, 2, 3]));
        assert!(result.valid);
        assert_eq!(result.confidence_delta, 0.0);
    }

    #[test]
    fn test_validate_elf() {
        let mut data = vec![0x7F, 0x45, 0x4C, 0x46]; // ELF magic
        data.push(2); // 64-bit
        data.push(1); // little-endian
        data.extend(vec![0x00; 46]); // padding to 52 bytes
        data[16] = 2; // ET_EXEC
        let result = validate_elf(&data);
        assert!(result.valid);
        assert!(result.confidence_delta > 0.0);
    }

    #[test]
    fn test_validate_wasm() {
        let data = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let result = validate_wasm(&data);
        assert!(result.valid);
        assert!(result.notes[0].contains("version: 1"));
    }
}
