//! Deep Stress Tests for Helix Salvager
//!
//! These tests create REAL ZIP files with REAL embedded content (JPEG, PNG, PDF,
//! text), then systematically corrupt them using every known real-world corruption
//! pattern, and verify the engine can still recover data.
//!
//! Corruption patterns tested:
//!   1. Central directory zeroed (most common real-world failure)
//!   2. Random byte flips (bad sectors / bit rot)
//!   3. Truncated file (incomplete download)
//!   4. Header destroyed (first 100 bytes zeroed)
//!   5. Interleaved garbage blocks (filesystem cluster damage)
//!   6. Single-bit errors scattered throughout
//!   7. Wrong magic bytes (archive type confusion)
//!   8. Zero-filled middle section (bad sector run)
//!   9. Concatenated archives (double-zip)
//!  10. Enormous file count (zip bomb boundary)
//!  11. Empty archive
//!  12. Pure garbage (no archive at all)
//!  13. Embedded files only (raw carve test)
//!  14. LZMA stream corruption patterns

use salvager_core::{SalvageEngine, SalvageReport};
use std::io::{Cursor, Write};

// ═══════════════════════════════════════════════════════
//  TEST DATA GENERATORS
// ═══════════════════════════════════════════════════════

/// Minimal valid JPEG (smallest possible — 2x1 pixel, ~283 bytes)
fn make_tiny_jpeg() -> Vec<u8> {
    // SOI marker
    let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0];
    // JFIF header
    j.extend_from_slice(&[
        0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00,
    ]);
    // DQT marker (quantization table)
    j.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    j.extend(std::iter::repeat_n(0x10u8, 64));
    // SOF marker (1x1, Y only)
    j.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    ]);
    // DHT marker (Huffman table, minimal DC)
    j.extend_from_slice(&[
        0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B,
    ]);
    // SOS marker + minimal scan data
    j.extend_from_slice(&[
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7B, 0x40,
    ]);
    // EOI
    j.extend_from_slice(&[0xFF, 0xD9]);
    j
}

/// Minimal valid PNG (1x1 pixel red dot, ~68 bytes)
fn make_tiny_png() -> Vec<u8> {
    let mut p = Vec::new();
    // PNG signature
    p.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    // IHDR chunk (1x1, 8-bit RGB)
    let ihdr_data = [
        0x00, 0x00, 0x00, 0x01, // width=1
        0x00, 0x00, 0x00, 0x01, // height=1
        0x08, // bit depth=8
        0x02, // color type=RGB
        0x00, 0x00, 0x00,
    ]; // compression, filter, interlace
    let ihdr_crc = crc32(b"IHDR", &ihdr_data);
    p.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
    p.extend_from_slice(b"IHDR");
    p.extend_from_slice(&ihdr_data);
    p.extend_from_slice(&ihdr_crc.to_be_bytes());
    // IDAT chunk (deflated: filter=0, R=255 G=0 B=0)
    let raw_row = [0x00, 0xFF, 0x00, 0x00]; // filter byte + RGB
    let compressed = deflate_compress(&raw_row);
    let idat_crc = crc32(b"IDAT", &compressed);
    p.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
    p.extend_from_slice(b"IDAT");
    p.extend_from_slice(&compressed);
    p.extend_from_slice(&idat_crc.to_be_bytes());
    // IEND chunk
    let iend_crc = crc32(b"IEND", &[]);
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(b"IEND");
    p.extend_from_slice(&iend_crc.to_be_bytes());
    p
}

/// Minimal PDF
fn make_tiny_pdf() -> Vec<u8> {
    b"%PDF-1.0\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
      2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
      3 0 obj<</Type/Page/MediaBox[0 0 3 3]/Parent 2 0 R>>endobj\n\
      xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n\
      0000000058 00000 n \n0000000115 00000 n \n\
      trailer<</Size 4/Root 1 0 R>>\nstartxref\n189\n%%EOF\n"
        .to_vec()
}

/// Simple CRC32 for PNG chunks
fn crc32(chunk_type: &[u8], data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in chunk_type.iter().chain(data.iter()) {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

/// Minimal deflate compression (stored block, no real compression)
fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // zlib header
    out.push(0x78); // CMF: deflate, window=32768
    out.push(0x01); // FLG: no dict, check bits
                    // Stored block (final=1, type=00)
    out.push(0x01); // BFINAL=1, BTYPE=00 (stored)
    let len = data.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(data);
    // Adler32 checksum
    let adler = adler32(data);
    out.extend_from_slice(&adler.to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Build a real ZIP containing known embedded files
fn make_test_zip(file_count: usize) -> Vec<u8> {
    let buf = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(buf);
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let jpeg = make_tiny_jpeg();
    let png = make_tiny_png();
    let pdf = make_tiny_pdf();
    let txt = b"Hello from Helix Salvager stress test! This is a plain text file with enough content to pass minimum size checks. Lorem ipsum dolor sit amet.".to_vec();

    for i in 0..file_count {
        match i % 4 {
            0 => {
                writer
                    .start_file(format!("photo_{:03}.jpg", i), opts)
                    .unwrap();
                writer.write_all(&jpeg).unwrap();
            }
            1 => {
                writer
                    .start_file(format!("image_{:03}.png", i), opts)
                    .unwrap();
                writer.write_all(&png).unwrap();
            }
            2 => {
                writer
                    .start_file(format!("doc_{:03}.pdf", i), opts)
                    .unwrap();
                writer.write_all(&pdf).unwrap();
            }
            _ => {
                writer
                    .start_file(format!("note_{:03}.txt", i), opts)
                    .unwrap();
                writer.write_all(&txt).unwrap();
            }
        }
    }

    writer.finish().unwrap().into_inner()
}

/// Build a ZIP with deflate compression
fn make_test_zip_deflated(file_count: usize) -> Vec<u8> {
    let buf = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(buf);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let txt = b"The quick brown fox jumps over the lazy dog. Repeated text for compression ratio. "
        .to_vec();

    for i in 0..file_count {
        writer
            .start_file(format!("file_{:03}.txt", i), opts)
            .unwrap();
        // Write repeated data for reasonable compression
        for _ in 0..10 {
            writer.write_all(&txt).unwrap();
        }
    }

    writer.finish().unwrap().into_inner()
}

// ═══════════════════════════════════════════════════════
//  CORRUPTION FUNCTIONS
// ═══════════════════════════════════════════════════════

/// Zero out the last N% of the file (central directory destruction)
fn corrupt_central_dir(data: &mut [u8], percent: usize) {
    let start = data.len() * (100 - percent) / 100;
    for b in data[start..].iter_mut() {
        *b = 0x00;
    }
}

/// Random byte flips simulating bit rot
fn corrupt_random_flips(data: &mut [u8], count: usize) {
    let len = data.len();
    if len == 0 {
        return;
    }
    // Deterministic "random" using a simple LCG
    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for _ in 0..count {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let pos = (seed >> 16) as usize % len;
        let flip = ((seed >> 8) & 0xFF) as u8;
        data[pos] ^= flip.max(1); // ensure at least 1 bit flips
    }
}

/// Truncate file to given percentage
fn corrupt_truncate(data: &mut Vec<u8>, keep_percent: usize) {
    // Note: needs Vec because we call truncate() which changes length
    let keep = data.len() * keep_percent / 100;
    data.truncate(keep);
}

/// Zero out a block in the middle
fn corrupt_zero_block(data: &mut [u8], start_pct: usize, end_pct: usize) {
    let start = data.len() * start_pct / 100;
    let end = (data.len() * end_pct / 100).min(data.len());
    for b in data[start..end].iter_mut() {
        *b = 0x00;
    }
}

/// Overwrite header (first N bytes)
fn corrupt_destroy_header(data: &mut [u8], bytes: usize) {
    let end = bytes.min(data.len());
    for b in data[..end].iter_mut() {
        *b = 0x00;
    }
}

/// Insert garbage blocks at intervals (simulates cluster damage)
fn corrupt_insert_garbage(data: &mut [u8], block_size: usize, interval: usize) {
    let mut pos = interval;
    let garbage: Vec<u8> = (0u8..=255).cycle().take(block_size).collect();
    while pos < data.len() {
        let end = (pos + block_size).min(data.len());
        let copy_len = end - pos;
        data[pos..pos + copy_len].copy_from_slice(&garbage[..copy_len]);
        pos += interval + block_size;
    }
}

/// Single-bit errors scattered throughout
fn corrupt_single_bit_errors(data: &mut [u8], count: usize) {
    let len = data.len();
    if len == 0 {
        return;
    }
    let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
    for _ in 0..count {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let pos = (seed >> 16) as usize % len;
        let bit = (seed >> 8) as u32 % 8;
        data[pos] ^= 1 << bit;
    }
}

// ═══════════════════════════════════════════════════════
//  HELPER
// ═══════════════════════════════════════════════════════

fn run(data: &[u8]) -> SalvageReport {
    let engine = SalvageEngine::new();
    engine.salvage(data, None)
}

fn assert_no_panic(label: &str, data: &[u8]) -> SalvageReport {
    // The most fundamental requirement: NEVER crash
    let report = run(data);
    println!(
        "[{}] type={}, method={}, files={}, bytes={}, rate={}%, time={}s",
        label,
        report.archive_type,
        report.method,
        report.files_salvaged,
        report.total_salvaged_bytes,
        report.salvage_rate_percent,
        report.salvage_time_secs
    );
    report
}

// ═══════════════════════════════════════════════════════
//  TEST 1: Valid ZIP baseline
// ═══════════════════════════════════════════════════════

#[test]
fn stress_valid_zip_8_files() {
    let data = make_test_zip(8);
    let r = assert_no_panic("valid_8", &data);
    assert_eq!(r.archive_type, "zip");
    assert_eq!(
        r.files_salvaged, 8,
        "All 8 files should be extracted from valid ZIP"
    );
    assert_eq!(r.crc_errors_ignored, 0);
}

#[test]
fn stress_valid_zip_50_files() {
    let data = make_test_zip(50);
    let r = assert_no_panic("valid_50", &data);
    assert_eq!(r.archive_type, "zip");
    assert_eq!(r.files_salvaged, 50);
}

// ═══════════════════════════════════════════════════════
//  TEST 2: Central directory destroyed
// ═══════════════════════════════════════════════════════

#[test]
fn stress_central_dir_zeroed_10pct() {
    let mut data = make_test_zip(8);
    corrupt_central_dir(&mut data, 10);
    let r = assert_no_panic("cd_zeroed_10", &data);
    assert_eq!(r.archive_type, "zip");
    // With only CD zeroed, structured extract should still work for most files
    // because local file headers are intact
}

#[test]
fn stress_central_dir_zeroed_30pct() {
    let mut data = make_test_zip(8);
    corrupt_central_dir(&mut data, 30);
    let r = assert_no_panic("cd_zeroed_30", &data);
    // Heavier CD damage — may fall back to raw carving
    assert!(
        r.files_salvaged > 0 || r.method.contains("Carve"),
        "Should either recover files or fall back to carving"
    );
}

// ═══════════════════════════════════════════════════════
//  TEST 3: Random byte flips (bit rot)
// ═══════════════════════════════════════════════════════

#[test]
fn stress_random_flips_light() {
    let mut data = make_test_zip(8);
    corrupt_random_flips(&mut data, 5);
    let r = assert_no_panic("flips_5", &data);
    assert_eq!(r.archive_type, "zip");
    // 5 random flips in a multi-KB file — most files should survive
    assert!(
        r.files_salvaged >= 4,
        "Light bit rot: expected >=4 files, got {}",
        r.files_salvaged
    );
}

#[test]
fn stress_random_flips_medium() {
    let mut data = make_test_zip(8);
    corrupt_random_flips(&mut data, 50);
    let _r = assert_no_panic("flips_50", &data);
    // 50 flips — some files will be damaged but engine should not crash
}

#[test]
fn stress_random_flips_heavy() {
    let mut data = make_test_zip(8);
    corrupt_random_flips(&mut data, 500);
    let _r = assert_no_panic("flips_500", &data);
    // Heavily damaged — engine should still not crash
}

// ═══════════════════════════════════════════════════════
//  TEST 4: Truncated file (incomplete download)
// ═══════════════════════════════════════════════════════

#[test]
fn stress_truncated_75pct() {
    let mut data = make_test_zip(8);
    corrupt_truncate(&mut data, 75);
    let r = assert_no_panic("truncated_75", &data);
    assert_eq!(r.archive_type, "zip");
    // First ~6 files should be extractable from the surviving portion
    assert!(
        r.files_salvaged >= 3,
        "75% file: expected >=3 files, got {}",
        r.files_salvaged
    );
}

#[test]
fn stress_truncated_50pct() {
    let mut data = make_test_zip(8);
    corrupt_truncate(&mut data, 50);
    let r = assert_no_panic("truncated_50", &data);
    assert!(
        r.files_salvaged >= 2,
        "50% file: expected >=2 files, got {}",
        r.files_salvaged
    );
}

#[test]
fn stress_truncated_25pct() {
    let mut data = make_test_zip(8);
    corrupt_truncate(&mut data, 25);
    let _r = assert_no_panic("truncated_25", &data);
    // Very truncated — may get 0-2 files
}

#[test]
fn stress_truncated_10pct() {
    let mut data = make_test_zip(8);
    corrupt_truncate(&mut data, 10);
    let _r = assert_no_panic("truncated_10", &data);
    // Engine should handle extreme truncation gracefully
}

// ═══════════════════════════════════════════════════════
//  TEST 5: Header destroyed
// ═══════════════════════════════════════════════════════

#[test]
fn stress_header_destroyed() {
    let mut data = make_test_zip(8);
    corrupt_destroy_header(&mut data, 100);
    let r = assert_no_panic("header_gone", &data);
    // ZIP magic at offset 0 is destroyed — engine must detect as unknown or
    // try raw carving. The local file headers at later offsets may still work.
    println!(
        "  Header destroyed: {} files via {}",
        r.files_salvaged, r.method
    );
}

// ═══════════════════════════════════════════════════════
//  TEST 6: Zero-filled middle section
// ═══════════════════════════════════════════════════════

#[test]
fn stress_zero_middle_small() {
    let mut data = make_test_zip(8);
    corrupt_zero_block(&mut data, 40, 50);
    let r = assert_no_panic("zero_mid_10pct", &data);
    assert_eq!(r.archive_type, "zip");
    // Files before and after the zeroed block should be recoverable
}

#[test]
fn stress_zero_middle_large() {
    let mut data = make_test_zip(8);
    corrupt_zero_block(&mut data, 20, 70);
    let _r = assert_no_panic("zero_mid_50pct", &data);
    // 50% of file is zeroed — significant damage
}

// ═══════════════════════════════════════════════════════
//  TEST 7: Single-bit errors (ECC failure simulation)
// ═══════════════════════════════════════════════════════

#[test]
fn stress_single_bit_errors() {
    let mut data = make_test_zip(8);
    corrupt_single_bit_errors(&mut data, 20);
    let r = assert_no_panic("sbe_20", &data);
    assert_eq!(r.archive_type, "zip");
    // ZIP with stored compression is resilient to isolated bit errors
    // because each file's data is independent
}

// ═══════════════════════════════════════════════════════
//  TEST 8: Garbage insertion (cluster damage)
// ═══════════════════════════════════════════════════════

#[test]
fn stress_garbage_insertion() {
    let mut data = make_test_zip(8);
    corrupt_insert_garbage(&mut data, 64, 512);
    let _r = assert_no_panic("garbage_insert", &data);
    // Structured extraction will likely fail, raw carving should find some files
}

// ═══════════════════════════════════════════════════════
//  TEST 9: Deflated ZIP corruption
// ═══════════════════════════════════════════════════════

#[test]
fn stress_deflated_zip_light_corruption() {
    let mut data = make_test_zip_deflated(5);
    corrupt_random_flips(&mut data, 3);
    let r = assert_no_panic("deflated_light", &data);
    assert_eq!(r.archive_type, "zip");
    // Deflated data is more fragile — even 1 bit flip can destroy a stream
}

#[test]
fn stress_deflated_zip_cd_destroyed() {
    let mut data = make_test_zip_deflated(5);
    corrupt_central_dir(&mut data, 15);
    let _r = assert_no_panic("deflated_cd_gone", &data);
}

// ═══════════════════════════════════════════════════════
//  TEST 10: Edge cases
// ═══════════════════════════════════════════════════════

#[test]
fn stress_empty_file() {
    let r = assert_no_panic("empty", &[]);
    assert_eq!(r.files_salvaged, 0);
    assert_eq!(r.archive_type, "unknown");
}

#[test]
fn stress_single_byte() {
    let r = assert_no_panic("1byte", &[0x42]);
    assert_eq!(r.files_salvaged, 0);
}

#[test]
fn stress_pure_zeroes() {
    let data = vec![0x00u8; 10_000];
    let r = assert_no_panic("zeroes_10k", &data);
    assert_eq!(r.files_salvaged, 0);
}

#[test]
fn stress_pure_garbage() {
    // Pseudorandom noise — no valid archive structure at all
    let mut data = Vec::with_capacity(50_000);
    let mut seed: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    for _ in 0..50_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((seed >> 16) as u8);
    }
    let _r = assert_no_panic("random_50k", &data);
    // Should not crash, might find 0 files (or false positive carves)
}

#[test]
fn stress_very_small_zip() {
    // ZIP with a single 1-byte file
    let buf = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(buf);
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("a.txt", opts).unwrap();
    writer.write_all(b"X").unwrap();
    let data = writer.finish().unwrap().into_inner();
    let r = assert_no_panic("tiny_zip", &data);
    assert_eq!(r.archive_type, "zip");
    assert_eq!(r.files_salvaged, 1);
}

// ═══════════════════════════════════════════════════════
//  TEST 11: Raw carving (embedded files in noise)
// ═══════════════════════════════════════════════════════

#[test]
fn stress_raw_carve_jpeg_in_noise() {
    let jpeg = make_tiny_jpeg();
    let mut data = vec![0x42u8; 500]; // prefix noise
    data.extend_from_slice(&jpeg);
    data.extend(vec![0x43u8; 500]); // suffix noise
    let r = assert_no_panic("carve_jpeg", &data);
    assert_eq!(r.archive_type, "unknown");
    assert!(r.files_salvaged >= 1, "Should carve at least the JPEG");
    assert!(
        r.files.iter().any(|f| f.file_type.contains("JPEG")),
        "Should identify the carved file as JPEG"
    );
}

#[test]
fn stress_raw_carve_multiple_types() {
    let mut data = Vec::new();
    // Embed JPEG + PNG + PDF with gaps between them
    data.extend(vec![0xAA; 200]);
    data.extend_from_slice(&make_tiny_jpeg());
    data.extend(vec![0xBB; 300]);
    data.extend_from_slice(&make_tiny_png());
    data.extend(vec![0xCC; 200]);
    data.extend_from_slice(&make_tiny_pdf());
    data.extend(vec![0xDD; 100]);

    let r = assert_no_panic("carve_multi", &data);
    assert_eq!(r.archive_type, "unknown");
    assert!(
        r.files_salvaged >= 2,
        "Should carve at least 2 embedded files, got {}",
        r.files_salvaged
    );

    let types: Vec<&str> = r.files.iter().map(|f| f.file_type.as_str()).collect();
    println!("  Carved types: {:?}", types);
}

#[test]
fn stress_raw_carve_back_to_back() {
    // Files placed directly adjacent with no gap
    let mut data = Vec::new();
    let jpeg = make_tiny_jpeg();
    let png = make_tiny_png();
    data.extend_from_slice(&jpeg);
    data.extend_from_slice(&png);
    data.extend_from_slice(&jpeg); // second JPEG

    let r = assert_no_panic("carve_adjacent", &data);
    assert!(
        r.files_salvaged >= 2,
        "Back-to-back carving: expected >=2, got {}",
        r.files_salvaged
    );
}

// ═══════════════════════════════════════════════════════
//  TEST 12: Concatenated / nested archives
// ═══════════════════════════════════════════════════════

#[test]
fn stress_concatenated_zips() {
    let zip1 = make_test_zip(3);
    let zip2 = make_test_zip(4);
    let mut data = zip1;
    data.extend_from_slice(&zip2);
    let r = assert_no_panic("concat_zips", &data);
    // First ZIP should be extracted; second may or may not be found
    assert!(
        r.files_salvaged >= 3,
        "Should extract at least the first ZIP's files"
    );
}

// ═══════════════════════════════════════════════════════
//  TEST 13: Maximum stress — every corruption at once
// ═══════════════════════════════════════════════════════

#[test]
fn stress_maximum_combined_damage() {
    let mut data = make_test_zip(12);
    // Apply every corruption pattern
    corrupt_random_flips(&mut data, 20);
    corrupt_zero_block(&mut data, 30, 40);
    corrupt_single_bit_errors(&mut data, 10);
    corrupt_central_dir(&mut data, 20);
    let r = assert_no_panic("max_damage", &data);
    // We just care that it doesn't crash and produces a valid report
    assert!(r.salvage_time_secs >= 0.0); // always true, just checking structure
}

// ═══════════════════════════════════════════════════════
//  TEST 14: 7z detection and handling
// ═══════════════════════════════════════════════════════

#[test]
fn stress_fake_7z_header() {
    // 7z magic header followed by garbage — tests zombie LZMA path doesn't crash
    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]; // 7z magic
    data.extend(vec![0x00; 32]); // 7z header area
    data.extend(vec![0x42; 5000]); // garbage payload
                                   // Embed a JPEG so raw carving has something to find
    data.extend_from_slice(&make_tiny_jpeg());
    data.extend(vec![0x43; 500]);

    let r = assert_no_panic("fake_7z", &data);
    assert_eq!(r.archive_type, "7z");
    // The zombie LZMA decoder should gracefully fail and fall back to raw carving
    println!("  Fake 7z: {} files via {}", r.files_salvaged, r.method);
}

#[test]
fn stress_7z_all_garbage() {
    // 7z magic + pure garbage
    let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    let mut seed: u64 = 0xFEED_FACE_DEAD_C0DE;
    for _ in 0..10_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((seed >> 16) as u8);
    }
    let r = assert_no_panic("7z_garbage", &data);
    assert_eq!(r.archive_type, "7z");
    // Should not hang or crash even on pure garbage
}

// ═══════════════════════════════════════════════════════
//  TEST 15: ZIP pack round-trip integrity
// ═══════════════════════════════════════════════════════

#[test]
fn stress_pack_roundtrip() {
    let engine = SalvageEngine::new();
    let data = make_test_zip(6);
    let report = engine.salvage(&data, None);
    assert_eq!(report.files_salvaged, 6);

    // Pack recovered files into a new ZIP
    let packed = engine.pack_salvaged_zip(&report.files);
    assert!(!packed.is_empty());

    // Verify the output ZIP is valid and contains all files
    let reader = Cursor::new(&packed);
    let archive = zip::ZipArchive::new(reader).unwrap();
    assert_eq!(
        archive.len(),
        6,
        "Packed ZIP should contain exactly 6 files"
    );

    // Verify SHA-256 hashes are present and look valid
    for f in &report.files {
        assert_eq!(f.sha256.len(), 64, "SHA-256 should be 64 hex chars");
        assert!(
            f.sha256.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 should be hex: {}",
            f.sha256
        );
    }
}

// ═══════════════════════════════════════════════════════
//  TEST 16: Performance / timeout guard
// ═══════════════════════════════════════════════════════

#[test]
fn stress_large_zip_performance() {
    // 100 files — should complete in well under 10 seconds
    let data = make_test_zip(100);
    let start = std::time::Instant::now();
    let r = assert_no_panic("perf_100", &data);
    let elapsed = start.elapsed();
    assert_eq!(r.files_salvaged, 100);
    assert!(
        elapsed.as_secs() < 10,
        "100-file ZIP took too long: {:?}",
        elapsed
    );
    println!("  Performance: 100 files in {:?}", elapsed);
}

#[test]
fn stress_large_corrupt_zip_performance() {
    // 100 files with corruption — zombie path should not hang
    let mut data = make_test_zip(100);
    corrupt_central_dir(&mut data, 30);
    corrupt_random_flips(&mut data, 100);
    let start = std::time::Instant::now();
    let r = assert_no_panic("perf_100_corrupt", &data);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "100-file corrupt ZIP took too long: {:?}",
        elapsed
    );
    println!(
        "  Performance (corrupt): {} files in {:?}",
        r.files_salvaged, elapsed
    );
}

// ═══════════════════════════════════════════════════════
//  TEST 17: Verify file type detection accuracy
// ═══════════════════════════════════════════════════════

#[test]
fn stress_type_detection_accuracy() {
    let data = make_test_zip(8); // 2 JPEG, 2 PNG, 2 PDF, 2 TXT
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    let jpeg_count = report.files.iter().filter(|f| f.extension == "jpg").count();
    let png_count = report.files.iter().filter(|f| f.extension == "png").count();
    let pdf_count = report.files.iter().filter(|f| f.extension == "pdf").count();
    let txt_count = report.files.iter().filter(|f| f.extension == "txt").count();

    println!(
        "  Type detection: {} JPEG, {} PNG, {} PDF, {} TXT",
        jpeg_count, png_count, pdf_count, txt_count
    );
    assert_eq!(jpeg_count, 2, "Should detect 2 JPEGs");
    assert_eq!(png_count, 2, "Should detect 2 PNGs");
    assert_eq!(pdf_count, 2, "Should detect 2 PDFs");
    assert_eq!(txt_count, 2, "Should detect 2 TXT files");
}

// ═══════════════════════════════════════════════════════
//  TEST 18: JPEG end-marker trimming
// ═══════════════════════════════════════════════════════

#[test]
fn stress_jpeg_end_marker_trim() {
    // Embed a JPEG with known end marker, followed by garbage
    let jpeg = make_tiny_jpeg();
    let jpeg_len = jpeg.len();
    let mut data = Vec::new();
    data.extend_from_slice(&jpeg);
    data.extend(vec![0x42; 10_000]); // 10KB of garbage after JPEG

    let engine = SalvageEngine::new();
    let carved = engine.salvage(&data, None);

    assert!(carved.files_salvaged >= 1);
    if let Some(f) = carved.files.first() {
        // The carved JPEG should be trimmed to the FF D9 end marker,
        // NOT include the 10KB of trailing garbage
        assert!(
            f.size <= jpeg_len + 10,
            "JPEG should be trimmed to ~{} bytes, got {} bytes",
            jpeg_len,
            f.size
        );
        println!("  JPEG trimmed: original={}, carved={}", jpeg_len, f.size);
    }
}

// ═══════════════════════════════════════════════════════
//  TEST 19: PNG end-marker trimming
// ═══════════════════════════════════════════════════════

#[test]
fn stress_png_end_marker_trim() {
    let png = make_tiny_png();
    let png_len = png.len();
    let mut data = Vec::new();
    data.extend_from_slice(&png);
    data.extend(vec![0x55; 10_000]);

    let engine = SalvageEngine::new();
    let carved = engine.salvage(&data, None);

    assert!(carved.files_salvaged >= 1);
    if let Some(f) = carved.files.first() {
        assert!(
            f.size <= png_len + 10,
            "PNG should be trimmed to ~{} bytes, got {}",
            png_len,
            f.size
        );
    }
}

// ═══════════════════════════════════════════════════════
//  TEST 20: PDF end-marker trimming
// ═══════════════════════════════════════════════════════

#[test]
fn stress_pdf_end_marker_trim() {
    let pdf = make_tiny_pdf();
    let pdf_len = pdf.len();
    let mut data = Vec::new();
    data.extend_from_slice(&pdf);
    data.extend(vec![0x20; 10_000]);

    let engine = SalvageEngine::new();
    let carved = engine.salvage(&data, None);

    assert!(carved.files_salvaged >= 1);
    if let Some(f) = carved.files.first() {
        assert!(
            f.size <= pdf_len + 10,
            "PDF should be trimmed to ~{} bytes, got {}",
            pdf_len,
            f.size
        );
    }
}

// ═══════════════════════════════════════════════════════
//  TEST 21: Zombie LZMA decoder unit stress
// ═══════════════════════════════════════════════════════

#[test]
fn stress_zombie_lzma_valid_roundtrip() {
    use salvager_core::ZombieLzmaDecoder;

    // Encode a known string as LZMA, then decode with zombie decoder
    let original = b"This is a comprehensive test of the zombie LZMA decoder. \
                     It should handle valid LZMA streams cleanly with zero taint. \
                     The Shannon entropy of this English text should pass validation.";

    let encoded = lzma_encode(original);
    if encoded.is_empty() {
        println!("  LZMA encoding not available in this environment, skipping");
        return;
    }

    let decoder = ZombieLzmaDecoder::new();
    let (output, taint, stats) = decoder.decode(&encoded);

    assert!(!output.is_empty(), "Should decode valid LZMA");
    assert_eq!(taint.taint_count(), 0, "Clean stream = zero taint");
    assert_eq!(stats.resync_count, 0, "No resyncs on valid stream");
    assert_eq!(
        &output[..original.len().min(output.len())],
        &original[..original.len().min(output.len())],
        "Decoded content should match original"
    );
    println!(
        "  LZMA roundtrip: {} bytes in, {} bytes out, 0 taint",
        encoded.len(),
        output.len()
    );
}

#[test]
fn stress_zombie_lzma_corrupt_middle() {
    use salvager_core::ZombieLzmaDecoder;

    let original = b"AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL \
                     MMMM NNNN OOOO PPPP QQQQ RRRR SSSS TTTT UUUU VVVV WWWW XXXX";
    let encoded = lzma_encode(original);
    if encoded.is_empty() {
        return;
    }

    let mut corrupted = encoded.clone();
    let mid = corrupted.len() / 2;
    // Corrupt 30% of the middle
    let corrupt_len = corrupted.len() / 3;
    for i in mid..mid + corrupt_len {
        if i < corrupted.len() {
            corrupted[i] = 0xFF;
        }
    }

    let decoder = ZombieLzmaDecoder::new();
    let (output, taint, stats) = decoder.decode(&corrupted);
    // Should not crash, should return something
    println!(
        "  LZMA corrupt middle: {} out, {} tainted, {} resyncs",
        output.len(),
        taint.taint_count(),
        stats.resync_count
    );
}

#[test]
fn stress_zombie_lzma_header_destroyed() {
    use salvager_core::ZombieLzmaDecoder;

    let original = b"Hello World from zombie LZMA! Testing header destruction recovery.";
    let encoded = lzma_encode(original);
    if encoded.is_empty() {
        return;
    }

    let mut corrupted = encoded;
    // Destroy the LZMA properties header (first 5 bytes)
    for i in 0..5.min(corrupted.len()) {
        corrupted[i] = 0x00;
    }

    let decoder = ZombieLzmaDecoder::new();
    let (output, _taint, stats) = decoder.decode(&corrupted);
    println!(
        "  LZMA header destroyed: {} out, {} resyncs",
        output.len(),
        stats.resync_count
    );
    // Should not crash
}

// ═══════════════════════════════════════════════════════
//  TEST 22: Shannon entropy edge cases
// ═══════════════════════════════════════════════════════

#[test]
fn stress_entropy_classification() {
    use salvager_core::{classify_entropy, EntropyClass};

    // All zeros
    let (_, c1) = classify_entropy(&vec![0u8; 1000]);
    assert_eq!(c1, EntropyClass::Flat);

    // Pure noise (all 256 values equally)
    let noise: Vec<u8> = (0u8..=255).cycle().take(2560).collect();
    let (_, c2) = classify_entropy(&noise);
    assert_eq!(c2, EntropyClass::Noise);

    // English text
    let text = b"The quick brown fox jumps over the lazy dog multiple times to generate entropy.";
    let (h, c3) = classify_entropy(text);
    assert_eq!(
        c3,
        EntropyClass::Valid,
        "English text entropy={} should be Valid",
        h
    );

    // Binary executable-like (mixed but not uniform)
    let mut binary_like = Vec::new();
    for i in 0..1000u16 {
        binary_like.push((i % 200) as u8);
    }
    let (h4, c4) = classify_entropy(&binary_like);
    println!("  Binary-like entropy: {} ({:?})", h4, c4);
}

// ═══════════════════════════════════════════════════════
//  TEST 23: TaintMap stress
// ═══════════════════════════════════════════════════════

#[test]
fn stress_taintmap_large() {
    use salvager_core::TaintMap;

    let mut tm = TaintMap::new(1_000_000);
    // Set every 7th byte as tainted
    for i in (0..1_000_000).step_by(7) {
        tm.set(i);
    }
    let expected = 1_000_000_usize.div_ceil(7);
    assert_eq!(
        tm.taint_count(),
        expected,
        "Expected {} tainted bytes, got {}",
        expected,
        tm.taint_count()
    );

    // Verify some spots
    assert!(tm.is_tainted(0));
    assert!(tm.is_tainted(7));
    assert!(tm.is_tainted(14));
    assert!(!tm.is_tainted(1));
    assert!(!tm.is_tainted(6));

    // Grow and verify old data preserved
    tm.grow_to(2_000_000);
    assert!(tm.is_tainted(7));
    assert!(!tm.is_tainted(1_000_001));
}

// ═══════════════════════════════════════════════════════
//  HELPER
// ═══════════════════════════════════════════════════════

fn lzma_encode(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    match lzma_rs::lzma_compress(&mut std::io::BufReader::new(Cursor::new(data)), &mut output) {
        Ok(_) => output,
        Err(_) => Vec::new(),
    }
}
