//! Real-world corrupt archive tests
//!
//! These tests create archive files with realistic content (multi-file ZIPs with
//! various compression methods, embedded images, PDFs, etc.) and then apply
//! real-world corruption patterns observed in practice:
//!
//! - Disk sector death (512-byte blocks zeroed)
//! - Bad USB transfer (random byte flips in transfer blocks)
//! - Incomplete download (truncation at various points)
//! - Bitrot (single-bit errors scattered throughout)
//! - Filesystem corruption (superblock-style header destruction)
//! - Network corruption (TCP segment reordering simulation)
//! - Power loss during write (partial file with repeated sectors)
//! - NAND flash degradation (block-level errors)

use salvager_core::SalvageEngine;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

/// Create a realistic multi-file ZIP with various content types.
fn make_realistic_zip() -> Vec<u8> {
    let buf = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(buf);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    // File 1: A fake JPEG (valid header + random-ish data)
    writer.start_file("photos/vacation.jpg", stored).unwrap();
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00];
    jpeg.extend((0..2000).map(|i| ((i * 7 + 13) % 256) as u8));
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    writer.write_all(&jpeg).unwrap();

    // File 2: A fake PNG (valid header + IEND)
    writer.start_file("photos/screenshot.png", stored).unwrap();
    let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR chunk
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]); // length
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // width 16
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // height 16
    png.push(8); // bit depth
    png.push(2); // color type (RGB)
    png.extend_from_slice(&[0x00, 0x00, 0x00]); // compression, filter, interlace
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC placeholder
    // IDAT chunk with fake data
    let fake_idat: Vec<u8> = (0..1500).map(|i| ((i * 11 + 3) % 256) as u8).collect();
    png.extend_from_slice(&(fake_idat.len() as u32).to_be_bytes());
    png.extend_from_slice(b"IDAT");
    png.extend_from_slice(&fake_idat);
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC placeholder
    // IEND chunk
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    png.extend_from_slice(b"IEND");
    png.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
    writer.write_all(&png).unwrap();

    // File 3: A text document (deflated)
    writer.start_file("documents/report.txt", deflated).unwrap();
    let report = "Project Report - Q4 2024\n\
                  =========================\n\n\
                  Sales figures indicate a 23% increase in revenue compared to Q3.\n\
                  The engineering team delivered 47 features and fixed 312 bugs.\n\
                  Customer satisfaction scores improved from 4.2 to 4.7 out of 5.0.\n\n\
                  Key milestones:\n\
                  - Launched v2.0 of the platform\n\
                  - Expanded to 3 new markets\n\
                  - Reduced server costs by 15%\n\n\
                  Next quarter goals:\n\
                  - Ship mobile app v1.0\n\
                  - Hire 5 more engineers\n\
                  - Achieve SOC2 compliance\n";
    writer.write_all(report.as_bytes()).unwrap();

    // File 4: A PDF document (stored)
    writer.start_file("documents/invoice.pdf", stored).unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_vec();
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
    pdf.extend((0..800).map(|i| ((i * 3 + 7) % 256) as u8));
    pdf.extend_from_slice(b"\n%%EOF\n");
    writer.write_all(&pdf).unwrap();

    // File 5: Config file (deflated)
    writer.start_file("config/settings.json", deflated).unwrap();
    let config = r#"{"database":{"host":"10.0.1.5","port":5432,"name":"production"},"cache":{"ttl":3600,"max_size":"512MB"},"features":{"dark_mode":true,"beta_access":false}}"#;
    writer.write_all(config.as_bytes()).unwrap();

    // File 6: Binary data (fake ELF)
    writer.start_file("bin/helper", stored).unwrap();
    let mut elf = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
    elf.extend((0..500).map(|i| ((i * 17 + 42) % 256) as u8));
    writer.write_all(&elf).unwrap();

    // File 7: XML data
    writer.start_file("data/manifest.xml", deflated).unwrap();
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest>
    <version>2.1.0</version>
    <entries>
        <entry name="module_a" checksum="abc123" size="1024"/>
        <entry name="module_b" checksum="def456" size="2048"/>
        <entry name="module_c" checksum="ghi789" size="4096"/>
    </entries>
</manifest>"#;
    writer.write_all(xml.as_bytes()).unwrap();

    writer.finish().unwrap().into_inner()
}

/// Simulate disk sector death: zero out 512-byte aligned blocks.
fn corrupt_sector_death(data: &mut [u8], sectors: &[usize]) {
    for &sector in sectors {
        let start = sector * 512;
        let end = (start + 512).min(data.len());
        if start < data.len() {
            data[start..end].fill(0x00);
        }
    }
}

/// Simulate bad USB transfer: random byte flips in 64-byte blocks.
fn corrupt_usb_transfer(data: &mut [u8], seed: u64) {
    let mut rng = seed;
    let block_size = 64;
    let num_bad_blocks = data.len() / block_size / 8; // ~12.5% of blocks corrupted

    for _ in 0..num_bad_blocks {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let block_idx = (rng >> 16) as usize % (data.len() / block_size);
        let offset = block_idx * block_size;

        // Flip 3-8 bytes in this block
        let num_flips = 3 + ((rng >> 48) as usize % 6);
        for _ in 0..num_flips {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let byte_off = offset + ((rng >> 16) as usize % block_size);
            if byte_off < data.len() {
                data[byte_off] ^= 0xFF;
            }
        }
    }
}

/// Simulate bitrot: scattered single-bit errors.
fn corrupt_bitrot(data: &mut [u8], num_errors: usize, seed: u64) {
    let mut rng = seed;
    for _ in 0..num_errors {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let pos = (rng >> 16) as usize % data.len();
        let bit = (rng >> 48) as u8 % 8;
        data[pos] ^= 1 << bit;
    }
}

/// Simulate power loss: truncate and repeat last sector.
fn corrupt_power_loss(data: &[u8], cut_percent: usize) -> Vec<u8> {
    let cut_at = data.len() * cut_percent / 100;
    let mut result = data[..cut_at].to_vec();
    // Repeat last 512-byte block (common in power-loss scenarios)
    if result.len() >= 512 {
        let last_sector = result[result.len() - 512..].to_vec();
        result.extend_from_slice(&last_sector);
        result.extend_from_slice(&last_sector);
    }
    result
}

/// Simulate NAND flash degradation: entire erase blocks become 0xFF.
fn corrupt_nand_degradation(data: &mut [u8], seed: u64) {
    let erase_block = 4096; // Typical NAND erase block
    let mut rng = seed;
    let num_bad = data.len() / erase_block / 10; // 10% of blocks

    for _ in 0..num_bad {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let block_idx = (rng >> 16) as usize % (data.len() / erase_block).max(1);
        let start = block_idx * erase_block;
        let end = (start + erase_block).min(data.len());
        data[start..end].fill(0xFF);
    }
}

/// Simulate network corruption: swap two ~256-byte segments (TCP reorder).
fn corrupt_tcp_reorder(data: &mut [u8], seed: u64) {
    let seg_size = 256;
    if data.len() < seg_size * 4 {
        return;
    }
    let mut rng = seed;
    let num_swaps = 3;

    for _ in 0..num_swaps {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let a = (rng >> 16) as usize % (data.len() - seg_size * 2);
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let b_offset = seg_size + (rng >> 16) as usize % (data.len() - a - seg_size * 2).max(1);
        let b = a + b_offset;

        if b + seg_size <= data.len() && a + seg_size <= b {
            let seg_a: Vec<u8> = data[a..a + seg_size].to_vec();
            let seg_b: Vec<u8> = data[b..b + seg_size].to_vec();
            data[a..a + seg_size].copy_from_slice(&seg_b);
            data[b..b + seg_size].copy_from_slice(&seg_a);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  TEST CASES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_realistic_zip_uncorrupted() {
    let data = make_realistic_zip();
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert_eq!(report.archive_type, "zip");
    assert!(
        report.files_salvaged >= 6,
        "Should recover at least 6 files from a valid 7-file ZIP, got {}",
        report.files_salvaged
    );
    assert_eq!(report.crc_errors_ignored, 0);
}

#[test]
fn test_sector_death_single_sector() {
    let mut data = make_realistic_zip();
    // Kill sector in the middle — typically destroys one or two files
    let mid_sector = data.len() / 512 / 2;
    corrupt_sector_death(&mut data, &[mid_sector]);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert!(
        report.files_salvaged >= 2,
        "Should still recover files despite one dead sector, got {}",
        report.files_salvaged
    );
}

#[test]
fn test_sector_death_multiple() {
    let mut data = make_realistic_zip();
    let total_sectors = data.len() / 512;
    // Kill 20% of sectors throughout the file
    let bad_sectors: Vec<usize> = (0..total_sectors).step_by(5).collect();
    corrupt_sector_death(&mut data, &bad_sectors);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // Even with heavy corruption, carving should find something
    assert!(
        report.files_salvaged >= 1,
        "Should recover at least 1 file from 20% dead sectors"
    );
}

#[test]
fn test_bad_usb_transfer() {
    let mut data = make_realistic_zip();
    corrupt_usb_transfer(&mut data, 0xDEADBEEF);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // USB corruption is scattered, fail-forward + carving should recover
    assert!(
        report.files_salvaged >= 1,
        "Should recover files from USB-corrupted archive"
    );
}

#[test]
fn test_bitrot_light() {
    let mut data = make_realistic_zip();
    // 10 single-bit errors scattered throughout
    corrupt_bitrot(&mut data, 10, 0xCAFEBABE);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert!(
        report.files_salvaged >= 4,
        "Light bitrot should allow most files to survive, got {}",
        report.files_salvaged
    );
}

#[test]
fn test_bitrot_heavy() {
    let mut data = make_realistic_zip();
    // 100 single-bit errors throughout (heavy bitrot)
    corrupt_bitrot(&mut data, 100, 0xFACEFEED);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // Engine should not panic, should attempt recovery
    assert!(report.archive_type == "zip" || report.archive_type == "unknown");
}

#[test]
fn test_incomplete_download_75_percent() {
    let data = make_realistic_zip();
    let truncated = &data[..data.len() * 75 / 100];

    let engine = SalvageEngine::new();
    let report = engine.salvage(truncated, None);

    // First 75% of archive should still have extractable files
    assert!(
        report.files_salvaged >= 1,
        "75% download should still yield files, got {}",
        report.files_salvaged
    );
}

#[test]
fn test_incomplete_download_50_percent() {
    let data = make_realistic_zip();
    let truncated = &data[..data.len() * 50 / 100];

    let engine = SalvageEngine::new();
    let report = engine.salvage(truncated, None);

    // 50% should still have carve-able content
    assert!(
        report.files_salvaged >= 1,
        "50% download should still yield some files"
    );
}

#[test]
fn test_incomplete_download_25_percent() {
    let data = make_realistic_zip();
    let truncated = &data[..data.len() * 25 / 100];

    let engine = SalvageEngine::new();
    let report = engine.salvage(truncated, None);

    // Even 25% might have the first file(s) — at minimum, the engine shouldn't panic
    let _ = report;
}

#[test]
fn test_power_loss_during_write() {
    let data = make_realistic_zip();
    let corrupted = corrupt_power_loss(&data, 60);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&corrupted, None);

    assert!(
        report.files_salvaged >= 1,
        "Power loss at 60% should preserve early files"
    );
}

#[test]
fn test_nand_flash_degradation() {
    let mut data = make_realistic_zip();
    corrupt_nand_degradation(&mut data, 0x12345678);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // Flash degradation (0xFF blocks) should still allow partial recovery
    assert!(
        report.files_salvaged >= 1,
        "NAND degradation should allow some recovery"
    );
}

#[test]
fn test_tcp_reorder_corruption() {
    let mut data = make_realistic_zip();
    corrupt_tcp_reorder(&mut data, 0xABCDEF01);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // TCP reorder preserves data but scrambles structure — carving should find pieces
    assert!(
        report.files_salvaged >= 1,
        "TCP reorder should still allow carved recovery"
    );
}

#[test]
fn test_header_destruction() {
    let mut data = make_realistic_zip();
    // Zero out the ZIP local file header (first 30 bytes)
    let end = 30.min(data.len());
    data[..end].fill(0x00);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // ZIP magic destroyed — should detect as unknown and fall back to carving
    // Still should carve embedded files (JPEG, PNG, PDF, etc.)
    assert!(
        report.files_salvaged >= 1,
        "Destroyed header should still allow raw carving"
    );
}

#[test]
fn test_central_directory_destroyed() {
    let mut data = make_realistic_zip();
    // Destroy last 200 bytes (central directory area)
    let len = data.len();
    let start = len.saturating_sub(200);
    data[start..].fill(0x00);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // With central directory gone, should still extract via fail-forward or carving
    assert!(
        report.files_salvaged >= 1,
        "Destroyed central dir should allow fail-forward or carving"
    );
}

#[test]
fn test_combined_corruption_realistic_scenario() {
    // Realistic scenario: bitrot + partial truncation + one dead sector
    let full_data = make_realistic_zip();
    let mut data = full_data[..full_data.len() * 80 / 100].to_vec();
    corrupt_bitrot(&mut data, 20, 0x42424242);
    corrupt_sector_death(&mut data, &[2]); // Kill sector 2

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert!(
        report.files_salvaged >= 1,
        "Combined corruption should still allow some recovery"
    );
}

#[test]
fn test_all_zeros_input() {
    let data = vec![0x00; 10000];
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert_eq!(report.files_salvaged, 0, "All zeros should yield no files");
    assert_eq!(report.archive_type, "unknown");
}

#[test]
fn test_all_ff_input() {
    let data = vec![0xFF; 10000];
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert_eq!(report.files_salvaged, 0, "All 0xFF should yield no files");
}

#[test]
fn test_random_noise_input() {
    let data: Vec<u8> = (0..10000).map(|i| ((i * 13 + 7) % 256) as u8).collect();
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // Random data might accidentally match a signature, but shouldn't crash
    let _ = report;
}

#[test]
fn test_embedded_archive_in_garbage() {
    // A valid ZIP surrounded by garbage bytes — tests carving ability
    let zip_data = make_realistic_zip();
    let mut data = Vec::new();
    data.extend((0..2000).map(|i| ((i * 19) % 256) as u8)); // 2KB garbage prefix
    data.extend_from_slice(&zip_data);
    data.extend((0..3000).map(|i| ((i * 23) % 256) as u8)); // 3KB garbage suffix

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    // Should be detected as unknown (garbage prefix), but should carve the ZIP and its contents
    assert!(
        report.files_salvaged >= 1,
        "Embedded ZIP in garbage should be carved"
    );
}

#[test]
fn test_concatenated_files_no_archive() {
    // Raw concatenated files (not in any archive format)
    let mut data = Vec::new();

    // JPEG
    data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    data.extend(std::iter::repeat(0x42u8).take(500));
    data.extend_from_slice(&[0xFF, 0xD9]);

    // Garbage gap
    data.extend(std::iter::repeat(0x00u8).take(100));

    // PNG
    data.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    data.extend(std::iter::repeat(0x55u8).take(300));
    data.extend_from_slice(b"IEND");
    data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);

    // PDF
    data.extend_from_slice(b"%PDF-1.7 ");
    data.extend(std::iter::repeat(0x20u8).take(200));
    data.extend_from_slice(b"%%EOF\n");

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    assert_eq!(report.archive_type, "unknown");
    assert_eq!(report.files_salvaged, 3, "Should carve 3 concatenated files");
}

#[test]
fn test_double_corrupted_zip() {
    // Create ZIP, corrupt it, then wrap it in another ZIP that's also corrupted
    let inner_zip = make_realistic_zip();
    let mut corrupted_inner = inner_zip;
    corrupt_bitrot(&mut corrupted_inner, 30, 0x11223344);

    let buf = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(buf);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    writer.start_file("backup.zip", opts).unwrap();
    writer.write_all(&corrupted_inner).unwrap();
    let mut outer = writer.finish().unwrap().into_inner();

    // Corrupt the outer ZIP too
    corrupt_bitrot(&mut outer, 15, 0x55667788);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&outer, None);

    // Double corruption — should still attempt recovery
    assert!(
        report.files_salvaged >= 1,
        "Double-corrupted ZIP should still yield something"
    );
}
