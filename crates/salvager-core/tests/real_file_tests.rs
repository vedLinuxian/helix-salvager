//! Real-life archive file tests
//!
//! These tests use REAL archive files downloaded from the internet:
//!   - corkami/pocs ZIP PoCs (simple, store, bz2, lzma, deflate64, unicode,
//!     zip64, dual, shrunk, implode)
//!   - corkami/pocs RAR files (v4, v5, 2MB prepended, CVE-2018-0986, SFX)
//!   - corkami/pocs FFF_PoCs.zip (Funky File Formats — a 2.4 MB ZIP with
//!     polyglot files from Ange Albertini's 31C3 talk)
//!   - GNU hello tarball (real gzip)
//!   - 7-Zip official XZ archive
//!   - W3C sample PDF and PNG
//!
//! Each test loads the REAL bytes, applies a real corruption pattern, and
//! verifies the salvager handles it gracefully — no panics, reasonable
//! recovery where possible.

use salvager_core::SalvageEngine;
use std::path::PathBuf;

/// Path to test_real_world directory.
fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_real_world")
}

/// Load a real file from the test_real_world directory.
fn load(name: &str) -> Vec<u8> {
    let path = data_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Cannot read real test file {}: {} (download with start.sh test first)",
            path.display(),
            e
        )
    })
}

/// Zero out 512-byte sectors.
fn kill_sectors(data: &mut [u8], sectors: &[usize]) {
    for &s in sectors {
        let start = s * 512;
        let end = (start + 512).min(data.len());
        if start < data.len() {
            data[start..end].fill(0x00);
        }
    }
}

/// Scatter single-bit errors throughout.
fn bitrot(data: &mut [u8], n: usize, seed: u64) {
    let mut rng = seed;
    for _ in 0..n {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let pos = (rng >> 16) as usize % data.len();
        let bit = (rng >> 48) as u8 % 8;
        data[pos] ^= 1 << bit;
    }
}

/// Byte-flip corruption in 64-byte USB transfer blocks.
fn usb_corrupt(data: &mut [u8], seed: u64) {
    let mut rng = seed;
    let bsz = 64;
    let n = data.len() / bsz / 8;
    for _ in 0..n {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let block = (rng >> 16) as usize % (data.len() / bsz);
        let off = block * bsz;
        let flips = 3 + ((rng >> 48) as usize % 6);
        for _ in 0..flips {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = off + ((rng >> 16) as usize % bsz);
            if b < data.len() {
                data[b] ^= 0xFF;
            }
        }
    }
}

/// NAND degradation: 4096-byte erase blocks go to 0xFF.
fn nand_degrade(data: &mut [u8], seed: u64) {
    let eb = 4096;
    let mut rng = seed;
    let n = data.len() / eb / 10;
    for _ in 0..n {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let block = (rng >> 16) as usize % (data.len() / eb).max(1);
        let start = block * eb;
        let end = (start + eb).min(data.len());
        data[start..end].fill(0xFF);
    }
}

// ═══════════════════════════════════════════════════════════════
//  REAL ZIP TESTS — corkami/pocs ZIP collection
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_corkami_simple_zip_intact() {
    let data = load("corkami_simple.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(
        report.files_salvaged >= 1,
        "Real corkami simple.zip should yield at least 1 file, got {}",
        report.files_salvaged
    );
}

#[test]
fn real_corkami_store_zip_intact() {
    let data = load("corkami_store.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(report.files_salvaged >= 1);
}

#[test]
fn real_corkami_zip64_intact() {
    let data = load("corkami_zip64.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(
        report.files_salvaged >= 1,
        "Real zip64 file should yield files, got {}",
        report.files_salvaged
    );
}

#[test]
fn real_corkami_dual_zip_intact() {
    // dual.zip has 2 files with same name — tests dedup / overwrite handling
    let data = load("corkami_dual.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(report.files_salvaged >= 1);
}

#[test]
fn real_corkami_unicode_zip_intact() {
    let data = load("corkami_unicode.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(report.files_salvaged >= 1);
}

#[test]
fn real_fff_pocs_zip_intact() {
    // Funky File Formats — 2.4 MB ZIP from 31C3 talk containing polyglot files
    let data = load("corkami_fff.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "zip");
    assert!(
        report.files_salvaged >= 5,
        "FFF PoCs ZIP (2.4 MB, multi-file) should yield many files, got {}",
        report.files_salvaged
    );
}

// ═══════════════════════════════════════════════════════════════
//  CORRUPT REAL ZIP TESTS
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_fff_zip_sector_death() {
    let mut data = load("corkami_fff.zip");
    // Kill 5 sectors in the middle of the 2.4 MB archive
    let mid = data.len() / 512 / 2;
    kill_sectors(&mut data, &[mid, mid + 1, mid + 2, mid + 3, mid + 4]);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Should still recover most files from a large multi-file ZIP
    assert!(
        report.files_salvaged >= 1,
        "FFF ZIP with 5 dead sectors should still recover files, got {}",
        report.files_salvaged
    );
}

#[test]
fn real_fff_zip_bitrot() {
    let mut data = load("corkami_fff.zip");
    bitrot(&mut data, 50, 0xCAFEBABE);

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert!(
        report.files_salvaged >= 1,
        "FFF ZIP with 50-bit errors should recover something"
    );
}

#[test]
fn real_fff_zip_truncated_75() {
    let data = load("corkami_fff.zip");
    let cut = &data[..data.len() * 75 / 100];
    let engine = SalvageEngine::new();
    let report = engine.salvage(cut, None);
    assert!(
        report.files_salvaged >= 1,
        "75% of FFF ZIP should still have extractable files"
    );
}

#[test]
fn real_fff_zip_truncated_50() {
    let data = load("corkami_fff.zip");
    let cut = &data[..data.len() * 50 / 100];
    let engine = SalvageEngine::new();
    let report = engine.salvage(cut, None);
    assert!(
        report.files_salvaged >= 1,
        "50% of FFF ZIP should yield some files"
    );
}

#[test]
fn real_fff_zip_header_destroyed() {
    let mut data = load("corkami_fff.zip");
    // Destroy the first 64 bytes (ZIP local header + magic)
    data[..64].fill(0x00);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Without ZIP magic, engine should fall to carving
    assert!(
        report.files_salvaged >= 1,
        "FFF ZIP with header destroyed should carve embedded files"
    );
}

#[test]
fn real_fff_zip_usb_corruption() {
    let mut data = load("corkami_fff.zip");
    usb_corrupt(&mut data, 0xDEAD);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert!(
        report.files_salvaged >= 1,
        "USB-corrupted FFF ZIP should still yield files"
    );
}

#[test]
fn real_fff_zip_nand_degradation() {
    let mut data = load("corkami_fff.zip");
    nand_degrade(&mut data, 0x1234);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert!(
        report.files_salvaged >= 1,
        "NAND-degraded FFF ZIP should recover something"
    );
}

#[test]
fn real_simple_zip_completely_destroyed() {
    // Take real simple.zip and overwrite 80% of it
    let mut data = load("corkami_simple.zip");
    let destroy_len = data.len() * 80 / 100;
    data[..destroy_len].fill(0xCC);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Mostly destroyed — engine should not panic, may or may not find anything
    let _ = report;
}

// ═══════════════════════════════════════════════════════════════
//  REAL RAR TESTS — corkami/pocs RAR collection
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_rar4_intact() {
    let data = load("corkami_rar4.rar");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // RAR not natively supported — should detect as unknown, carve what it can
    // The file has a RAR magic, engine should recognize it
    assert!(
        report.archive_type == "unknown" || report.archive_type == "rar",
        "RAR v4 should be detected, got: {}",
        report.archive_type
    );
}

#[test]
fn real_rar5_intact() {
    let data = load("corkami_rar5.rar");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert!(
        report.archive_type == "unknown" || report.archive_type == "rar",
        "RAR v5 should be handled, got: {}",
        report.archive_type
    );
}

#[test]
fn real_2mb_rar_with_prepended_data() {
    // 2mb.rar has 0x1ffff0 bytes of prepended space before the RAR data
    let data = load("corkami_2mb.rar");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Even with 2MB of prepended data, carver should find embedded content
    let _ = report; // mostly verifying no panic on large input
}

#[test]
fn real_cve_2018_0986_rar() {
    // CVE-2018-0986 PoC RAR — this is a real CVE exploit file
    let data = load("corkami_cve.rar");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Should handle malicious input safely — no panic, no infinite loop
    let _ = report;
}

#[test]
fn real_sfx_rar() {
    // SFX RAR — self-extracting archive (has executable header + RAR data)
    let data = load("corkami_sfx.rar");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Should process the whole blob, carve any recognizable content
    let _ = report;
}

#[test]
fn real_2mb_rar_sector_death() {
    let mut data = load("corkami_2mb.rar");
    kill_sectors(&mut data, &[100, 200, 300, 400, 500]);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    let _ = report;
}

#[test]
fn real_2mb_rar_heavy_bitrot() {
    let mut data = load("corkami_2mb.rar");
    bitrot(&mut data, 500, 0xBEEF);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    let _ = report;
}

// ═══════════════════════════════════════════════════════════════
//  REAL XZ / GZIP / TARBALL TESTS
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_xz_archive_intact() {
    // Official 7-Zip Linux binary (XZ compressed tar)
    let data = load("test_7z.7z");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // XZ magic 0xFD377A585A00 — engine should detect and attempt decompression
    assert!(
        report.archive_type == "xz"
            || report.archive_type == "unknown"
            || report.archive_type == "7z",
        "XZ file should be recognized, got: {}",
        report.archive_type
    );
}

#[test]
fn real_xz_truncated() {
    let data = load("test_7z.7z");
    let cut = &data[..data.len() / 2];
    let engine = SalvageEngine::new();
    let report = engine.salvage(cut, None);
    // Truncated XZ — should not panic
    let _ = report;
}

#[test]
fn real_xz_bitrot() {
    let mut data = load("test_7z.7z");
    bitrot(&mut data, 100, 0xABCD);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    let _ = report;
}

#[test]
fn real_gzip_tarball_intact() {
    let data = load("real_gzip.gz");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert!(
        report.archive_type == "gzip"
            || report.archive_type == "unknown"
            || report.archive_type == "tar",
        "Gzip file should be detected, got: {}",
        report.archive_type
    );
}

#[test]
fn real_gzip_tarball_truncated() {
    let data = load("real_gzip.gz");
    let cut = &data[..data.len() * 60 / 100];
    let engine = SalvageEngine::new();
    let report = engine.salvage(cut, None);
    // Truncated gzip — partial decompression, should not panic
    let _ = report;
}

#[test]
fn real_gzip_tarball_corrupted() {
    let mut data = load("real_gzip.gz");
    usb_corrupt(&mut data, 0x9999);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    let _ = report;
}

// ═══════════════════════════════════════════════════════════════
//  REAL PDF AND PNG (non-archive files fed to salvager)
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_pdf_as_unknown_input() {
    // Feed a real PDF (not an archive) — should detect as unknown, carve the PDF itself
    let data = load("sample.pdf");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "unknown");
    assert!(
        report.files_salvaged >= 1,
        "Real PDF fed directly should be carved as a PDF file, got {}",
        report.files_salvaged
    );
}

#[test]
fn real_png_as_unknown_input() {
    let data = load("sample.png");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    assert_eq!(report.archive_type, "unknown");
    assert!(
        report.files_salvaged >= 1,
        "Real PNG fed directly should be carved, got {}",
        report.files_salvaged
    );
}

// ═══════════════════════════════════════════════════════════════
//  EXTREME CORRUPTION SCENARIOS ON REAL FILES
// ═══════════════════════════════════════════════════════════════

#[test]
fn real_fff_zip_50_percent_zeroed() {
    let mut data = load("corkami_fff.zip");
    // Zero out the second half of the archive
    let half = data.len() / 2;
    data[half..].fill(0x00);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // First half should still have extractable content
    assert!(
        report.files_salvaged >= 1,
        "Half-zeroed FFF ZIP should recover from first half"
    );
}

#[test]
fn real_fff_zip_every_other_sector_dead() {
    let mut data = load("corkami_fff.zip");
    let sectors: Vec<usize> = (0..data.len() / 512).step_by(2).collect();
    kill_sectors(&mut data, &sectors);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // 50% sector loss — mostly destroyed but engine should not panic
    let _ = report;
}

#[test]
fn real_mixed_corruption_gzip() {
    // Combine bitrot + sector death on a real gzip
    let mut data = load("real_gzip.gz");
    bitrot(&mut data, 30, 0x7777);
    kill_sectors(&mut data, &[0, 5, 10]);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    let _ = report;
}

#[test]
fn real_xz_header_destroyed() {
    let mut data = load("test_7z.7z");
    // Destroy XZ magic bytes
    data[..12].fill(0x00);
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);
    // Without magic, should fall to unknown → carve
    assert_eq!(report.archive_type, "unknown");
}

#[test]
fn real_concatenated_real_files() {
    // Concatenate multiple real files into one blob (simulates disk image carving)
    let pdf = load("sample.pdf");
    let png = load("sample.png");
    let txt = load("sample.txt");
    let zip = load("corkami_simple.zip");

    let mut blob = Vec::new();
    blob.extend(vec![0xAA; 512]); // garbage prefix
    blob.extend_from_slice(&pdf);
    blob.extend(vec![0x00; 256]); // gap
    blob.extend_from_slice(&png);
    blob.extend(vec![0xBB; 128]); // gap
    blob.extend_from_slice(&zip);
    blob.extend(vec![0xCC; 64]);  // gap
    blob.extend_from_slice(&txt);
    blob.extend(vec![0xDD; 512]); // garbage suffix

    let engine = SalvageEngine::new();
    let report = engine.salvage(&blob, None);
    assert_eq!(report.archive_type, "unknown");
    assert!(
        report.files_salvaged >= 2,
        "Concatenated real files should be carved, got {}",
        report.files_salvaged
    );
}

#[test]
fn real_disk_image_simulation() {
    // Simulate a raw disk image fragment: FFF ZIP embedded at offset 4096
    // with garbage sectors before and after
    let zip = load("corkami_fff.zip");
    let mut disk = vec![0x00; 4096]; // empty sectors
    disk.extend_from_slice(&zip);
    disk.extend(vec![0xFF; 4096]); // unallocated space

    let engine = SalvageEngine::new();
    let report = engine.salvage(&disk, None);
    assert!(
        report.files_salvaged >= 1,
        "ZIP embedded in disk image should be found"
    );
}
