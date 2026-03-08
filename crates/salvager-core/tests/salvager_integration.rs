//! Integration tests: run Salvager-Core against real corrupted archives.
//!
//! These tests require external test archives that are NOT included in the
//! repository.  If a test archive is missing, the test is **skipped** rather
//! than failed.  To run them, place the following files in the workspace root:
//!
//!   test_photos.zip               — 10-file clean ZIP (JPEG/PNG)
//!   test_corrupt_light.zip/.7z    — ~5 % random byte flips
//!   test_corrupt_medium.zip/.7z   — ~20 % random byte flips
//!   test_corrupt_heavy.zip/.7z    — ~50 % random byte flips
//!   test_corrupt_header.zip/.7z   — first 64 bytes zeroed
//!   test_corrupt_catastrophic.zip/.7z — 80 %+ destruction

use salvager_core::SalvageEngine;
use std::path::PathBuf;

fn project_dir() -> PathBuf {
    // Test archives live at the workspace root, two levels up from crates/salvager-core/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Load a test archive; returns `None` if the file doesn't exist (skip test).
fn try_load(name: &str) -> Option<Vec<u8>> {
    let path = project_dir().join(name);
    match std::fs::read(&path) {
        Ok(data) => Some(data),
        Err(_) => {
            eprintln!("SKIP: test archive not found: {}", path.display());
            None
        }
    }
}

/// Helper macro: skip the test (return early) if the test archive is absent.
macro_rules! require_file {
    ($name:expr) => {
        match try_load($name) {
            Some(data) => data,
            None => return,
        }
    };
}

fn run_salvage(data: &[u8], label: &str) -> salvager_core::SalvageReport {
    let engine = SalvageEngine::new();
    let report = engine.salvage(data, None);
    println!("\n══════ {} ══════", label);
    println!("  Archive type  : {}", report.archive_type);
    println!("  Method        : {}", report.method);
    println!("  Input size    : {} bytes", report.input_size);
    println!("  Files salvaged: {}", report.files_salvaged);
    println!("  Salvaged bytes: {} bytes", report.total_salvaged_bytes);
    println!("  CRC errors    : {}", report.crc_errors_ignored);
    println!("  LZMA errors   : {}", report.lzma_errors_bypassed);
    println!("  Salvage rate  : {}%", report.salvage_rate_percent);
    println!("  Time          : {}s", report.salvage_time_secs);
    for tc in &report.type_breakdown {
        println!("    {} : {} files, {} bytes", tc.file_type, tc.count, tc.total_bytes);
    }
    for f in &report.files {
        println!("    [{}] {} .{} — {} bytes @ offset 0x{:X} — sha256:{}…",
            f.index, f.file_type, f.extension, f.size, f.offset, &f.sha256[..16.min(f.sha256.len())]);
    }
    report
}

// ══════════════════════════════════════════════
//  ZIP TESTS
// ══════════════════════════════════════════════

#[test]
fn test_salvage_valid_zip() {
    let data = require_file!("test_photos.zip");
    let r = run_salvage(&data, "test_photos.zip");
    assert_eq!(r.archive_type, "zip");
    assert_eq!(r.files_salvaged, 10, "Should extract all 10 files from clean ZIP");
    assert_eq!(r.crc_errors_ignored, 0);
}

#[test]
fn test_salvage_corrupt_light_zip() {
    let data = require_file!("test_corrupt_light.zip");
    let r = run_salvage(&data, "test_corrupt_light.zip");
    assert_eq!(r.archive_type, "zip");
    assert!(r.files_salvaged >= 5, "Light ZIP corruption: expected ≥5 files, got {}", r.files_salvaged);
}

#[test]
fn test_salvage_corrupt_medium_zip() {
    let data = require_file!("test_corrupt_medium.zip");
    let r = run_salvage(&data, "test_corrupt_medium.zip");
    assert_eq!(r.archive_type, "zip");
    assert!(r.files_salvaged >= 3, "Medium ZIP corruption: expected ≥3 files, got {}", r.files_salvaged);
}

#[test]
fn test_salvage_corrupt_heavy_zip() {
    let data = require_file!("test_corrupt_heavy.zip");
    let r = run_salvage(&data, "test_corrupt_heavy.zip");
    assert_eq!(r.archive_type, "zip");
    assert!(r.files_salvaged >= 1, "Heavy ZIP corruption: expected ≥1 file, got {}", r.files_salvaged);
}

#[test]
fn test_salvage_corrupt_header_zip() {
    let data = require_file!("test_corrupt_header.zip");
    let r = run_salvage(&data, "test_corrupt_header.zip");
    println!("  Header-destroyed ZIP: {} files via {}", r.files_salvaged, r.method);
}

#[test]
fn test_salvage_corrupt_catastrophic_zip() {
    let data = require_file!("test_corrupt_catastrophic.zip");
    let r = run_salvage(&data, "test_corrupt_catastrophic.zip");
    println!("  Catastrophic ZIP: {} files via {}", r.files_salvaged, r.method);
}

// ══════════════════════════════════════════════
//  7z TESTS
// ══════════════════════════════════════════════

#[test]
fn test_salvage_corrupt_light_7z() {
    let data = require_file!("test_corrupt_light.7z");
    let r = run_salvage(&data, "test_corrupt_light.7z");
    assert_eq!(r.archive_type, "7z");
    println!("  Light 7z: {} files via {}", r.files_salvaged, r.method);
}

#[test]
fn test_salvage_corrupt_medium_7z() {
    let data = require_file!("test_corrupt_medium.7z");
    let r = run_salvage(&data, "test_corrupt_medium.7z");
    assert_eq!(r.archive_type, "7z");
    println!("  Medium 7z: {} files via {}", r.files_salvaged, r.method);
}

#[test]
fn test_salvage_corrupt_heavy_7z() {
    let data = require_file!("test_corrupt_heavy.7z");
    let r = run_salvage(&data, "test_corrupt_heavy.7z");
    assert_eq!(r.archive_type, "7z");
    println!("  Heavy 7z: {} files via {}", r.files_salvaged, r.method);
}

#[test]
fn test_salvage_corrupt_header_7z() {
    let data = require_file!("test_corrupt_header.7z");
    let r = run_salvage(&data, "test_corrupt_header.7z");
    println!("  Header-destroyed 7z: type={}, {} files via {}", r.archive_type, r.files_salvaged, r.method);
}

#[test]
fn test_salvage_corrupt_catastrophic_7z() {
    let data = require_file!("test_corrupt_catastrophic.7z");
    let r = run_salvage(&data, "test_corrupt_catastrophic.7z");
    println!("  Catastrophic 7z: {} files via {}", r.files_salvaged, r.method);
}

// ══════════════════════════════════════════════
//  PACK & DOWNLOAD TEST
// ══════════════════════════════════════════════

#[test]
fn test_pack_salvaged_output() {
    let data = require_file!("test_corrupt_medium.zip");
    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    if report.files_salvaged > 0 {
        let zip_bytes = engine.pack_salvaged_zip(&report.files);
        assert!(!zip_bytes.is_empty(), "Packed recovery ZIP should not be empty");
        println!("  Packed {} salvaged files into {} byte ZIP", report.files_salvaged, zip_bytes.len());

        // Verify the output ZIP is valid
        let reader = std::io::Cursor::new(&zip_bytes);
        let archive = zip::ZipArchive::new(reader).unwrap();
        assert_eq!(archive.len(), report.files_salvaged);
    }
}
