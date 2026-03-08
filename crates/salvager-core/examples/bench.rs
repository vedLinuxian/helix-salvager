//! Benchmarks for the Helix Salvager core engine.
//!
//! Run: cargo bench --workspace

use salvager_core::SalvageEngine;
use std::io::{Cursor, Write};
use std::time::Instant;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

/// Create a test ZIP of the specified target size (approximately).
fn make_zip(target_bytes: usize) -> Vec<u8> {
    let buf = Cursor::new(Vec::with_capacity(target_bytes));
    let mut w = zip::ZipWriter::new(buf);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    let mut written = 0;
    let mut idx = 0;
    while written < target_bytes {
        let name = format!("file_{:04}.dat", idx);
        let opts = if idx % 2 == 0 { stored } else { deflated };
        w.start_file(&name, opts).unwrap();
        let chunk_size = (target_bytes - written).min(8192);
        let data: Vec<u8> = (0..chunk_size)
            .map(|i| ((i * 7 + idx) % 256) as u8)
            .collect();
        w.write_all(&data).unwrap();
        written += chunk_size;
        idx += 1;
    }
    w.finish().unwrap().into_inner()
}

/// Corrupt a ZIP by zeroing sectors.
fn corrupt(data: &mut [u8], pct: usize) {
    let sector = 512;
    let bad_count = (data.len() / sector) * pct / 100;
    let mut rng: u64 = 0xDEAD;
    for _ in 0..bad_count {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let s = (rng >> 16) as usize % (data.len() / sector).max(1);
        let start = s * sector;
        let end = (start + sector).min(data.len());
        data[start..end].fill(0x00);
    }
}

fn bench_one(label: &str, data: &[u8]) {
    let engine = SalvageEngine::new();

    // Warm up
    let _ = engine.salvage(data, None);

    // Timed run (3 iterations)
    let mut times = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        let report = engine.salvage(data, None);
        let elapsed = t.elapsed();
        times.push((elapsed, report.files_salvaged, report.bytes_recovered));
    }

    let avg_ms = times.iter().map(|t| t.0.as_millis()).sum::<u128>() / 3;
    let files = times[0].1;
    let bytes = times[0].2;
    let throughput = if avg_ms > 0 {
        (data.len() as f64 / 1024.0 / 1024.0) / (avg_ms as f64 / 1000.0)
    } else {
        0.0
    };

    println!(
        "  {:<40} {:>8} bytes  {:>4} ms  {:>3} files  {:>10} bytes  {:.1} MB/s",
        label,
        data.len(),
        avg_ms,
        files,
        bytes,
        throughput
    );
}

fn main() {
    println!();
    println!(
        "╔══════════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║                        HELIX SALVAGER — BENCHMARKS                                  ║"
    );
    println!(
        "╠══════════════════════════════════════════════════════════════════════════════════════╣"
    );
    println!(
        "║  Scenario                                    Input      Time  Files    Recovered    ║"
    );
    println!(
        "╟──────────────────────────────────────────────────────────────────────────────────────╢"
    );

    // ── Clean ZIP benchmarks ──
    let zip_10k = make_zip(10_000);
    bench_one("Clean ZIP 10 KB", &zip_10k);

    let zip_100k = make_zip(100_000);
    bench_one("Clean ZIP 100 KB", &zip_100k);

    let zip_1m = make_zip(1_000_000);
    bench_one("Clean ZIP 1 MB", &zip_1m);

    let zip_10m = make_zip(10_000_000);
    bench_one("Clean ZIP 10 MB", &zip_10m);

    println!(
        "╟──────────────────────────────────────────────────────────────────────────────────────╢"
    );

    // ── Corrupted ZIP benchmarks ──
    let mut c5 = zip_1m.clone();
    corrupt(&mut c5, 5);
    bench_one("Corrupt ZIP 1 MB (5% sectors dead)", &c5);

    let mut c20 = zip_1m.clone();
    corrupt(&mut c20, 20);
    bench_one("Corrupt ZIP 1 MB (20% sectors dead)", &c20);

    let mut c50 = zip_1m.clone();
    corrupt(&mut c50, 50);
    bench_one("Corrupt ZIP 1 MB (50% sectors dead)", &c50);

    println!(
        "╟──────────────────────────────────────────────────────────────────────────────────────╢"
    );

    // ── Raw carving benchmarks ──
    let mut raw = Vec::new();
    // Embed known file signatures in random data
    for i in 0..20 {
        raw.extend(vec![0xAA; 500]);
        match i % 4 {
            0 => {
                raw.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
                raw.extend(vec![0x42; 300]);
                raw.extend_from_slice(&[0xFF, 0xD9]);
            }
            1 => {
                raw.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
                raw.extend(vec![0x55; 400]);
            }
            2 => {
                raw.extend_from_slice(b"%PDF-1.4 ");
                raw.extend(vec![0x20; 200]);
                raw.extend_from_slice(b"%%EOF\n");
            }
            _ => {
                raw.extend_from_slice(b"RIFF");
                raw.extend_from_slice(&1000u32.to_le_bytes());
                raw.extend_from_slice(b"WAVE");
                raw.extend(vec![0x33; 300]);
            }
        }
    }
    bench_one("Raw carving (20 embedded signatures)", &raw);

    // Large raw carving
    let mut big_raw: Vec<u8> = (0..5_000_000).map(|i| ((i * 13 + 7) % 256) as u8).collect();
    // Plant some real signatures
    big_raw[100_000..100_004].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    big_raw[200_000..200_008].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    big_raw[300_000..300_009].copy_from_slice(b"%PDF-1.7 ");
    bench_one("Raw carving 5 MB (3 planted sigs)", &big_raw);

    println!(
        "╟──────────────────────────────────────────────────────────────────────────────────────╢"
    );

    // ── All zeros / noise (worst case) ──
    let zeros = vec![0x00; 1_000_000];
    bench_one("All zeros 1 MB (no recovery)", &zeros);

    let noise: Vec<u8> = (0..1_000_000)
        .map(|i| ((i * 17 + 31) % 256) as u8)
        .collect();
    bench_one("Random noise 1 MB (no recovery)", &noise);

    println!(
        "╚══════════════════════════════════════════════════════════════════════════════════════╝"
    );
    println!();
}
