//! Helix Salvager CLI — command-line corrupt archive recovery.
//!
//! Usage:
//!   salvager recover  broken_archive.zip  -o ./recovered/
//!   salvager recover  broken_archive.7z   -o ./recovered/ --json
//!   salvager inspect  broken_archive.zip
//!   salvager formats
//!   salvager version

use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use salvager_core::{SalvageEngine, SalvageReport};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// ═══════════════════════════════════════════════════════
///  Helix Salvager — Corrupt Archive Recovery CLI
/// ═══════════════════════════════════════════════════════
#[derive(Parser)]
#[command(
    name = "salvager",
    version = "1.0.0",
    about = "Corrupt Archive Recovery Engine",
    long_about = "Helix Salvager — Recovers files from damaged/corrupt ZIP, 7z, GZIP, BZIP2, XZ, and raw binary blobs.\n\
                  Engines: Fail-Forward ZIP · Zombie LZMA · AhoCorasick 29-sig Carver · TaintMap",
    after_help = "Examples:\n  \
                  salvager recover broken.zip -o ./recovered/\n  \
                  salvager recover archive.7z -o ./out --json\n  \
                  salvager inspect damaged.zip\n  \
                  salvager formats"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Recover files from a corrupt archive
    Recover {
        /// Path to the corrupt archive file
        input: PathBuf,

        /// Output directory for recovered files (default: ./salvaged_output/)
        #[arg(short, long, default_value = "salvaged_output")]
        output: PathBuf,

        /// Write a single ZIP file instead of individual files
        #[arg(long)]
        zip: bool,

        /// Output machine-readable JSON report to stdout
        #[arg(long)]
        json: bool,

        /// Suppress all human-readable output except errors
        #[arg(short, long)]
        quiet: bool,
    },

    /// Inspect an archive without extracting (dry-run analysis)
    Inspect {
        /// Path to the archive file
        input: PathBuf,

        /// Output JSON instead of human-readable table
        #[arg(long)]
        json: bool,
    },

    /// Show version and engine info
    Version,

    /// List all supported file signatures and archive formats
    Formats,

    /// Scan a disk image (.img/.dd/.raw) for recoverable files
    DiskImage {
        /// Path to the disk image file
        input: PathBuf,

        /// Output directory for recovered files
        #[arg(short, long, default_value = "salvaged_output")]
        output: PathBuf,

        /// Output JSON report
        #[arg(long)]
        json: bool,
    },

    /// Stream-process a large file using sliding window carving
    Stream {
        /// Path to the large file to process
        input: PathBuf,

        /// Output directory for recovered files
        #[arg(short, long, default_value = "salvaged_output")]
        output: PathBuf,

        /// Window size in MB (default: 64)
        #[arg(long, default_value = "64")]
        window_mb: usize,

        /// Output JSON report
        #[arg(long)]
        json: bool,
    },

    /// Load plugin signatures and recover with custom file types
    Plugin {
        /// Path to the plugin JSON configuration file
        config: PathBuf,

        /// Path to the archive or data file to recover from
        input: PathBuf,

        /// Output directory for recovered files
        #[arg(short, long, default_value = "salvaged_output")]
        output: PathBuf,

        /// Output JSON report
        #[arg(long)]
        json: bool,
    },

    /// Validate recovered files and show structural analysis
    Validate {
        /// Path to a file or directory of files to validate
        input: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Recover {
            input,
            output,
            zip,
            json,
            quiet,
        } => cmd_recover(input, output, zip, json, quiet),
        Commands::Inspect { input, json } => cmd_inspect(input, json),
        Commands::Version => cmd_version(),
        Commands::Formats => cmd_formats(),
        Commands::DiskImage {
            input,
            output,
            json,
        } => cmd_disk_image(input, output, json),
        Commands::Stream {
            input,
            output,
            window_mb,
            json,
        } => cmd_stream(input, output, window_mb, json),
        Commands::Plugin {
            config,
            input,
            output,
            json,
        } => cmd_plugin(config, input, output, json),
        Commands::Validate { input } => cmd_validate(input),
    }
}

// ═══════════════════════════════════════════════════════
//  RECOVER
// ═══════════════════════════════════════════════════════

fn cmd_recover(input: PathBuf, output: PathBuf, as_zip: bool, json: bool, quiet: bool) {
    if !quiet && !json {
        print_banner();
    }

    // Read input file
    let data = match std::fs::read(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{} Cannot read {}: {}",
                "ERROR".red().bold(),
                input.display(),
                e
            );
            std::process::exit(1);
        }
    };

    if !quiet && !json {
        eprintln!(
            "{}  Input : {} ({} bytes)",
            "▸".cyan().bold(),
            input.display().to_string().white().bold(),
            data.len()
        );
    }

    // Set up progress bar (only for interactive mode)
    let pb = if !quiet && !json {
        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{bar:40.cyan/dim}] {pos}% {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        Some(pb)
    } else {
        None
    };

    let engine = SalvageEngine::new();
    let start = Instant::now();

    let report = if let Some(ref pb) = pb {
        let pb_clone = pb.clone();
        engine.salvage(
            &data,
            Some(&move |phase: &str, pct: u32| {
                pb_clone.set_position(pct as u64);
                pb_clone.set_message(phase.to_string());
            }),
        )
    } else {
        engine.salvage(&data, None)
    };

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    let elapsed = start.elapsed();

    // Write output
    if report.files_salvaged == 0 {
        if json {
            print_json_report(&report, &input);
        } else if !quiet {
            eprintln!(
                "\n{}  No recoverable files found. The archive may be fully destroyed.",
                "✗".red().bold()
            );
        }
        std::process::exit(2);
    }

    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!(
            "{} Cannot create output dir {}: {}",
            "ERROR".red().bold(),
            output.display(),
            e
        );
        std::process::exit(1);
    });

    if as_zip {
        // Pack everything into a single ZIP
        let zip_bytes = engine.pack_salvaged_zip(&report.files);
        let zip_name = input
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "salvaged".into());
        let zip_path = output.join(format!("{}_recovered.zip", zip_name));

        std::fs::write(&zip_path, &zip_bytes).unwrap_or_else(|e| {
            eprintln!(
                "{} Cannot write {}: {}",
                "ERROR".red().bold(),
                zip_path.display(),
                e
            );
            std::process::exit(1);
        });

        if !quiet && !json {
            eprintln!(
                "{}  Wrote {} → {}",
                "▸".green().bold(),
                format!("{} files", report.files_salvaged).white().bold(),
                zip_path.display().to_string().green()
            );
        }
    } else {
        // Write individual files
        for f in &report.files {
            let fname = format!("salvaged_{:04}_{}.{}", f.index, f.file_type, f.extension);
            let fpath = output.join(&fname);
            if let Err(e) = std::fs::write(&fpath, &f.data) {
                eprintln!(
                    "{}  Failed to write {}: {}",
                    "⚠".yellow().bold(),
                    fpath.display(),
                    e
                );
            }
        }
        if !quiet && !json {
            eprintln!(
                "{}  Extracted {} files → {}",
                "▸".green().bold(),
                format!("{}", report.files_salvaged).white().bold(),
                output.display().to_string().green()
            );
        }
    }

    // Print results
    if json {
        print_json_report(&report, &input);
    } else if !quiet {
        print_human_report(&report, elapsed);
    }
}

// ═══════════════════════════════════════════════════════
//  INSPECT (dry-run)
// ═══════════════════════════════════════════════════════

fn cmd_inspect(input: PathBuf, json: bool) {
    if !json {
        print_banner();
    }

    let data = match std::fs::read(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{} Cannot read {}: {}",
                "ERROR".red().bold(),
                input.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let engine = SalvageEngine::new();
    let report = engine.salvage(&data, None);

    if json {
        print_json_report(&report, &input);
    } else {
        eprintln!(
            "{}  Input : {} ({} bytes)",
            "▸".cyan().bold(),
            input.display().to_string().white().bold(),
            data.len()
        );
        print_human_report(
            &report,
            std::time::Duration::from_secs_f64(report.salvage_time_secs),
        );
        eprintln!(
            "\n{}  Dry run — no files written. Use `salvager recover` to extract.",
            "ℹ".blue().bold()
        );
    }
}

// ═══════════════════════════════════════════════════════
//  VERSION
// ═══════════════════════════════════════════════════════

fn cmd_version() {
    println!("salvager {}", env!("CARGO_PKG_VERSION"));
    println!("Engines : Fail-Forward ZIP | Zombie LZMA | RAR v4/v5 | AhoCorasick 29-sig Carver | TaintMap");
    println!("Formats : ZIP, 7z, RAR, GZIP, BZIP2, XZ, TAR (via decompression)");
    println!("Carve   : JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, PDF, MP3, FLAC,");
    println!("          OGG, WAV, AVI, MP4, MKV, ELF, PE/EXE, SQLite, WASM, ZIP");
    println!("Features: Parallel recovery, Plugin system, Disk image support,");
    println!("          Streaming mode, Deep validation, Confidence scoring");
    println!("License : MIT OR Apache-2.0");
}

fn cmd_formats() {
    println!();
    println!(
        "{}  {} — Supported Formats & Signatures",
        "═══".cyan(),
        "Helix Salvager".white().bold()
    );
    println!();
    println!(
        "{}  Archive Formats (structured extraction):",
        "▸".cyan().bold()
    );
    println!(
        "    {:<12} ZIP archives (PKzip, WinZip, etc.)",
        "ZIP".yellow().bold()
    );
    println!(
        "    {:<12} 7-Zip archives (LZMA/LZMA2 compressed)",
        "7z".yellow().bold()
    );
    println!(
        "    {:<12} RAR archives (v4/v5 header parsing)",
        "RAR".yellow().bold()
    );
    println!(
        "    {:<12} GNU zip compressed streams",
        "GZIP".yellow().bold()
    );
    println!(
        "    {:<12} bzip2 compressed streams",
        "BZIP2".yellow().bold()
    );
    println!(
        "    {:<12} XZ/LZMA2 compressed streams",
        "XZ".yellow().bold()
    );
    println!(
        "    {:<12} Tape archives (inside gzip/bzip2/xz)",
        "TAR".yellow().bold()
    );
    println!();
    println!(
        "{}  File Signatures (magic-byte carving):",
        "▸".cyan().bold()
    );
    println!("    ── Images ──");
    println!("    {:<12} JPEG (FF D8 FF)", "JPEG".green());
    println!("    {:<12} PNG (89 50 4E 47)", "PNG".green());
    println!("    {:<12} GIF (47 49 46 38)", "GIF".green());
    println!("    {:<12} BMP (42 4D + valid size)", "BMP".green());
    println!(
        "    {:<12} TIFF (49 49 2A 00 / 4D 4D 00 2A)",
        "TIFF".green()
    );
    println!("    {:<12} WebP (RIFF + WEBP)", "WebP".green());
    println!("    {:<12} ICO (00 00 01 00 + valid dir)", "ICO".green());
    println!();
    println!("    ── Audio/Video ──");
    println!("    {:<12} MP3 frame sync (FF FB/FA/F3/F2)", "MP3".green());
    println!("    {:<12} FLAC (66 4C 61 43)", "FLAC".green());
    println!("    {:<12} OGG (4F 67 67 53)", "OGG".green());
    println!("    {:<12} WAV (RIFF + WAVE)", "WAV".green());
    println!("    {:<12} AVI (RIFF + AVI)", "AVI".green());
    println!("    {:<12} MP4 (ftyp at +4)", "MP4".green());
    println!("    {:<12} MKV/WebM (1A 45 DF A3)", "MKV".green());
    println!();
    println!("    ── Documents ──");
    println!("    {:<12} PDF (25 50 44 46)", "PDF".green());
    println!();
    println!("    ── Executables ──");
    println!("    {:<12} ELF (7F 45 4C 46)", "ELF".green());
    println!("    {:<12} PE/EXE (4D 5A + PE header)", "PE/EXE".green());
    println!("    {:<12} WASM (00 61 73 6D)", "WASM".green());
    println!();
    println!("    ── Data ──");
    println!("    {:<12} SQLite (53 51 4C 69 74 65)", "SQLite".green());
    println!("    {:<12} ZIP (50 4B 03 04)", "ZIP".green());
    println!();
    println!(
        "  {} Total: {} file signatures across {} archive formats",
        "═══".cyan(),
        "29".white().bold(),
        "7".white().bold()
    );
    println!();
}

// ═══════════════════════════════════════════════════════
//  DISK IMAGE
// ═══════════════════════════════════════════════════════

fn cmd_disk_image(input: PathBuf, output: PathBuf, json: bool) {
    if !json {
        print_banner();
    }

    eprintln!(
        "{}  Scanning disk image: {} ",
        "▸".cyan().bold(),
        input.display().to_string().white().bold()
    );

    let engine = SalvageEngine::new();
    let start = Instant::now();

    let report = match salvager_core::scan_disk_image(&input, &engine, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Disk image error: {}", "ERROR".red().bold(), e);
            std::process::exit(1);
        }
    };

    let all_files = salvager_core::collect_all_files(&report);
    let elapsed = start.elapsed();

    if all_files.is_empty() {
        if json {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            eprintln!(
                "{}  No recoverable files found in disk image.",
                "✗".red().bold()
            );
        }
        std::process::exit(2);
    }

    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!("{} Cannot create output dir: {}", "ERROR".red().bold(), e);
        std::process::exit(1);
    });

    for (i, f) in all_files.iter().enumerate() {
        let fname = format!("disk_{:04}_{}.{}", i, f.file_type, f.extension);
        let fpath = output.join(&fname);
        let _ = std::fs::write(&fpath, &f.data);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        eprintln!();
        eprintln!("{}", "─── Disk Image Report ───".cyan().bold());
        eprintln!("  Image size      : {} bytes", report.image_size);
        eprintln!("  Partition scheme: {:?}", report.partition_scheme);
        eprintln!("  Partitions found: {}", report.partitions.len());
        for p in &report.partitions {
            eprintln!(
                "    #{}: {} ({}) offset={} size={}",
                p.index, p.label, p.filesystem, p.start_offset, p.size
            );
        }
        eprintln!(
            "  Files recovered : {}",
            format!("{}", all_files.len()).green().bold()
        );
        eprintln!("  Time            : {:.3}s", elapsed.as_secs_f64());
        eprintln!(
            "{}  Extracted → {}",
            "▸".green().bold(),
            output.display().to_string().green()
        );
        eprintln!();
    }
}

// ═══════════════════════════════════════════════════════
//  STREAM
// ═══════════════════════════════════════════════════════

fn cmd_stream(input: PathBuf, output: PathBuf, window_mb: usize, json: bool) {
    if !json {
        print_banner();
    }

    eprintln!(
        "{}  Streaming recovery: {} (window: {} MB)",
        "▸".cyan().bold(),
        input.display().to_string().white().bold(),
        window_mb
    );

    let engine = SalvageEngine::new();
    let config = salvager_core::StreamConfig {
        window_size: window_mb * 1024 * 1024,
        ..Default::default()
    };

    let report = match salvager_core::stream_salvage(&input, &engine, &config, None) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Stream error: {}", "ERROR".red().bold(), e);
            std::process::exit(1);
        }
    };

    if report.files.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "input_size": report.input_size,
                    "windows_processed": report.windows_processed,
                    "files_salvaged": 0,
                }))
                .unwrap()
            );
        } else {
            eprintln!("{}  No recoverable files found.", "✗".red().bold());
        }
        std::process::exit(2);
    }

    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!("{} Cannot create output dir: {}", "ERROR".red().bold(), e);
        std::process::exit(1);
    });

    for f in &report.files {
        let fname = format!("stream_{:04}_{}.{}", f.index, f.file_type, f.extension);
        let fpath = output.join(&fname);
        let _ = std::fs::write(&fpath, &f.data);
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "input_size": report.input_size,
                "windows_processed": report.windows_processed,
                "files_salvaged": report.files_salvaged,
                "bytes_recovered": report.bytes_recovered,
                "method": report.method,
                "time_secs": report.scan_time_secs,
            }))
            .unwrap()
        );
    } else {
        eprintln!();
        eprintln!("{}", "─── Stream Report ───".cyan().bold());
        eprintln!("  Input size      : {} bytes", report.input_size);
        eprintln!("  Windows scanned : {}", report.windows_processed);
        eprintln!(
            "  Files recovered : {}",
            format!("{}", report.files_salvaged).green().bold()
        );
        eprintln!("  Bytes recovered : {}", report.bytes_recovered);
        eprintln!("  Method          : {}", report.method);
        eprintln!("  Time            : {:.3}s", report.scan_time_secs);
        eprintln!(
            "{}  Extracted → {}",
            "▸".green().bold(),
            output.display().to_string().green()
        );
        eprintln!();
    }
}

// ═══════════════════════════════════════════════════════
//  PLUGIN
// ═══════════════════════════════════════════════════════

fn cmd_plugin(config_path: PathBuf, input: PathBuf, output: PathBuf, json: bool) {
    if !json {
        print_banner();
    }

    let registry = match salvager_core::PluginRegistry::load_json(&config_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} Failed to load plugin config {}: {}",
                "ERROR".red().bold(),
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    eprintln!(
        "{}  Loaded {} custom signatures from {}",
        "▸".cyan().bold(),
        registry.len(),
        config_path.display().to_string().white().bold()
    );

    let data = match std::fs::read(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{} Cannot read {}: {}",
                "ERROR".red().bold(),
                input.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let engine = SalvageEngine::with_plugins(&registry);
    let start = Instant::now();

    let report = engine.salvage(&data, None);
    let elapsed = start.elapsed();

    if report.files_salvaged == 0 {
        if json {
            print_json_report(&report, &input);
        } else {
            eprintln!("{}  No recoverable files found.", "✗".red().bold());
        }
        std::process::exit(2);
    }

    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!("{} Cannot create output dir: {}", "ERROR".red().bold(), e);
        std::process::exit(1);
    });

    for f in &report.files {
        let fname = format!("plugin_{:04}_{}.{}", f.index, f.file_type, f.extension);
        let fpath = output.join(&fname);
        let _ = std::fs::write(&fpath, &f.data);
    }

    if json {
        print_json_report(&report, &input);
    } else {
        eprintln!(
            "{}  Recovered {} files with {} plugin sigs + {} built-in sigs",
            "▸".green().bold(),
            format!("{}", report.files_salvaged).green().bold(),
            registry.len(),
            engine.builtin_signature_count()
        );
        print_human_report(&report, elapsed);
    }
}

// ═══════════════════════════════════════════════════════
//  VALIDATE
// ═══════════════════════════════════════════════════════

fn cmd_validate(input: PathBuf) {
    print_banner();

    let paths: Vec<PathBuf> = if input.is_dir() {
        match std::fs::read_dir(&input) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect(),
            Err(e) => {
                eprintln!("{} Cannot read directory: {}", "ERROR".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        vec![input]
    };

    eprintln!("{}", "─── File Validation ───".cyan().bold());

    for p in &paths {
        let data = match std::fs::read(p) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  {} {} — read error: {}", "✗".red(), p.display(), e);
                continue;
            }
        };

        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Build a SalvagedFile wrapper for the validator
        let salvaged = salvager_core::SalvagedFile {
            index: 0,
            name: p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            file_type: ext.clone(),
            extension: ext,
            offset: 0,
            size: data.len(),
            sha256: String::new(),
            confidence: 0.5,
            data,
        };

        let result = salvager_core::validate_file(&salvaged);
        let status = if result.valid {
            format!("{}", "VALID".green().bold())
        } else {
            format!("{}", "INVALID".red().bold())
        };

        let conf_delta = if result.confidence_delta >= 0.0 {
            format!("+{:.0}%", result.confidence_delta * 100.0)
                .green()
                .to_string()
        } else {
            format!("{:.0}%", result.confidence_delta * 100.0)
                .red()
                .to_string()
        };

        eprintln!(
            "  {} {} — {} (conf: {})",
            if result.valid {
                "✓".green()
            } else {
                "✗".red()
            },
            p.file_name().unwrap_or_default().to_string_lossy(),
            status,
            conf_delta
        );

        for note in &result.notes {
            eprintln!("      {}", note.dimmed());
        }
        for issue in &result.issues {
            let sev = match issue.severity {
                salvager_core::IssueSeverity::Info => "INFO".blue(),
                salvager_core::IssueSeverity::Warning => "WARN".yellow(),
                salvager_core::IssueSeverity::Error => "ERR ".red(),
            };
            eprintln!(
                "      [{}] offset {}: {}",
                sev, issue.offset, issue.description
            );
        }
    }
    eprintln!();
}

// ═══════════════════════════════════════════════════════
//  Display helpers
// ═══════════════════════════════════════════════════════

fn print_banner() {
    eprintln!();
    eprintln!(
        "{}",
        "═══════════════════════════════════════════════════════".cyan()
    );
    eprintln!(
        "  {} {}",
        "Helix Salvager".white().bold(),
        "v1.0 — Corrupt Archive Recovery".dimmed()
    );
    eprintln!(
        "{}",
        "═══════════════════════════════════════════════════════".cyan()
    );
    eprintln!();
}

fn print_human_report(report: &SalvageReport, elapsed: std::time::Duration) {
    eprintln!();
    eprintln!("{}", "─── Salvage Report ───".cyan().bold());
    eprintln!(
        "  Archive type    : {}",
        report.archive_type.to_uppercase().yellow().bold()
    );
    eprintln!("  Method          : {}", report.method.white());
    eprintln!(
        "  Input size      : {} bytes",
        format!("{}", report.input_size).white()
    );
    eprintln!(
        "  Files recovered : {}",
        format!("{}", report.files_salvaged).green().bold()
    );
    eprintln!(
        "  Salvaged bytes  : {}",
        format!("{}", report.total_salvaged_bytes).green()
    );
    if report.crc_errors_ignored > 0 {
        eprintln!(
            "  CRC errors hit  : {} {}",
            report.crc_errors_ignored,
            "(bypassed)".dimmed()
        );
    }
    if report.lzma_errors_bypassed > 0 {
        eprintln!(
            "  LZMA errors     : {} {}",
            report.lzma_errors_bypassed,
            "(chunk-bypassed)".dimmed()
        );
    }
    eprintln!(
        "  Salvage rate    : {}",
        format!("{}%", report.salvage_rate_percent).green().bold()
    );
    eprintln!(
        "  Confidence      : {}",
        format_confidence(report.overall_confidence)
    );
    eprintln!("  Time            : {:.3}s", elapsed.as_secs_f64());

    if !report.type_breakdown.is_empty() {
        eprintln!();
        eprintln!("{}", "─── Type Breakdown ───".cyan());
        for tc in &report.type_breakdown {
            eprintln!(
                "  {:>8} : {} files, {} bytes",
                tc.file_type.yellow(),
                tc.count,
                tc.total_bytes
            );
        }
    }

    if !report.files.is_empty() {
        eprintln!();
        eprintln!("{}", "─── Recovered Files ───".cyan());
        for f in &report.files {
            let hash_short = if f.sha256.len() >= 12 {
                &f.sha256[..12]
            } else {
                &f.sha256
            };
            let conf_str = format_confidence(f.confidence);
            let name_display = if f.name.is_empty() {
                format!("salvaged_{:04}.{}", f.index, f.extension)
            } else {
                f.name.clone()
            };
            eprintln!(
                "  {} {:>6} .{:<4} {:>10} bytes  {} {}  {}",
                format!("[{:3}]", f.index).dimmed(),
                f.file_type.yellow(),
                f.extension,
                f.size,
                conf_str,
                hash_short.dimmed(),
                name_display.blue()
            );
        }
    }
    eprintln!();
}

fn print_json_report(report: &SalvageReport, input: &Path) {
    let file_list: Vec<serde_json::Value> = report
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "index": f.index,
                "name": f.name,
                "file_type": f.file_type,
                "extension": f.extension,
                "offset": f.offset,
                "size": f.size,
                "sha256": f.sha256,
                "confidence": f.confidence,
            })
        })
        .collect();

    let out = serde_json::json!({
        "input": input.display().to_string(),
        "input_size": report.input_size,
        "archive_type": report.archive_type,
        "method": report.method,
        "files_salvaged": report.files_salvaged,
        "total_salvaged_bytes": report.total_salvaged_bytes,
        "corruption_bypassed": report.corruption_bypassed,
        "crc_errors_ignored": report.crc_errors_ignored,
        "lzma_errors_bypassed": report.lzma_errors_bypassed,
        "salvage_rate_percent": report.salvage_rate_percent,
        "overall_confidence": report.overall_confidence,
        "salvage_time_secs": report.salvage_time_secs,
        "type_breakdown": report.type_breakdown,
        "files": file_list,
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

/// Format confidence as a colored string: green(>0.8), yellow(>0.5), red(<=0.5)
fn format_confidence(confidence: f64) -> colored::ColoredString {
    let pct = (confidence * 100.0).round() as u32;
    let label = format!("{}%", pct);
    if confidence >= 0.8 {
        label.green().bold()
    } else if confidence >= 0.5 {
        label.yellow()
    } else {
        label.red()
    }
}
