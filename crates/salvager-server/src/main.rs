//! Helix Salvager v2.0 — Advanced Corrupt Archive Recovery Server
//!
//! Features:
//!   - Port management: random, custom, auto-detect free port, kill conflicting processes
//!   - Advanced verbose logging with colored terminal output and timestamps
//!   - Task history with retention policies
//!   - Health monitoring and uptime tracking
//!   - Graceful shutdown handling

use actix_cors::Cors;
use actix_files as fs;
use actix_multipart::Multipart;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use chrono::Local;
use clap::Parser;
use colored::Colorize;
use futures_util::TryStreamExt;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use salvager_core::SalvageEngine;

// ═══════════════════════════════════════════════════════
//  CLI ARGUMENTS — Port management & configuration
// ═══════════════════════════════════════════════════════

/// Helix Salvager Server — Corrupt Archive Recovery Web UI
#[derive(Parser, Debug)]
#[command(
    name = "salvager-server",
    version = "2.0.0",
    about = "Corrupt Archive Recovery Server with Web UI",
    long_about = "Helix Salvager Server — runs a web interface for corrupt archive recovery.\n\
                  Supports advanced port management, verbose logging, and real-time progress tracking."
)]
struct ServerArgs {
    /// Port to listen on (0 = random available port)
    #[arg(short, long, default_value = "5001")]
    port: u16,

    /// Use a random available port
    #[arg(long, conflicts_with = "port")]
    random_port: bool,

    /// Kill any process currently using the target port before starting
    #[arg(long)]
    kill_port: bool,

    /// Bind address (default: 127.0.0.1, use 0.0.0.0 for all interfaces)
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Maximum upload size in MB (default: 256)
    #[arg(long, default_value = "256")]
    max_upload_mb: usize,

    /// Number of worker threads (default: auto-detect CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Verbose logging level (0=minimal, 1=normal, 2=detailed, 3=trace)
    #[arg(short = 'V', long, default_value = "1")]
    verbose: u8,

    /// Open browser automatically after starting
    #[arg(long)]
    open: bool,

    /// Directory for static web assets (auto-detected if not set)
    #[arg(long)]
    static_dir: Option<String>,

    /// Directory for download files (default: system temp)
    #[arg(long)]
    download_dir: Option<String>,

    /// Maximum concurrent tasks (default: 8)
    #[arg(long, default_value = "8")]
    max_tasks: usize,

    /// Task retention time in minutes (default: 30)
    #[arg(long, default_value = "30")]
    task_retention: u64,

    /// Disable colored terminal output
    #[arg(long)]
    no_color: bool,
}

// ═══════════════════════════════════════════════════════
//  VERBOSE LOGGER
// ═══════════════════════════════════════════════════════

struct VerboseLogger {
    level: u8,
    no_color: bool,
}

impl VerboseLogger {
    fn new(level: u8, no_color: bool) -> Self {
        Self { level, no_color }
    }

    fn timestamp(&self) -> String {
        Local::now().format("%H:%M:%S%.3f").to_string()
    }

    fn info(&self, msg: &str) {
        if self.level >= 1 {
            if self.no_color {
                eprintln!("[{}] INFO  {}", self.timestamp(), msg);
            } else {
                eprintln!(
                    "{} {} {}",
                    format!("[{}]", self.timestamp()).dimmed(),
                    "INFO ".green().bold(),
                    msg
                );
            }
        }
    }

    fn detail(&self, msg: &str) {
        if self.level >= 2 {
            if self.no_color {
                eprintln!("[{}] DETAIL {}", self.timestamp(), msg);
            } else {
                eprintln!(
                    "{} {} {}",
                    format!("[{}]", self.timestamp()).dimmed(),
                    "DETAIL".cyan(),
                    msg
                );
            }
        }
    }

    fn warn(&self, msg: &str) {
        if self.no_color {
            eprintln!("[{}] WARN  {}", self.timestamp(), msg);
        } else {
            eprintln!(
                "{} {} {}",
                format!("[{}]", self.timestamp()).dimmed(),
                "WARN ".yellow().bold(),
                msg.yellow()
            );
        }
    }

    fn error(&self, msg: &str) {
        if self.no_color {
            eprintln!("[{}] ERROR {}", self.timestamp(), msg);
        } else {
            eprintln!(
                "{} {} {}",
                format!("[{}]", self.timestamp()).dimmed(),
                "ERROR".red().bold(),
                msg.red()
            );
        }
    }

    fn success(&self, msg: &str) {
        if self.no_color {
            eprintln!("[{}] OK    {}", self.timestamp(), msg);
        } else {
            eprintln!(
                "{} {} {}",
                format!("[{}]", self.timestamp()).dimmed(),
                "  OK ".green().bold(),
                msg.green()
            );
        }
    }
}

// ═══════════════════════════════════════════════════════
//  PORT MANAGEMENT
// ═══════════════════════════════════════════════════════

fn find_random_port(bind: &str) -> std::io::Result<u16> {
    let listener = TcpListener::bind(format!("{bind}:0"))?;
    Ok(listener.local_addr()?.port())
}

fn is_port_available(bind: &str, port: u16) -> bool {
    TcpListener::bind(format!("{bind}:{port}")).is_ok()
}

fn kill_port_processes(port: u16, logger: &VerboseLogger) -> bool {
    logger.warn(&format!("Attempting to kill processes on port {port}..."));

    let output = std::process::Command::new("lsof")
        .args(["-t", "-i", &format!(":{port}")])
        .output();

    if let Ok(output) = output {
        let pids = String::from_utf8_lossy(&output.stdout);
        let pids: Vec<&str> = pids.trim().split('\n').filter(|s| !s.is_empty()).collect();

        if pids.is_empty() {
            logger.info(&format!("No process found on port {port}"));
            return true;
        }

        for pid in &pids {
            logger.detail(&format!("Killing PID {pid} on port {port}"));
            let _ = std::process::Command::new("kill")
                .args(["-9", pid])
                .output();
        }

        std::thread::sleep(std::time::Duration::from_millis(500));

        if is_port_available("127.0.0.1", port) {
            logger.success(&format!("Port {port} is now free"));
            return true;
        }
    }

    let output = std::process::Command::new("fuser")
        .args(["-k", &format!("{port}/tcp")])
        .output();

    if output.is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if is_port_available("127.0.0.1", port) {
            logger.success(&format!("Port {port} freed via fuser"));
            return true;
        }
    }

    logger.error(&format!("Failed to free port {port}"));
    false
}

fn show_port_info(port: u16, logger: &VerboseLogger) {
    let output = std::process::Command::new("lsof")
        .args(["-i", &format!(":{port}"), "-P", "-n"])
        .output();

    if let Ok(output) = output {
        let info = String::from_utf8_lossy(&output.stdout);
        if !info.trim().is_empty() {
            logger.detail(&format!("Port {port} in use by:\n{info}"));
        }
    }
}

// ═══════════════════════════════════════════════════════
//  APP STATE
// ═══════════════════════════════════════════════════════

struct AppState {
    tasks: RwLock<HashMap<String, TaskState>>,
    download_dir: PathBuf,
    static_dir: PathBuf,
    max_upload_bytes: usize,
    max_tasks: usize,
    task_retention_secs: u64,
    start_time: Instant,
    total_uploads: AtomicU64,
    total_files_recovered: AtomicU64,
    total_bytes_processed: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
struct TaskState {
    id: String,
    #[serde(skip_serializing)]
    owner: String,
    status: String,
    phase: String,
    percent: u32,
    result: Option<serde_json::Value>,
    error: Option<String>,
    #[serde(skip_serializing)]
    download_path: Option<PathBuf>,
    created_at: String,
    filename: Option<String>,
}

impl TaskState {
    fn new(id: &str, owner: &str) -> Self {
        Self {
            id: id.to_string(),
            owner: owner.to_string(),
            status: "running".to_string(),
            phase: "Starting...".to_string(),
            percent: 0,
            result: None,
            error: None,
            download_path: None,
            created_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            filename: None,
        }
    }
}

fn client_key(req: &HttpRequest) -> String {
    let sanitize_sid = |raw: &str| -> Option<String> {
        let trimmed = raw.trim();
        let valid = !trimmed.is_empty()
            && trimmed.len() <= 128
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if valid {
            Some(trimmed.to_string())
        } else {
            None
        }
    };

    if let Some(session_header) = req
        .headers()
        .get("x-salvager-session")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(sid) = sanitize_sid(session_header) {
            return format!("sid:{sid}");
        }
    }
    if let Some(sid) = req.query_string().split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        if key == "sid" {
            sanitize_sid(value)
        } else {
            None
        }
    }) {
        return format!("sid:{sid}");
    }

    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown_ip".to_string());
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown_ua");
    format!("{ip}|{ua}")
}

fn new_task(state: &AppState, owner: &str) -> Option<String> {
    let id = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
    let mut tasks = state.tasks.write();

    let running = tasks.values().filter(|t| t.status == "running").count();
    if running >= state.max_tasks {
        return None;
    }

    // Purge expired tasks
    let retention = state.task_retention_secs;
    let now = chrono::Utc::now();
    let expired: Vec<String> = tasks
        .iter()
        .filter(|(_, t)| {
            if t.status == "done" || t.status == "error" {
                if let Ok(created) =
                    chrono::NaiveDateTime::parse_from_str(&t.created_at, "%Y-%m-%d %H:%M:%S")
                {
                    let created_utc = created.and_utc();
                    return (now - created_utc).num_seconds() as u64 > retention;
                }
            }
            false
        })
        .map(|(k, _)| k.clone())
        .collect();

    for old_id in &expired {
        if let Some(old_task) = tasks.remove(old_id) {
            if let Some(path) = &old_task.download_path {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    if tasks.len() > 100 {
        let done_ids: Vec<String> = tasks
            .iter()
            .filter(|(_, t)| t.status == "done" || t.status == "error")
            .map(|(k, _)| k.clone())
            .collect();
        for old_id in done_ids.iter().take(done_ids.len().saturating_sub(10)) {
            if let Some(old_task) = tasks.remove(old_id) {
                if let Some(path) = &old_task.download_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    tasks.insert(id.clone(), TaskState::new(&id, owner));
    Some(id)
}

fn update_task(state: &AppState, id: &str, f: impl FnOnce(&mut TaskState)) {
    let mut tasks = state.tasks.write();
    if let Some(t) = tasks.get_mut(id) {
        f(t);
    }
}

// ═══════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════

async fn api_health(state: web::Data<AppState>) -> HttpResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let tasks = state.tasks.read();
    let running = tasks.values().filter(|t| t.status == "running").count();
    let completed = tasks.values().filter(|t| t.status == "done").count();

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "Helix Salvager",
        "version": "2.0.0",
        "uptime_secs": uptime,
        "active_tasks": running,
        "completed_tasks": completed,
        "total_uploads": state.total_uploads.load(Ordering::Relaxed),
        "total_files_recovered": state.total_files_recovered.load(Ordering::Relaxed),
        "total_bytes_processed": state.total_bytes_processed.load(Ordering::Relaxed),
        "max_upload_mb": state.max_upload_bytes / (1024 * 1024),
    }))
}

async fn api_stats(state: web::Data<AppState>) -> HttpResponse {
    let tasks = state.tasks.read();
    let running = tasks.values().filter(|t| t.status == "running").count();
    let completed = tasks.values().filter(|t| t.status == "done").count();
    let errored = tasks.values().filter(|t| t.status == "error").count();
    let uptime = state.start_time.elapsed().as_secs();

    HttpResponse::Ok().json(serde_json::json!({
        "uptime_secs": uptime,
        "tasks_running": running,
        "tasks_completed": completed,
        "tasks_errored": errored,
        "total_uploads": state.total_uploads.load(Ordering::Relaxed),
        "total_files_recovered": state.total_files_recovered.load(Ordering::Relaxed),
        "total_bytes_processed": state.total_bytes_processed.load(Ordering::Relaxed),
    }))
}

async fn api_tasks(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let owner = client_key(&req);
    let tasks = state.tasks.read();
    let my_tasks: Vec<serde_json::Value> = tasks
        .values()
        .filter(|t| t.owner == owner)
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "status": t.status,
                "phase": t.phase,
                "percent": t.percent,
                "created_at": t.created_at,
                "filename": t.filename,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({ "tasks": my_tasks }))
}

async fn api_progress(
    path: web::Path<String>,
    state: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let task_id = path.into_inner();
    let owner = client_key(&req);

    let tasks = state.tasks.read();
    match tasks.get(&task_id) {
        Some(t) if t.owner == owner => HttpResponse::Ok().json(t),
        Some(_) => HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Task not found"})),
    }
}

async fn api_salvage(
    req: HttpRequest,
    mut payload: Multipart,
    state: web::Data<AppState>,
) -> HttpResponse {
    let owner_key = client_key(&req);
    let max_upload = state.max_upload_bytes;

    let mut file_data: Option<Vec<u8>> = None;
    let mut filename = "archive".to_string();

    while let Some(mut field) = payload.try_next().await.unwrap_or(None) {
        let cd = field.content_disposition();
        let name = cd
            .map(|c| c.get_name().unwrap_or("").to_string())
            .unwrap_or_default();
        let field_filename = cd.and_then(|c| c.get_filename().map(|s| s.to_string()));

        let mut data = Vec::new();
        while let Some(chunk) = field.try_next().await.unwrap_or(None) {
            if data.len() + chunk.len() > max_upload {
                return HttpResponse::PayloadTooLarge().json(serde_json::json!({
                    "error": format!("Payload too large (max {} MB)", max_upload / (1024 * 1024))
                }));
            }
            data.extend_from_slice(&chunk);
        }

        if name == "file" {
            filename = field_filename.unwrap_or_else(|| "archive".into());
            file_data = Some(data);
        }
    }

    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => {
            log::warn!("Salvage request with no file data");
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "No file uploaded."}));
        }
    };

    log::info!(
        "\x1b[1;36m▸ Upload\x1b[0m {} ({} bytes)",
        filename,
        data.len()
    );

    let task_id = match new_task(state.get_ref(), &owner_key) {
        Some(id) => id,
        None => {
            return HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "Too many concurrent tasks. Please wait."
            }));
        }
    };

    {
        let mut tasks = state.tasks.write();
        if let Some(t) = tasks.get_mut(&task_id) {
            t.filename = Some(filename.clone());
        }
    }

    state.total_uploads.fetch_add(1, Ordering::Relaxed);
    state
        .total_bytes_processed
        .fetch_add(data.len() as u64, Ordering::Relaxed);

    let watcher_state = state.clone();
    let state_clone = state.into_inner().clone();
    let tid = task_id.clone();

    let join_handle = tokio::task::spawn_blocking(move || {
        let cb_state = state_clone.clone();
        let cb_tid = tid.clone();
        let cb = move |phase: &str, pct: u32| {
            update_task(&cb_state, &cb_tid, |t| {
                t.phase = phase.to_string();
                t.percent = pct;
            });
        };

        log::info!(
            "\x1b[1;33m▸ Recovery\x1b[0m Starting engine on {} bytes",
            data.len()
        );
        let engine = SalvageEngine::new();
        let report = engine.salvage(&data, Some(&cb));
        log::info!(
            "\x1b[1;32m▸ Result\x1b[0m {} files recovered, {} bytes, type={}, method={}, rate={}%, time={}s",
            report.files_salvaged,
            report.total_salvaged_bytes,
            report.archive_type,
            report.method,
            report.salvage_rate_percent,
            report.salvage_time_secs
        );

        let zip_bytes = engine.pack_salvaged_zip(&report.files);
        let download_path = state_clone.download_dir.join(format!("{}.zip", tid));
        if let Err(e) = std::fs::write(&download_path, &zip_bytes) {
            log::error!("Failed to write salvage ZIP: {}", e);
        }
        drop(zip_bytes);

        state_clone
            .total_files_recovered
            .fetch_add(report.files_salvaged as u64, Ordering::Relaxed);

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

        let response = serde_json::json!({
            "success": true,
            "filename": filename,
            "input_size": report.input_size,
            "archive_type": report.archive_type,
            "total_files_found": report.total_files_found,
            "files_salvaged": report.files_salvaged,
            "total_salvaged_bytes": report.total_salvaged_bytes,
            "corruption_bypassed": report.corruption_bypassed,
            "crc_errors_ignored": report.crc_errors_ignored,
            "lzma_errors_bypassed": report.lzma_errors_bypassed,
            "salvage_rate_percent": report.salvage_rate_percent,
            "overall_confidence": report.overall_confidence,
            "type_breakdown": report.type_breakdown,
            "files": file_list,
            "salvage_time_secs": report.salvage_time_secs,
            "method": report.method,
            "zombie_stats": {
                "resync_count": report.zombie_resync_count,
                "bytes_tainted": report.zombie_bytes_tainted,
                "bytes_zeroed": report.zombie_bytes_zeroed,
                "entropy_rejections": report.zombie_entropy_rejections,
            },
            "download_url": format!("/api/download/{}", tid),
        });

        update_task(&state_clone, &tid, |t| {
            t.status = "done".to_string();
            t.percent = 100;
            t.phase = "Complete".to_string();
            t.result = Some(response);
            t.download_path = Some(download_path);
        });
    });

    let watcher_tid = task_id.clone();
    tokio::spawn(async move {
        if let Err(e) = join_handle.await {
            log::error!("Salvage task panicked: {}", e);
            update_task(watcher_state.get_ref(), &watcher_tid, |t| {
                t.status = "error".to_string();
                t.error = Some("Internal engine error (task panicked)".to_string());
            });
        }
    });

    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id}))
}

async fn serve_index(state: web::Data<AppState>) -> HttpResponse {
    let index_path = state.static_dir.join("index.html");
    match tokio::fs::read_to_string(&index_path).await {
        Ok(content) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(content),
        Err(_) => HttpResponse::Ok()
            .content_type("text/html")
            .body("<h1>Helix Salvager — static/index.html not found</h1>"),
    }
}

async fn api_download(
    path: web::Path<String>,
    state: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let task_id = path.into_inner();
    let owner = client_key(&req);

    let download_path = {
        let tasks = state.tasks.read();
        match tasks.get(&task_id) {
            Some(t) if t.owner == owner && t.status == "done" => t.download_path.clone(),
            Some(t) if t.owner != owner => {
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "Access denied"}));
            }
            _ => None,
        }
    };

    match download_path {
        Some(p) => match tokio::fs::metadata(&p).await {
            Ok(_) => match tokio::fs::read(&p).await {
                Ok(bytes) => HttpResponse::Ok()
                    .content_type("application/zip")
                    .insert_header((
                        "Content-Disposition",
                        format!("attachment; filename=\"salvaged_{}.zip\"", task_id),
                    ))
                    .body(bytes),
                Err(_) => HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": "Failed to read download file"})),
            },
            Err(_) => HttpResponse::NotFound()
                .json(serde_json::json!({"error": "Download file not found"})),
        },
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "Download not available"})),
    }
}

async fn api_delete_task(
    path: web::Path<String>,
    state: web::Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    let task_id = path.into_inner();
    let owner = client_key(&req);

    let mut tasks = state.tasks.write();
    match tasks.get(&task_id) {
        Some(t) if t.owner == owner => {
            if let Some(path) = &t.download_path {
                let _ = std::fs::remove_file(path);
            }
            tasks.remove(&task_id);
            HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
        }
        Some(_) => HttpResponse::Forbidden().json(serde_json::json!({"error": "Access denied"})),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Task not found"})),
    }
}

// ═══════════════════════════════════════════════════════
//  BANNER
// ═══════════════════════════════════════════════════════

fn print_banner(bind: &str, port: u16, args: &ServerArgs, workers: usize) {
    if args.no_color {
        eprintln!();
        eprintln!("    ██╗  ██╗███████╗██╗     ██╗██╗  ██╗");
        eprintln!("    ██║  ██║██╔════╝██║     ██║╚██╗██╔╝");
        eprintln!("    ███████║█████╗  ██║     ██║ ╚███╔╝ ");
        eprintln!("    ██╔══██║██╔══╝  ██║     ██║ ██╔██╗ ");
        eprintln!("    ██║  ██║███████╗███████╗██║██╔╝ ██╗");
        eprintln!("    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝");
        eprintln!("    SALVAGER v2.0 | Corrupt Archive Recovery Server");
        eprintln!();
        eprintln!("    Server : http://{}:{}", bind, port);
        eprintln!(
            "    Workers: {}  |  Upload: {} MB  |  Verbose: {}",
            workers, args.max_upload_mb, args.verbose
        );
        eprintln!(
            "    Tasks  : {} max  |  Retention: {} min",
            args.max_tasks, args.task_retention
        );
        eprintln!();
    } else {
        eprintln!();
        eprintln!("    {}", "██╗  ██╗███████╗██╗     ██╗██╗  ██╗".red().bold());
        eprintln!("    {}", "██║  ██║██╔════╝██║     ██║╚██╗██╔╝".red().bold());
        eprintln!(
            "    {}",
            "███████║█████╗  ██║     ██║ ╚███╔╝ ".yellow().bold()
        );
        eprintln!(
            "    {}",
            "██╔══██║██╔══╝  ██║     ██║ ██╔██╗ ".yellow().bold()
        );
        eprintln!("    {}", "██║  ██║███████╗███████╗██║██╔╝ ██╗".red());
        eprintln!("    {}", "╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝".red());
        eprintln!(
            "    {} {} {} {}",
            "SALVAGER".white().bold(),
            "v2.0".dimmed(),
            "│".dimmed(),
            "Corrupt Archive Recovery Server".dimmed()
        );
        eprintln!();
        eprintln!(
            "    {} {}",
            "▸".green().bold(),
            format!("http://{}:{}", bind, port).green().bold()
        );
        eprintln!();
        eprintln!(
            "    {}  {}   {}  {}",
            "Workers".dimmed(),
            workers.to_string().white().bold(),
            "Upload".dimmed(),
            format!("{} MB", args.max_upload_mb).white()
        );
        eprintln!(
            "    {}  {}   {}  {}",
            "Verbose".dimmed(),
            format!("level {}", args.verbose).white(),
            "Tasks ".dimmed(),
            format!(
                "{} max / {} min retention",
                args.max_tasks, args.task_retention
            )
            .white()
        );
        eprintln!();
        eprintln!("    {}", "Engines".cyan().bold());
        eprintln!(
            "    {} Fail-Forward ZIP     {} Zombie LZMA Decoder",
            "●".red().bold(),
            "●".yellow().bold()
        );
        eprintln!(
            "    {} AhoCorasick 29-sig   {} RAR v4/v5 Parser",
            "●".cyan().bold(),
            "●".purple().bold()
        );
        eprintln!(
            "    {} SHA-256 Dedup        {} GZIP/BZIP2/XZ/TAR",
            "●".green().bold(),
            "●".blue().bold()
        );
        eprintln!(
            "    {} Deep Validation      {} Plugin System",
            "●".red(),
            "●".yellow()
        );
        eprintln!(
            "    {} Parallel Recovery    {} Disk Image / Streaming",
            "●".cyan(),
            "●".green()
        );
        eprintln!();
    }
}

fn get_num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// ═══════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = ServerArgs::parse();

    let log_filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "info,actix_web=debug",
        _ => "debug,actix_web=trace",
    };
    env_logger::init_from_env(env_logger::Env::new().default_filter_or(log_filter));

    let logger = VerboseLogger::new(args.verbose, args.no_color);

    // ── Resolve port ──
    let port = if args.random_port {
        let p = find_random_port(&args.bind).map_err(|e| {
            logger.error(&format!("Cannot find random port: {e}"));
            e
        })?;
        logger.info(&format!("Selected random port: {p}"));
        p
    } else {
        args.port
    };

    // ── Port conflict handling ──
    if !is_port_available(&args.bind, port) {
        logger.warn(&format!("Port {port} is already in use!"));
        show_port_info(port, &logger);

        if args.kill_port {
            if !kill_port_processes(port, &logger) {
                logger.error("Could not free port. Try --port <N> or --random-port");
                std::process::exit(1);
            }
        } else {
            logger.error(&format!(
                "Port {port} in use. Options:\n  \
                 1. --kill-port to kill the process\n  \
                 2. --port <N> for a different port\n  \
                 3. --random-port for auto-selection"
            ));
            std::process::exit(1);
        }
    }

    // ── Resolve directories ──
    let static_dir = args
        .static_dir
        .as_ref()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .or_else(|| {
            let cwd = PathBuf::from("static");
            if cwd.is_dir() {
                Some(cwd)
            } else {
                None
            }
        })
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|p| p.join("static")))
                .filter(|p| p.is_dir())
        })
        .or_else(|| {
            let crate_static = PathBuf::from("crates/salvager-server/static");
            if crate_static.is_dir() {
                Some(crate_static)
            } else {
                None
            }
        })
        .unwrap_or_else(|| PathBuf::from("static"));

    let download_dir = args
        .download_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("salvager_downloads"));
    std::fs::create_dir_all(&download_dir)?;

    logger.detail(&format!("Static dir: {}", static_dir.display()));
    logger.detail(&format!("Download dir: {}", download_dir.display()));

    let max_upload_bytes = args.max_upload_mb * 1024 * 1024;
    let worker_count = args.workers.unwrap_or_else(get_num_cpus);

    let state = web::Data::new(AppState {
        tasks: RwLock::new(HashMap::new()),
        download_dir,
        static_dir: static_dir.clone(),
        max_upload_bytes,
        max_tasks: args.max_tasks,
        task_retention_secs: args.task_retention * 60,
        start_time: Instant::now(),
        total_uploads: AtomicU64::new(0),
        total_files_recovered: AtomicU64::new(0),
        total_bytes_processed: AtomicU64::new(0),
    });

    print_banner(&args.bind, port, &args, worker_count);

    if args.open {
        let url = format!("http://{}:{}", args.bind, port);
        logger.info(&format!("Opening browser: {url}"));
        let _ = open_browser(&url);
    }

    let bind_addr = format!("{}:{}", args.bind, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(max_upload_bytes))
            .route("/", web::get().to(serve_index))
            .route("/api/health", web::get().to(api_health))
            .route("/api/stats", web::get().to(api_stats))
            .route("/api/tasks", web::get().to(api_tasks))
            .route("/api/progress/{task_id}", web::get().to(api_progress))
            .route("/api/salvage", web::post().to(api_salvage))
            .route("/api/download/{task_id}", web::get().to(api_download))
            .route("/api/task/{task_id}", web::delete().to(api_delete_task))
            .service(fs::Files::new("/static", &static_dir))
    })
    .bind(&bind_addr)?
    .workers(worker_count)
    .run()
    .await
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()?;
    }
    Ok(())
}
