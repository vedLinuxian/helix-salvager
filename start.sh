#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  HELIX SALVAGER v2.0 — Advanced Launcher
#  Corrupt Archive Recovery Engine | Rust + Actix-Web
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Colors & Formatting ───
R='\033[0;31m'    BR='\033[1;31m'
G='\033[0;32m'    BG='\033[1;32m'
Y='\033[0;33m'    BY='\033[1;33m'
B='\033[0;34m'    BB='\033[1;34m'
P='\033[0;35m'    BP='\033[1;35m'
C='\033[0;36m'    BC='\033[1;36m'
W='\033[1;37m'    D='\033[2m'
UL='\033[4m'      N='\033[0m'

# ─── Defaults ───
PORT="${PORT:-5001}"
BIND="${BIND:-127.0.0.1}"
MODE="${MODE:-server}"
VERBOSE="${VERBOSE:-1}"
MAX_UPLOAD="${MAX_UPLOAD:-256}"
WORKERS="${WORKERS:-0}"
OPEN_BROWSER="${OPEN_BROWSER:-false}"
KILL_PORT="${KILL_PORT:-false}"
RANDOM_PORT="${RANDOM_PORT:-false}"
BUILD_FIRST="${BUILD_FIRST:-false}"
RELEASE="${RELEASE:-false}"
SHOW_PORTS="${SHOW_PORTS:-false}"
LIST_PORT=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Logging Helpers ───
timestamp() { date '+%H:%M:%S'; }

log_info()    { echo -e "${D}[$(timestamp)]${N} ${BG} INFO ${N}  $*"; }
log_detail()  { [[ "$VERBOSE" -ge 2 ]] && echo -e "${D}[$(timestamp)]${N} ${BC} DTAIL${N}  $*" || true; }
log_trace()   { [[ "$VERBOSE" -ge 3 ]] && echo -e "${D}[$(timestamp)]${N} ${BP} TRACE${N}  $*" || true; }
log_warn()    { echo -e "${D}[$(timestamp)]${N} ${BY} WARN ${N}  ${Y}$*${N}"; }
log_error()   { echo -e "${D}[$(timestamp)]${N} ${BR} ERROR${N}  ${R}$*${N}"; }
log_success() { echo -e "${D}[$(timestamp)]${N} ${BG}  OK  ${N}  ${G}$*${N}"; }

# ─── ASCII Art Banner ───
print_banner() {
    echo ""
    echo -e "${BR}    ██╗  ██╗███████╗██╗     ██╗██╗  ██╗${N}"
    echo -e "${BR}    ██║  ██║██╔════╝██║     ██║╚██╗██╔╝${N}"
    echo -e "${BY}    ███████║█████╗  ██║     ██║ ╚███╔╝ ${N}"
    echo -e "${BY}    ██╔══██║██╔══╝  ██║     ██║ ██╔██╗ ${N}"
    echo -e "${R}    ██║  ██║███████╗███████╗██║██╔╝ ██╗${N}"
    echo -e "${R}    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝${N}"
    echo -e "${D}    ┌─────────────────────────────────────────┐${N}"
    echo -e "${D}    │${N}  ${W}SALVAGER${N} ${D}v2.0${N}  ${D}│${N} ${C}Corrupt Archive Recovery${N} ${D}│${N}"
    echo -e "${D}    └─────────────────────────────────────────┘${N}"
    echo ""
    echo -e "    ${D}Engines${N}"
    echo -e "    ${R}●${N} Fail-Forward ZIP    ${Y}●${N} Zombie LZMA Decoder"
    echo -e "    ${C}●${N} AhoCorasick 29-sig  ${P}●${N} Shannon Entropy Gate"
    echo -e "    ${G}●${N} SHA-256 Dedup       ${B}●${N} GZIP/BZIP2/XZ/TAR"
    echo ""
}

# ─── Help ───
print_help() {
    print_banner
    echo -e "${W}USAGE${N}"
    echo -e "  ${G}./start.sh${N} [OPTIONS]"
    echo ""
    echo -e "${W}MODES${N}  ${D}(-m/--mode)${N}"
    echo -e "  ${G}server${N}   Start web UI server ${D}(default)${N}"
    echo -e "  ${G}cli${N}      Run CLI recovery tool"
    echo -e "  ${G}build${N}    Build the project"
    echo -e "  ${G}test${N}     Run full test suite"
    echo -e "  ${G}check${N}    Run cargo check + clippy"
    echo ""
    echo -e "${W}SERVER OPTIONS${N}"
    echo -e "  ${C}-p, --port${N} PORT        Server port ${D}(default: 5001)${N}"
    echo -e "  ${C}    --random-port${N}       Pick a random available port"
    echo -e "  ${C}    --kill-port${N}          Kill process on target port first"
    echo -e "  ${C}    --show-ports${N}         Show all salvager processes & ports"
    echo -e "  ${C}    --list-port${N} PORT     Show who's using a specific port"
    echo -e "  ${C}-b, --bind${N} ADDR         Bind address ${D}(default: 127.0.0.1)${N}"
    echo -e "  ${C}-w, --workers${N} N          Worker threads ${D}(default: auto)${N}"
    echo -e "  ${C}    --max-upload${N} MB      Max upload size ${D}(default: 256)${N}"
    echo -e "  ${C}    --open${N}               Open browser after start"
    echo ""
    echo -e "${W}BUILD OPTIONS${N}"
    echo -e "  ${C}    --build-first${N}        Build before running"
    echo -e "  ${C}    --release${N}            Release mode (optimized)"
    echo ""
    echo -e "${W}LOGGING${N}"
    echo -e "  ${C}-v, --verbose${N} LEVEL      0=quiet 1=info 2=detail 3=trace ${D}(default: 1)${N}"
    echo ""
    echo -e "${W}GENERAL${N}"
    echo -e "  ${C}-h, --help${N}              Show this help"
    echo ""
    echo -e "${W}EXAMPLES${N}"
    echo -e "  ${D}\$${N} ./start.sh                                ${D}# Server on :5001${N}"
    echo -e "  ${D}\$${N} ./start.sh -p 8080 --open                 ${D}# Port 8080, open browser${N}"
    echo -e "  ${D}\$${N} ./start.sh --random-port -v 3             ${D}# Random port, trace logs${N}"
    echo -e "  ${D}\$${N} ./start.sh --kill-port -p 5001            ${D}# Kill :5001 user, then start${N}"
    echo -e "  ${D}\$${N} ./start.sh --show-ports                   ${D}# List active salvager procs${N}"
    echo -e "  ${D}\$${N} ./start.sh --list-port 8080               ${D}# Who's on port 8080?${N}"
    echo -e "  ${D}\$${N} ./start.sh -m cli -- recover broken.zip   ${D}# CLI recovery${N}"
    echo -e "  ${D}\$${N} ./start.sh -m build --release             ${D}# Release build${N}"
    echo -e "  ${D}\$${N} ./start.sh -m test                        ${D}# Run all tests${N}"
    echo ""
    echo -e "${W}ENVIRONMENT VARIABLES${N}"
    echo -e "  PORT  BIND  MODE  VERBOSE  MAX_UPLOAD  WORKERS"
    echo -e "  OPEN_BROWSER=true  KILL_PORT=true  RANDOM_PORT=true"
    echo ""
}

# ─── Parse Args ───
CLI_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)       MODE="$2"; shift 2 ;;
        -p|--port)       PORT="$2"; shift 2 ;;
        -b|--bind)       BIND="$2"; shift 2 ;;
        -v|--verbose)    VERBOSE="$2"; shift 2 ;;
        -w|--workers)    WORKERS="$2"; shift 2 ;;
        --max-upload)    MAX_UPLOAD="$2"; shift 2 ;;
        --open)          OPEN_BROWSER="true"; shift ;;
        --kill-port)     KILL_PORT="true"; shift ;;
        --random-port)   RANDOM_PORT="true"; shift ;;
        --build-first)   BUILD_FIRST="true"; shift ;;
        --release)       RELEASE="true"; shift ;;
        --show-ports)    SHOW_PORTS="true"; shift ;;
        --list-port)     LIST_PORT="$2"; shift 2 ;;
        -h|--help)       print_help; exit 0 ;;
        --)              shift; CLI_ARGS+=("$@"); break ;;
        *)               CLI_ARGS+=("$1"); shift ;;
    esac
done

# ─── System Info ───
print_sysinfo() {
    local rust_ver
    rust_ver=$(rustc --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "?")
    local cores
    cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "?")
    local mem
    mem=$(free -h 2>/dev/null | awk '/Mem:/{print $2}' || echo "?")

    echo -e "  ${D}System${N}"
    echo -e "    ${D}Rust   :${N} $rust_ver"
    echo -e "    ${D}Cores  :${N} $cores"
    echo -e "    ${D}Memory :${N} $mem"
    echo -e "    ${D}Dir    :${N} ${D}$SCRIPT_DIR${N}"
    echo ""
}

# ─── Dependency Check ───
check_deps() {
    if ! command -v cargo &>/dev/null; then
        log_error "Cargo not found. Install Rust: ${UL}https://rustup.rs/${N}"
        exit 1
    fi
    log_detail "Rust toolchain found"
}

# ─── Port Utilities ───
is_port_free() {
    local port=$1
    if command -v ss &>/dev/null; then
        ! ss -tuln 2>/dev/null | grep -q ":${port} "
    elif command -v netstat &>/dev/null; then
        ! netstat -tuln 2>/dev/null | grep -q ":${port} "
    else
        python3 -c "
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(('127.0.0.1',${port}))
    s.close(); exit(0)
except: exit(1)
" 2>/dev/null
    fi
}

find_free_port() {
    python3 -c "
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('',0))
print(s.getsockname()[1])
s.close()
" 2>/dev/null || echo "5001"
}

show_port_info() {
    local port=$1
    echo -e "  ${W}Port $port usage:${N}"
    if command -v lsof &>/dev/null; then
        lsof -i ":${port}" -P -n 2>/dev/null | head -8 | while IFS= read -r line; do
            echo -e "    ${D}$line${N}"
        done
    elif command -v ss &>/dev/null; then
        ss -tulnp 2>/dev/null | grep ":${port} " | while IFS= read -r line; do
            echo -e "    ${D}$line${N}"
        done
    else
        echo -e "    ${D}(no lsof/ss available)${N}"
    fi
    echo ""
}

kill_port_users() {
    local port=$1
    log_warn "Killing processes on port $port..."

    if command -v lsof &>/dev/null; then
        local pids
        pids=$(lsof -t -i ":${port}" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            echo "$pids" | while IFS= read -r pid; do
                log_detail "Sending SIGKILL to PID $pid"
                kill -9 "$pid" 2>/dev/null || true
            done
            sleep 0.5
            if is_port_free "$port"; then
                log_success "Port $port is now free"
            else
                log_error "Failed to free port $port"
                exit 1
            fi
        else
            log_info "No process found on port $port"
        fi
    elif command -v fuser &>/dev/null; then
        fuser -k "${port}/tcp" 2>/dev/null || true
        sleep 0.5
        if is_port_free "$port"; then
            log_success "Port $port freed via fuser"
        else
            log_error "Failed to free port $port"
            exit 1
        fi
    else
        log_error "Cannot kill port: neither lsof nor fuser available"
        exit 1
    fi
}

show_salvager_procs() {
    echo -e "  ${W}Active Salvager processes:${N}"
    echo ""
    local found=0
    if command -v pgrep &>/dev/null; then
        pgrep -a "salvager" 2>/dev/null | while IFS= read -r line; do
            echo -e "    ${G}●${N} $line"
            found=1
        done
    fi
    if command -v lsof &>/dev/null; then
        echo ""
        echo -e "  ${W}Ports with salvager bindings:${N}"
        echo ""
        lsof -i -P -n 2>/dev/null | grep -i "salvager" | while IFS= read -r line; do
            echo -e "    ${C}●${N} $line"
            found=1
        done
    fi
    if [[ "$found" -eq 0 ]]; then
        echo -e "    ${D}No salvager processes found${N}"
    fi
    echo ""
}

# ─── Handle port-info commands ───
if [[ "$SHOW_PORTS" == "true" ]]; then
    print_banner
    show_salvager_procs
    exit 0
fi

if [[ -n "$LIST_PORT" ]]; then
    print_banner
    show_port_info "$LIST_PORT"
    exit 0
fi

# ─── Build ───
do_build() {
    local profile="dev" flag=""
    if [[ "$RELEASE" == "true" ]]; then
        profile="release"
        flag="--release"
    fi

    log_info "Building ${W}$profile${N} profile..."
    local start_time=$SECONDS

    cargo build $flag 2>&1 | while IFS= read -r line; do
        if [[ "$VERBOSE" -ge 2 ]]; then
            echo -e "    ${D}$line${N}"
        fi
    done

    local elapsed=$((SECONDS - start_time))
    log_success "Build complete in ${elapsed}s"
}

# ─── Server Mode ───
run_server() {
    if [[ "$BUILD_FIRST" == "true" ]]; then
        do_build
        echo ""
    fi

    # Port resolution
    if [[ "$RANDOM_PORT" == "true" ]]; then
        PORT=$(find_free_port)
        log_info "Random port selected: ${BG}$PORT${N}"
    fi

    log_detail "Checking port $PORT availability..."

    # Port conflict check
    if ! is_port_free "$PORT"; then
        log_warn "Port $PORT is already in use!"
        show_port_info "$PORT"

        if [[ "$KILL_PORT" == "true" ]]; then
            kill_port_users "$PORT"
        else
            echo -e "  ${W}Options:${N}"
            echo -e "    ${C}--kill-port${N}       Kill the process and take the port"
            echo -e "    ${C}--random-port${N}     Pick a random free port"
            echo -e "    ${C}-p PORT${N}           Use a different port"
            echo ""
            exit 1
        fi
    fi

    log_detail "Port $PORT is available"

    # Build server args
    local args=(--port "$PORT" --bind "$BIND" --verbose "$VERBOSE" --max-upload-mb "$MAX_UPLOAD" --max-tasks 8)

    if [[ "$WORKERS" != "0" ]]; then
        args+=(--workers "$WORKERS")
        log_detail "Using $WORKERS worker threads"
    fi

    if [[ "$OPEN_BROWSER" == "true" ]]; then
        args+=(--open)
        log_detail "Browser will open after start"
    fi

    # Determine binary
    local bin_path="target/debug/salvager-server"
    [[ "$RELEASE" == "true" ]] && bin_path="target/release/salvager-server"

    if [[ ! -f "$bin_path" ]]; then
        log_warn "Binary not found at $bin_path — building..."
        do_build
        echo ""
    fi

    echo -e "  ${D}╭──────────────────────────────────────────╮${N}"
    echo -e "  ${D}│${N}  ${W}Server${N}  ${G}http://${BIND}:${PORT}${N}$(printf '%*s' $((26 - ${#BIND} - ${#PORT})) '')${D}│${N}"
    echo -e "  ${D}│${N}  ${W}Mode${N}    ${D}$(printf '%-32s' "$([[ "$RELEASE" == "true" ]] && echo "release" || echo "debug")")${N}${D}│${N}"
    echo -e "  ${D}│${N}  ${W}Upload${N}  ${D}$(printf '%-30s' "${MAX_UPLOAD} MB max")${N}${D}│${N}"
    echo -e "  ${D}│${N}  ${W}Verbose${N} ${D}$(printf '%-29s' "level $VERBOSE")${N}${D}│${N}"
    echo -e "  ${D}╰──────────────────────────────────────────╯${N}"
    echo ""

    log_info "Starting server..."
    log_trace "Exec: $bin_path ${args[*]}"
    exec "$bin_path" "${args[@]}"
}

# ─── CLI Mode ───
run_cli() {
    if [[ "$BUILD_FIRST" == "true" ]]; then
        do_build
        echo ""
    fi

    local bin_path="target/debug/salvager"
    [[ "$RELEASE" == "true" ]] && bin_path="target/release/salvager"

    if [[ ! -f "$bin_path" ]]; then
        log_warn "Binary not found — building..."
        do_build
        echo ""
    fi

    log_info "Running CLI with args: ${CLI_ARGS[*]:-none}"
    exec "$bin_path" "${CLI_ARGS[@]}"
}

# ─── Test Mode ───
run_tests() {
    log_info "Running full test suite..."
    echo ""
    local start_time=$SECONDS

    cargo test --workspace -- --test-threads=4 2>&1 | while IFS= read -r line; do
        if echo "$line" | grep -q "^test .* ok$"; then
            echo -e "  ${G}✓${N} ${line#test }"
        elif echo "$line" | grep -q "^test .* FAILED$"; then
            echo -e "  ${R}✗${N} ${line#test }"
        elif echo "$line" | grep -q "^test result:"; then
            echo ""
            echo -e "  ${W}$line${N}"
        else
            [[ "$VERBOSE" -ge 2 ]] && echo -e "  ${D}$line${N}" || true
        fi
    done

    local elapsed=$((SECONDS - start_time))
    echo ""
    log_success "Tests completed in ${elapsed}s"
}

# ─── Check Mode ───
run_check() {
    log_info "Running ${W}cargo check${N}..."
    cargo check --workspace 2>&1 | tail -5
    echo ""
    log_info "Running ${W}clippy${N}..."
    cargo clippy --workspace 2>&1 | tail -5
    echo ""
    log_success "All checks passed"
}

# ═══════════ MAIN ═══════════

print_banner
check_deps
print_sysinfo

case "$MODE" in
    server)   run_server ;;
    cli)      run_cli ;;
    build)    do_build ;;
    test)     run_tests ;;
    check)    run_check ;;
    *)
        log_error "Unknown mode: $MODE"
        echo -e "  Valid modes: ${G}server${N} | ${G}cli${N} | ${G}build${N} | ${G}test${N} | ${G}check${N}"
        exit 1
        ;;
esac
