/* ═══════════ HELIX SALVAGER v2.0 — Client Engine ═══════════ */

// ─── State ───
let pollTimer = null;
let elapsedTimer = null;
let startTime = null;
let progressLogs = [];
let dashTimer = null;
let currentFiles = [];

const THEME_KEY = 'helix_theme';
const SESSION_KEY = 'helix_session';

function getSession() {
    let id = localStorage.getItem(SESSION_KEY);
    if (!id) {
        id = crypto.randomUUID ? crypto.randomUUID() : 'sess_' + Date.now() + '_' + Math.random().toString(36).slice(2);
        id = id.replace(/[^a-zA-Z0-9_-]/g, '');
        localStorage.setItem(SESSION_KEY, id);
    }
    return id;
}
const SID = getSession();

// ─── Utils ───
const $ = id => document.getElementById(id);
const show = el => el.classList.remove('hidden');
const hide = el => el.classList.add('hidden');
const headers = () => ({ 'x-salvager-session': SID });

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function fmtB(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(2) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
}

function fmtUp(s) {
    if (s < 60) return s + 's';
    if (s < 3600) {
        const m = Math.floor(s / 60), r = s % 60;
        return m + 'm ' + (r > 0 ? r + 's' : '');
    }
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + 'h ' + m + 'm';
}

// ═══════════ THEME ═══════════

function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    $('themeToggle').addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme');
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem(THEME_KEY, next);
    });
}

// ═══════════ COLLAPSIBLES ═══════════

function initCollapsibles() {
    document.querySelectorAll('.panel-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = $(btn.dataset.target);
            if (target) {
                btn.classList.toggle('collapsed');
                target.classList.toggle('collapsed');
            }
        });
    });
}

// ═══════════ DASHBOARD ═══════════

async function fetchDash() {
    try {
        const r = await fetch('/api/stats', { headers: headers() });
        if (!r.ok) throw 0;
        const d = await r.json();
        $('dashUptime').textContent = fmtUp(d.uptime_secs || 0);
        $('dashUploads').textContent = d.total_uploads || 0;
        $('dashRecovered').textContent = d.total_files_recovered || 0;
        $('dashBytes').textContent = fmtB(d.total_bytes_processed || 0);
        $('dashRunning').textContent = d.tasks_running || 0;
        $('dashCompleted').textContent = d.tasks_completed || 0;

        const chip = $('serverChip');
        chip.classList.add('online');
        $('serverStatus').textContent = 'Online';
    } catch {
        const chip = $('serverChip');
        chip.classList.remove('online');
        $('serverStatus').textContent = 'Offline';
    }
}

function startDash() {
    fetchDash();
    dashTimer = setInterval(fetchDash, 3000);
}

// ═══════════ TASK HISTORY ═══════════

async function fetchHistory() {
    try {
        const r = await fetch('/api/tasks', { headers: headers() });
        if (!r.ok) return;
        const d = await r.json();
        renderHistory(d.tasks || []);
    } catch { /* */ }
}

function renderHistory(tasks) {
    const el = $('historyList');
    if (!tasks.length) {
        el.innerHTML = `<div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="empty-icon"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
            <p>No recovery tasks yet</p><span>Upload a corrupt archive to begin</span></div>`;
        return;
    }
    el.innerHTML = tasks.map(t => {
        const cls = t.status === 'done' ? 'done' : t.status === 'error' ? 'error' : 'running';
        return `<div class="history-item">
            <div class="hist-left">
                <span class="hist-dot ${cls}"></span>
                <span class="hist-name">${esc(t.filename || 'Unknown')}</span>
                <span class="hist-meta">${t.status} &middot; ${t.percent || 0}%</span>
            </div>
            <button class="hist-del" onclick="deleteTask('${t.id}')" title="Remove">&times;</button>
        </div>`;
    }).join('');
}

async function deleteTask(id) {
    try {
        await fetch(`/api/task/${id}`, { method: 'DELETE', headers: headers() });
        fetchHistory();
        fetchDash();
    } catch { /* */ }
}

// ═══════════ HEX PREVIEW ═══════════

function showHex(file) {
    const reader = new FileReader();
    reader.onload = function () {
        const bytes = new Uint8Array(reader.result);
        const len = Math.min(bytes.length, 256);

        // Magic detection
        let magic = 'Unknown';
        if (bytes[0] === 0x50 && bytes[1] === 0x4B) magic = 'ZIP (PK\\x03\\x04)';
        else if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC) magic = '7-Zip';
        else if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72) magic = 'RAR';
        else if (bytes[0] === 0x1F && bytes[1] === 0x8B) magic = 'GZIP';
        else if (bytes[0] === 0xFD && bytes[1] === 0x37 && bytes[2] === 0x7A) magic = 'XZ';
        else if (bytes[0] === 0x42 && bytes[1] === 0x5A && bytes[2] === 0x68) magic = 'BZIP2';
        else if (bytes[0] === 0xFF && bytes[1] === 0xD8) magic = 'JPEG';
        else if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E) magic = 'PNG';
        else if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44) magic = 'PDF';
        $('hexMagic').textContent = magic;

        let html = '';
        for (let row = 0; row < len; row += 16) {
            let line = `<span class="hx-off">${row.toString(16).padStart(8, '0')}</span>  `;
            let ascii = '';
            for (let c = 0; c < 16; c++) {
                const i = row + c;
                if (i < len) {
                    const b = bytes[i];
                    const hx = b.toString(16).padStart(2, '0');
                    let cls = 'hx-n';
                    if (b === 0) cls = 'hx-0';
                    else if (b >= 0x80) cls = 'hx-h';
                    else if (b >= 0x20 && b <= 0x7e) cls = 'hx-a';
                    line += `<span class="${cls}">${hx}</span> `;
                    ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
                } else {
                    line += '   ';
                    ascii += ' ';
                }
                if (c === 7) line += ' ';
            }
            line += `<span class="hx-asc">${esc(ascii)}</span>`;
            html += line + '\n';
        }
        $('hexContent').innerHTML = html;
        show($('hexPreview'));
    };
    reader.readAsArrayBuffer(file.slice(0, 256));
}

// ═══════════ PROGRESS ═══════════

const STEPS = ['Upload', 'Decompress', 'Scan Headers', 'Carve Files', 'Pack Results'];

function showProgress(title) {
    $('progressTitle').textContent = title;
    $('progressBar').style.width = '0%';
    $('progressPercent').textContent = '0%';
    $('progressElapsed').textContent = '0.0s';
    $('progressPhase').textContent = 'Initializing engine...';
    $('progressLog').innerHTML = '';
    progressLogs = [];

    $('progressSteps').innerHTML = STEPS.map((s, i) =>
        `<div class="pstep" id="pstep${i}">${s}</div>`
    ).join('');

    startTime = Date.now();
    show($('progressOverlay'));
    elapsedTimer = setInterval(() => {
        $('progressElapsed').textContent = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
    }, 100);
}

function updateProgress(d) {
    const pct = d.percent || 0;
    $('progressBar').style.width = pct + '%';
    $('progressPercent').textContent = pct + '%';
    const phase = d.phase || '';
    $('progressPhase').textContent = phase;

    if (phase && (!progressLogs.length || progressLogs[progressLogs.length - 1].m !== phase)) {
        const t = ((Date.now() - startTime) / 1000).toFixed(1);
        progressLogs.push({ t, m: phase });
        $('progressLog').innerHTML = progressLogs.map(l =>
            `<div class="log-line"><span class="log-ts">[${l.t}s]</span>${l.m}</div>`
        ).join('');
        $('progressLog').scrollTop = $('progressLog').scrollHeight;
    }

    const th = [2, 25, 40, 60, 85];
    STEPS.forEach((_, i) => {
        const el = $('pstep' + i);
        if (!el) return;
        if (pct >= (th[i + 1] || 100)) el.className = 'pstep done';
        else if (pct >= th[i]) el.className = 'pstep active';
        else el.className = 'pstep';
    });
}

function hideProgress() {
    hide($('progressOverlay'));
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

function pollTask(taskId, onDone) {
    pollTimer = setInterval(async () => {
        try {
            const r = await fetch(`/api/progress/${taskId}`, { headers: headers() });
            const d = await r.json();
            updateProgress(d);
            if (d.status === 'done') {
                clearInterval(pollTimer); pollTimer = null;
                setTimeout(() => { hideProgress(); onDone(d.result); fetchHistory(); fetchDash(); }, 250);
            } else if (d.status === 'error') {
                clearInterval(pollTimer); pollTimer = null;
                hideProgress();
                alert('Recovery error: ' + (d.error || 'Unknown'));
                fetchHistory();
            }
        } catch { /* retry */ }
    }, 200);
}

// ═══════════ FILE HANDLERS ═══════════

function onFileSelect() {
    const f = $('fileInput').files[0];
    if (!f) return;
    $('fileName').textContent = f.name;
    $('fileSize').textContent = fmtB(f.size);
    show($('fileInfo'));
    hide($('dropContent'));
    showHex(f);
}

function clearFile() {
    $('fileInput').value = '';
    hide($('fileInfo'));
    hide($('hexPreview'));
    show($('dropContent'));
}

async function doSalvage() {
    const file = $('fileInput').files[0];
    if (!file) { alert('Select a corrupt archive first'); return; }

    showProgress('RECOVERING');

    try {
        const res = await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            const fd = new FormData();
            fd.append('file', file);

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round(e.loaded / e.total * 100);
                    $('progressPhase').textContent = `Uploading ${fmtB(e.loaded)} / ${fmtB(e.total)}`;
                    $('progressBar').style.width = (pct * 0.2) + '%';
                    $('progressPercent').textContent = Math.round(pct * 0.2) + '%';
                }
            };
            xhr.onload = () => {
                if (xhr.status === 200) resolve(JSON.parse(xhr.responseText));
                else reject(xhr.statusText || 'Upload failed');
            };
            xhr.onerror = () => reject('Network error');
            xhr.open('POST', '/api/salvage');
            xhr.setRequestHeader('x-salvager-session', SID);
            xhr.send(fd);
        });

        if (res.task_id) {
            pollTask(res.task_id, showResults);
        } else if (res.error) {
            hideProgress();
            alert('Error: ' + res.error);
        }
    } catch (e) {
        hideProgress();
        alert('Failed: ' + e);
    }
}

// ═══════════ RESULTS ═══════════

function showResults(data) {
    if (!data || !data.success) { alert('Recovery failed'); return; }

    $('resultTime').textContent = data.salvage_time_secs + 's';

    const stats = [
        { v: fmtB(data.input_size), l: 'Input Size' },
        { v: data.archive_type.toUpperCase(), l: 'Archive Type', c: 'color:var(--cyan)' },
        { v: data.files_salvaged, l: 'Files Recovered', c: 'color:var(--green)' },
        { v: fmtB(data.total_salvaged_bytes), l: 'Data Recovered', c: 'color:var(--green)' },
        { v: data.corruption_bypassed, l: 'Errors Bypassed', c: 'color:var(--amber)' },
        { v: data.crc_errors_ignored, l: 'CRC Bypassed', c: 'color:var(--red)' },
        { v: data.lzma_errors_bypassed, l: 'LZMA Bypassed', c: 'color:var(--red)' },
        { v: data.salvage_rate_percent + '%', l: 'Recovery Rate', c: 'color:var(--cyan)' },
        { v: data.method, l: 'Strategy', c: 'color:var(--purple);font-size:0.8rem' },
    ];
    $('statsGrid').innerHTML = stats.map(s =>
        `<div class="stat-card"><div class="stat-val" style="${s.c || ''}">${s.v}</div><div class="stat-lbl">${s.l}</div></div>`
    ).join('');

    // Zombie stats
    if (data.zombie_stats) {
        const z = data.zombie_stats;
        if (z.resync_count > 0 || z.bytes_tainted > 0 || z.bytes_zeroed > 0 || z.entropy_rejections > 0) {
            $('zombieGrid').innerHTML = [
                { v: z.resync_count, l: 'Resyncs', c: 'color:var(--red)' },
                { v: fmtB(z.bytes_tainted), l: 'Tainted', c: 'color:var(--amber)' },
                { v: fmtB(z.bytes_zeroed), l: 'Zeroed', c: 'color:var(--text-3)' },
                { v: z.entropy_rejections, l: 'Entropy Rej', c: 'color:var(--purple)' },
            ].map(i => `<div class="zombie-item"><div class="zombie-val" style="${i.c}">${i.v}</div><div class="zombie-lbl">${i.l}</div></div>`).join('');
            show($('zombieSection'));
        } else {
            hide($('zombieSection'));
        }
    }

    // Breakdown
    if (data.type_breakdown && data.type_breakdown.length) {
        $('breakdown').innerHTML = data.type_breakdown.map(t =>
            `<div class="type-tag">${esc(t.file_type)} <span class="type-count">&times;${t.count}</span> (${fmtB(t.total_bytes)})</div>`
        ).join('');
    }

    // Files
    currentFiles = data.files || [];
    renderFiles(currentFiles);

    // Download
    if (data.download_url) {
        const dl = $('downloadLink');
        dl.href = data.download_url;
        dl.download = 'salvaged_' + (data.filename || 'files') + '.zip';
        show(dl);
    }

    show($('salvageResults'));
    $('salvageResults').scrollIntoView({ behavior: 'smooth' });
}

function renderFiles(files) {
    if (!files || !files.length) {
        $('fileBody').innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-3);padding:1.5rem">No files recovered</td></tr>';
        return;
    }
    $('fileBody').innerHTML = files.map(f => {
        const ext = (f.extension || '').toLowerCase();
        const cls = 'ft-' + ext;
        return `<tr>
            <td>${f.index}</td>
            <td class="${cls}">${esc(f.file_type)}</td>
            <td class="mono-sm">.${esc(f.extension)}</td>
            <td class="mono-sm">${fmtB(f.size)}</td>
            <td class="mono-sm">0x${f.offset.toString(16).toUpperCase()}</td>
            <td class="mono-sm" title="${f.sha256}">${f.sha256.slice(0, 16)}&hellip;</td>
        </tr>`;
    }).join('');
}

function initFilter() {
    $('fileFilter').addEventListener('input', e => {
        const q = e.target.value.toLowerCase().trim();
        if (!q) { renderFiles(currentFiles); return; }
        renderFiles(currentFiles.filter(f =>
            (f.file_type || '').toLowerCase().includes(q) ||
            (f.extension || '').toLowerCase().includes(q) ||
            (f.sha256 || '').toLowerCase().includes(q)
        ));
    });
}

// ═══════════ INIT ═══════════

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initCollapsibles();
    initFilter();

    $('browseLink').addEventListener('click', e => { e.preventDefault(); $('fileInput').click(); });
    $('fileInput').addEventListener('change', onFileSelect);
    $('fileClear').addEventListener('click', clearFile);
    $('salvageBtn').addEventListener('click', doSalvage);

    const dz = $('dropZone');
    dz.addEventListener('click', e => {
        if (e.target.closest('.file-chip') || e.target.closest('.chip-clear')) return;
        $('fileInput').click();
    });
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', e => {
        e.preventDefault();
        dz.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            $('fileInput').files = e.dataTransfer.files;
            onFileSelect();
        }
    });

    startDash();
    fetchHistory();
});
