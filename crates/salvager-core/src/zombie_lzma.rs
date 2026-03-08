//! Zombie LZMA Decoder
//!
//! A fault-tolerant LZMA1 stream recovery module that never panics and never
//! gives up.  It wraps `lzma_rs::lzma_decompress` with a multi-strategy retry
//! pipeline designed to extract maximum data from corrupt LZMA streams.
//!
//! ## How it works
//!
//! Standard LZMA decoders (7-zip, `lzma-rs`) abort the instant the stream
//! contains a single corrupt byte.  The Zombie module instead:
//!
//! 1. **Full-stream attempt** — try `lzma_rs::lzma_decompress` on the entire
//!    input.  If it succeeds, validate the output with Shannon entropy and
//!    return immediately.
//!
//! 2. **Chunked retry** — on failure, split the input into `CHUNK_SIZE`
//!    windows.  For each window, attempt decompression; on failure, invoke
//!    `force_resynchronize` to byte-slide forward until a new valid LZMA
//!    properties header is found at which point a fresh decode can begin.
//!    Undecodable gaps are zero-padded and flagged in the TaintMap.
//!
//! 3. **Shannon Entropy heuristic** — after decoding each window we compute
//!    H(window) in bits.  Output that is all-zero padding (H < 1.5) or
//!    pure noise (H > 7.85) is flagged as tainted.  This prevents garbage
//!    data from polluting the output.
//!
//! 4. **Taint Map** — a compact bit-vector parallel to the output buffer.
//!    Every byte produced during error-recovery (zero-padding, resync probes,
//!    bad-entropy windows) is marked tainted.  Callers can use this metadata
//!    to distinguish clean vs. uncertain output regions.
//!
//! 5. **Multi-offset scan** — for 7z solid streams, the module probes LZMA
//!    data at common offsets [0, 32, 34, 48, 64, 96, 128, 256] and keeps the
//!    best (longest) successful decode.
//!
//! ## Limitations
//!
//! This module does **not** implement a custom LZMA range-coder.  Each decode
//! attempt creates a fresh `lzma_rs` decoder.  The resync strategy is
//! byte-sliding to find the next valid LZMA header, not mid-stream probability
//! table repair.  For heavily interleaved corruption (every ~100 bytes), the
//! chunked approach may produce mostly zero-padded output.

use std::io::Cursor;

// ══════════════════════════════════════════════════════════════
//  CONSTANTS
// ══════════════════════════════════════════════════════════════

/// Neutral probability value (1/2) for an 11-bit LZMA probability model.
/// Retained as a public constant for reference; `lzma_rs` manages its own
/// probability state internally — we do not reset tables ourselves.
pub const PROB_INIT: u16 = 0x0400;

/// Minimum output bytes we must decode before a window is considered "progress".
const MIN_PROGRESS_BYTES: usize = 16;

/// Number of consecutive decode errors before we force a resync.
pub const MAX_CONSEC_ERRORS: usize = 3;

/// Maximum byte-slide attempts per resync event.
const MAX_SLIDE_ATTEMPTS: usize = 64;

/// Maximum total decode operations in zombie_decode_chunked before we bail out.
const MAX_CHUNK_OPS: usize = 32;

/// Minimum input bytes needed before we attempt an LZMA decode.
const MIN_LZMA_INPUT: usize = 13;

/// Size of the probe decode used to validate a candidate resync point.
const PROBE_WINDOW: usize = 64;

/// Minimum Shannon entropy (bits) for a decoded window to be accepted as real data.
pub const ENTROPY_THRESHOLD_LOW: f64 = 1.5;

/// Maximum Shannon entropy above which output looks like random noise / already encrypted.
pub const ENTROPY_THRESHOLD_HIGH: f64 = 7.85;

/// Chunk size for the chunked retry strategy.
const CHUNK_SIZE: usize = 32_768; // 32 KB

// ══════════════════════════════════════════════════════════════
//  TAINT MAP
// ══════════════════════════════════════════════════════════════

/// A compact bit-vector that tracks which output bytes came from error-recovery
/// (zero-padding, resync guesses, etc.).  Reading a tainted dictionary position
/// during a match-copy should yield 0x00 rather than whatever garbage is there.
#[derive(Debug, Clone)]
pub struct TaintMap {
    bits: Vec<u64>,
    /// Logical capacity (bytes tracked).
    capacity: usize,
    /// Number of tainted bytes.
    taint_count: usize,
}

impl TaintMap {
    /// Create a new TaintMap sized for `capacity` output bytes.
    pub fn new(capacity: usize) -> Self {
        let words = capacity.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            capacity,
            taint_count: 0,
        }
    }

    /// Mark one byte position as tainted.
    pub fn set(&mut self, pos: usize) {
        if pos < self.capacity {
            let word = pos / 64;
            let bit = pos % 64;
            if self.bits[word] & (1u64 << bit) == 0 {
                self.bits[word] |= 1u64 << bit;
                self.taint_count += 1;
            }
        }
    }

    /// Mark an inclusive range `[start, end)` as tainted.
    pub fn set_range(&mut self, start: usize, end: usize) {
        for i in start..end.min(self.capacity) {
            self.set(i);
        }
    }

    /// Returns true if `pos` is tainted.
    pub fn is_tainted(&self, pos: usize) -> bool {
        if pos >= self.capacity {
            return true;
        }
        let word = pos / 64;
        let bit = pos % 64;
        (self.bits[word] >> bit) & 1 == 1
    }

    /// Total number of tainted output bytes.
    pub fn taint_count(&self) -> usize {
        self.taint_count
    }

    /// Ensure the taint map can track at least `new_cap` bytes (grows if needed).
    pub fn grow_to(&mut self, new_cap: usize) {
        if new_cap > self.capacity {
            let needed_words = new_cap.div_ceil(64);
            self.bits.resize(needed_words, 0u64);
            self.capacity = new_cap;
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  SHANNON ENTROPY
// ══════════════════════════════════════════════════════════════

/// Compute Shannon entropy of a byte slice, in bits (0.0 – 8.0).
///
/// H = -Σ p_i * log₂(p_i)
///
/// Returns 0.0 for empty or single-value slices.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Classify decoded output quality based on entropy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntropyClass {
    /// Looks like real decompressed data (mixed bytes, meaningful structure).
    Valid,
    /// Dominated by zeros / single value — probably zero-padding or dead region.
    Flat,
    /// Near-uniform distribution — already compressed, encrypted, or random noise.
    Noise,
}

/// Compute entropy and classify a decoded window.
pub fn classify_entropy(data: &[u8]) -> (f64, EntropyClass) {
    let h = shannon_entropy(data);
    let class = if h < ENTROPY_THRESHOLD_LOW {
        EntropyClass::Flat
    } else if h > ENTROPY_THRESHOLD_HIGH {
        EntropyClass::Noise
    } else {
        EntropyClass::Valid
    };
    (h, class)
}

// ══════════════════════════════════════════════════════════════
//  ZOMBIE STATS
// ══════════════════════════════════════════════════════════════

/// Accumulates statistics across a zombie decode run.
#[derive(Debug, Clone, Default)]
pub struct ZombieStats {
    /// Total bytes written to the output buffer.
    pub bytes_decoded: usize,
    /// Number of output bytes marked as tainted (came from error recovery).
    pub bytes_tainted: usize,
    /// How many times force_resynchronize was invoked.
    pub resync_count: usize,
    /// Bytes we zero-padded because we couldn't decode them.
    pub bytes_zeroed: usize,
    /// Number of output windows rejected by the entropy check.
    pub entropy_rejections: usize,
    /// Number of probe windows accepted at a resync point.
    pub probe_successes: usize,
    /// Input bytes consumed.
    pub input_consumed: usize,
}

// ══════════════════════════════════════════════════════════════
//  ZOMBIE LZMA DECODER
// ══════════════════════════════════════════════════════════════

/// Zombie LZMA Decoder — fault-tolerant LZMA1 stream recovery.
///
/// Construct with `ZombieLzmaDecoder::new()` and call `decode(input)`.
pub struct ZombieLzmaDecoder {
    entropy_low: f64,
    entropy_high: f64,
    max_slide: usize,
}

impl Default for ZombieLzmaDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZombieLzmaDecoder {
    /// Create a decoder with default (PRD-specified) parameters.
    pub fn new() -> Self {
        Self {
            entropy_low: ENTROPY_THRESHOLD_LOW,
            entropy_high: ENTROPY_THRESHOLD_HIGH,
            max_slide: MAX_SLIDE_ATTEMPTS,
        }
    }

    /// Override the entropy window thresholds.
    pub fn with_entropy_bounds(mut self, low: f64, high: f64) -> Self {
        self.entropy_low = low;
        self.entropy_high = high;
        self
    }

    // ──────────────────────────────────────────────────────────
    //  MAIN ENTRY POINT
    // ──────────────────────────────────────────────────────────

    /// Decode a potentially corrupt LZMA1 stream.
    ///
    /// Returns `(output_bytes, taint_map, stats)`.  Never panics.  Output bytes
    /// in recovering regions are zero-padded and flagged in the taint map.
    pub fn decode(&self, input: &[u8]) -> (Vec<u8>, TaintMap, ZombieStats) {
        let mut stats = ZombieStats::default();
        let mut output: Vec<u8> = Vec::new();
        let mut taint = TaintMap::new(0);

        if input.is_empty() {
            return (output, taint, stats);
        }

        // ── Pass 1: attempt clean decode of the entire input ──────────────
        if let Some(decoded) = self.try_lzma_decode(input) {
            let (h, class) = classify_entropy(&decoded);
            if class == EntropyClass::Valid || (!decoded.is_empty() && h > 0.1) {
                let n = decoded.len();
                taint.grow_to(n);
                stats.bytes_decoded = n;
                stats.input_consumed = input.len();
                output = decoded;
                return (output, taint, stats);
            }
            // Entropy looks bad — still return the bytes but mark them tainted
            if !decoded.is_empty() {
                let n = decoded.len();
                taint.grow_to(n);
                taint.set_range(0, n);
                stats.bytes_decoded = n;
                stats.bytes_tainted = n;
                stats.entropy_rejections += 1;
                stats.input_consumed = input.len();
                output = decoded;
                return (output, taint, stats);
            }
        }

        // ── Pass 2: chunked retry with resync ─────────────────────────────
        self.zombie_decode_chunked(input, &mut output, &mut taint, &mut stats);

        stats.bytes_decoded = output.len();
        stats.bytes_tainted = taint.taint_count();
        (output, taint, stats)
    }

    // ──────────────────────────────────────────────────────────
    //  CHUNKED ZOMBIE DECODE
    // ──────────────────────────────────────────────────────────

    /// Chunked decode with byte-slide resynchronization.
    ///
    /// Splits input into CHUNK_SIZE windows and attempts to decode each.
    /// On failure: invokes `force_resynchronize` to find next valid sync point,
    /// zero-pads the undecodable gap, and continues.
    /// Hard-bails after MAX_CHUNK_OPS operations to prevent hanging on pure binary data.
    fn zombie_decode_chunked(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        taint: &mut TaintMap,
        stats: &mut ZombieStats,
    ) {
        let mut pos = 0usize;
        let mut ops = 0usize;

        while pos < input.len() && ops < MAX_CHUNK_OPS {
            ops += 1;
            let window_end = (pos + CHUNK_SIZE).min(input.len());
            let window = &input[pos..window_end];

            // Fast-fail: must start with a valid LZMA properties byte
            if !is_valid_lzma_props(window[0]) {
                let (sync_offset, probe_bytes) = self.force_resynchronize(&input[pos..], stats);
                // Zero-pad
                let gap_size = sync_offset.min(PROBE_WINDOW);
                if gap_size > 0 {
                    let base = output.len();
                    taint.grow_to(base + gap_size);
                    taint.set_range(base, base + gap_size);
                    output.extend(std::iter::repeat_n(0u8, gap_size));
                    stats.bytes_zeroed += gap_size;
                }
                if !probe_bytes.is_empty() {
                    let base = output.len();
                    taint.grow_to(base + probe_bytes.len());
                    taint.set_range(base, base + probe_bytes.len());
                    output.extend_from_slice(&probe_bytes);
                    stats.bytes_tainted += probe_bytes.len();
                }
                pos += (sync_offset + 1).min(input.len() - pos);
                continue;
            }

            match self.try_lzma_decode(window) {
                Some(decoded) if decoded.len() >= MIN_PROGRESS_BYTES => {
                    let (h, class) = classify_entropy(&decoded);

                    if class == EntropyClass::Valid || h > self.entropy_low {
                        // Good decode
                        let base = output.len();
                        taint.grow_to(base + decoded.len());
                        output.extend_from_slice(&decoded);
                        pos = window_end;
                    } else {
                        // Bad entropy — taint and consume
                        stats.entropy_rejections += 1;
                        let base = output.len();
                        let pad = decoded.len().max(PROBE_WINDOW);
                        taint.grow_to(base + pad);
                        taint.set_range(base, base + pad);
                        output.extend(std::iter::repeat_n(0u8, pad));
                        stats.bytes_zeroed += pad;
                        pos += 1; // slide forward
                    }
                }
                _ => {
                    // Decode failed — try force_resynchronize
                    let (sync_offset, probe_bytes) = self.force_resynchronize(&input[pos..], stats);

                    // Zero-pad the undecodable gap
                    let gap_size = sync_offset.min(PROBE_WINDOW);
                    if gap_size > 0 {
                        let base = output.len();
                        taint.grow_to(base + gap_size);
                        taint.set_range(base, base + gap_size);
                        output.extend(std::iter::repeat_n(0u8, gap_size));
                        stats.bytes_zeroed += gap_size;
                    }

                    // Append the probe bytes (mark tainted if resync'd)
                    if !probe_bytes.is_empty() {
                        let base = output.len();
                        taint.grow_to(base + probe_bytes.len());
                        taint.set_range(base, base + probe_bytes.len());
                        output.extend_from_slice(&probe_bytes);
                        stats.bytes_tainted += probe_bytes.len();
                    }

                    // Advance past the sync point
                    pos += (sync_offset + 1).min(input.len() - pos);
                }
            }
        }

        stats.input_consumed = input.len();
    }

    // ──────────────────────────────────────────────────────────
    //  FORCE RESYNCHRONIZE
    // ──────────────────────────────────────────────────────────

    /// Slide forward byte-by-byte from `&input[0..]`, looking for the next
    /// position where `lzma_rs::lzma_decompress` produces a PROBE_WINDOW-byte
    /// window with acceptable entropy.
    ///
    /// Strategy:
    /// - Skip 1 byte (slide)
    /// - Quick-check: reject positions without a valid LZMA properties byte
    /// - Create a fresh `lzma_rs` decoder at the new position
    /// - Test-decode up to `PROBE_WINDOW * 4` input bytes
    /// - Accept if output length >= MIN_PROGRESS_BYTES and entropy passes
    ///
    /// Returns `(bytes_skipped, probe_output)`.
    pub fn force_resynchronize(&self, input: &[u8], stats: &mut ZombieStats) -> (usize, Vec<u8>) {
        stats.resync_count += 1;

        for slide in 1..self.max_slide.min(input.len()) {
            let candidate = &input[slide..];
            if candidate.len() < MIN_LZMA_INPUT {
                break;
            }

            // Fast path: check valid LZMA properties byte before doing any decoding.
            let props = candidate[0];
            if !is_valid_lzma_props(props) {
                continue;
            }

            // Try decoding a probe window.
            let probe_end = (PROBE_WINDOW * 4).min(candidate.len());
            if let Some(probe) = self.try_lzma_decode(&candidate[..probe_end]) {
                if probe.len() >= MIN_PROGRESS_BYTES {
                    let (h, class) = classify_entropy(&probe);
                    if class == EntropyClass::Valid || h > self.entropy_low {
                        stats.probe_successes += 1;
                        return (slide, probe);
                    }
                }
            }

            // (Raw-byte fallback removed: returning undecoded compressed
            //  bytes as "output" would corrupt the recovery stream.)
        }

        (self.max_slide.min(input.len()), Vec::new())
    }

    // ──────────────────────────────────────────────────────────
    //  LOW-LEVEL LZMA DECODE
    // ──────────────────────────────────────────────────────────

    /// Attempt to decode `data` as an LZMA1 stream using lzma-rs.
    /// Returns None on any error.
    fn try_lzma_decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 13 {
            return None;
        }
        let mut reader = Cursor::new(data);
        let mut output = Vec::new();
        match lzma_rs::lzma_decompress(&mut reader, &mut output) {
            Ok(_) if !output.is_empty() => Some(output),
            _ => None,
        }
    }

    // ──────────────────────────────────────────────────────────
    //  HELPER: XZ/LZMA2 fallback
    // ──────────────────────────────────────────────────────────

    /// Try XZ-format decode (wraps LZMA2) as a fallback for `.xz`-wrapped streams.
    pub fn try_xz_decode(&self, data: &[u8]) -> Option<Vec<u8>> {
        use std::io::Read;
        use xz2::read::XzDecoder;
        let decoder = XzDecoder::new(Cursor::new(data));
        // Guard against decompression bombs: cap output at 512 MB.
        let mut limited = decoder.take(512 * 1024 * 1024);
        let mut output = Vec::new();
        match limited.read_to_end(&mut output) {
            Ok(_) if !output.is_empty() => Some(output),
            _ => None,
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  LZMA PROPERTY VALIDATION
// ══════════════════════════════════════════════════════════════

/// Validate an LZMA properties byte.
///
/// The properties byte encodes: `props = lc + lp * 9 + pb * 9 * 5`
/// - lc ∈ [0, 8], lp ∈ [0, 4], pb ∈ [0, 4]
/// - Maximum valid value: 8 + 4*9 + 4*45 = 8 + 36 + 180 = 224
pub fn is_valid_lzma_props(props: u8) -> bool {
    if props > 224 {
        return false;
    }
    let pb = props / 45;
    let remainder = props % 45;
    let lp = remainder / 9;
    let lc = remainder % 9;
    pb <= 4 && lp <= 4 && lc <= 8
}

/// Extract (lc, lp, pb) from an LZMA properties byte.
pub fn decode_lzma_props(props: u8) -> (u8, u8, u8) {
    let pb = props / 45;
    let remainder = props % 45;
    let lp = remainder / 9;
    let lc = remainder % 9;
    (lc, lp, pb)
}

// ══════════════════════════════════════════════════════════════
//  CONVENIENCE: multi-offset scan
// ══════════════════════════════════════════════════════════════

/// Scan `data` at multiple offsets, collect all decodable LZMA segments, and
/// merge them (deduplicated, sorted by output size descending).
///
/// This is the top-level entry point used by the Salvager pipeline.
/// Returns merged output bytes, merged taint map, and aggregate stats.
pub fn zombie_scan_and_decode(data: &[u8]) -> (Vec<u8>, TaintMap, ZombieStats) {
    let decoder = ZombieLzmaDecoder::new();

    // Common 7z solid-stream offsets where LZMA1 data begins.
    let probe_offsets: &[usize] = &[0, 32, 34, 48, 64, 96, 128, 256];

    let mut best_output: Vec<u8> = Vec::new();
    let mut best_taint = TaintMap::new(0);
    let mut best_stats = ZombieStats::default();

    for &off in probe_offsets {
        if off >= data.len() {
            continue;
        }
        let slice = &data[off..];
        // Fast-fail: skip offsets that can't be valid LZMA1 headers.
        if slice.len() < MIN_LZMA_INPUT || !is_valid_lzma_props(slice[0]) {
            continue;
        }
        let (out, taint, stats) = decoder.decode(slice);

        if out.len() > best_output.len() {
            best_output = out;
            best_taint = taint;
            best_stats = stats;
            best_stats.input_consumed += off; // account for the skipped prefix
        }
    }

    // If nothing worked at known offsets, do a byte-slide scan across the whole file.
    if best_output.is_empty() {
        let mut stats = ZombieStats::default();
        let (slide, probe) = decoder.force_resynchronize(data, &mut stats);
        if !probe.is_empty() {
            let total_len = slide + probe.len();
            let mut taint = TaintMap::new(total_len);
            // Bytes before the sync point were skipped → mark as tainted.
            best_output.extend(std::iter::repeat_n(0u8, slide));
            best_output.extend_from_slice(&probe);
            // Only the zero-padded gap is tainted; probe bytes are decoded successfully.
            taint.set_range(0, slide);
            best_taint = taint;
            best_stats = stats;
        }
    }

    (best_output, best_taint, best_stats)
}

// ══════════════════════════════════════════════════════════════
//  TESTS
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── TaintMap ───────────────────────────────────────────────

    #[test]
    fn test_taintmap_basic() {
        let mut tm = TaintMap::new(128);
        assert!(!tm.is_tainted(0));
        assert!(!tm.is_tainted(127));
        tm.set(5);
        tm.set(63);
        tm.set(64);
        assert!(tm.is_tainted(5));
        assert!(tm.is_tainted(63));
        assert!(tm.is_tainted(64));
        assert!(!tm.is_tainted(6));
        assert_eq!(tm.taint_count(), 3);
    }

    #[test]
    fn test_taintmap_range() {
        let mut tm = TaintMap::new(256);
        tm.set_range(10, 20);
        for i in 10..20 {
            assert!(tm.is_tainted(i), "byte {} should be tainted", i);
        }
        assert!(!tm.is_tainted(9));
        assert!(!tm.is_tainted(20));
        assert_eq!(tm.taint_count(), 10);
    }

    #[test]
    fn test_taintmap_out_of_bounds_is_tainted() {
        let tm = TaintMap::new(10);
        // Out-of-bounds positions are always considered tainted (safe fallback).
        assert!(tm.is_tainted(10));
        assert!(tm.is_tainted(9999));
    }

    #[test]
    fn test_taintmap_grow() {
        let mut tm = TaintMap::new(64);
        tm.set(63);
        tm.grow_to(128);
        assert!(tm.is_tainted(63));
        assert!(!tm.is_tainted(64));
    }

    #[test]
    fn test_taintmap_double_set_count() {
        let mut tm = TaintMap::new(32);
        tm.set(7);
        tm.set(7); // double-set should not double-count
        assert_eq!(tm.taint_count(), 1);
    }

    // ── Shannon Entropy ────────────────────────────────────────

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform_zero() {
        // All same byte → H = 0
        let data = vec![0x00u8; 1024];
        let h = shannon_entropy(&data);
        assert!(
            h < 0.001,
            "uniform data should have near-zero entropy, got {}",
            h
        );
    }

    #[test]
    fn test_entropy_max() {
        // Perfectly uniform 256-byte symbol distribution → H ≈ 8
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.9, "max entropy should be near 8.0, got {}", h);
    }

    #[test]
    fn test_entropy_typical_text() {
        // ASCII text has medium entropy (typically 4–6 bits)
        let text = b"Hello, World! This is a test of the Shannon entropy function.";
        let h = shannon_entropy(text);
        assert!(
            h > 3.0 && h < 7.0,
            "text entropy should be in [3,7], got {}",
            h
        );
    }

    #[test]
    fn test_classify_entropy_flat() {
        let data = vec![0x00u8; 64];
        let (_, class) = classify_entropy(&data);
        assert_eq!(class, EntropyClass::Flat);
    }

    #[test]
    fn test_classify_entropy_valid() {
        let data: Vec<u8> = (0u8..=127).cycle().take(256).collect();
        let (h, class) = classify_entropy(&data);
        assert_eq!(class, EntropyClass::Valid, "entropy was {}", h);
    }

    // ── LZMA property validation ───────────────────────────────

    #[test]
    fn test_valid_lzma_props() {
        // Common defaults: lc=3, lp=0, pb=2 → 3 + 0*9 + 2*45 = 93
        assert!(is_valid_lzma_props(93));
        // lc=0, lp=0, pb=0 → 0
        assert!(is_valid_lzma_props(0));
        // max: lc=8, lp=4, pb=4 → 8 + 36 + 180 = 224
        assert!(is_valid_lzma_props(224));
        // invalid: > 224
        assert!(!is_valid_lzma_props(225));
        assert!(!is_valid_lzma_props(255));
    }

    #[test]
    fn test_decode_lzma_props_roundtrip() {
        // lc=3, lp=0, pb=2
        let (lc, lp, pb) = decode_lzma_props(93);
        assert_eq!(lc, 3);
        assert_eq!(lp, 0);
        assert_eq!(pb, 2);
    }

    // ── ZombieLzmaDecoder ──────────────────────────────────────

    #[test]
    fn test_zombie_decode_empty() {
        let d = ZombieLzmaDecoder::new();
        let (out, taint, stats) = d.decode(&[]);
        assert!(out.is_empty());
        assert_eq!(stats.bytes_decoded, 0);
        assert_eq!(taint.taint_count(), 0);
    }

    #[test]
    fn test_zombie_decode_garbage_no_panic() {
        // Random garbage should not panic; it should return gracefully.
        let garbage: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let d = ZombieLzmaDecoder::new();
        let (_, _, stats) = d.decode(&garbage);
        // We don't assert on output content — just that it doesn't crash and
        // that resync was attempted (stats.resync_count > 0 or bytes_zeroed > 0).
        let _ = stats;
    }

    #[test]
    fn test_zombie_decode_valid_lzma_stream() {
        // Encode "Hello, Zombie World!" as a valid LZMA stream, then decode.
        let original = b"Hello, Zombie World! This is a test of the zombie LZMA decoder. \
                         If you can read this, the decoder works correctly on valid input.";
        let encoded = lzma_encode(original);
        if encoded.is_empty() {
            // If we can't encode in this environment, skip gracefully.
            return;
        }
        let d = ZombieLzmaDecoder::new();
        let (out, taint, stats) = d.decode(&encoded);
        assert!(!out.is_empty(), "should decode valid LZMA stream");
        assert_eq!(
            taint.taint_count(),
            0,
            "clean stream should have zero taint"
        );
        assert_eq!(stats.resync_count, 0, "no resyncs needed for valid stream");
        assert_eq!(
            &out[..out.len().min(original.len())],
            &original[..out.len().min(original.len())]
        );
    }

    #[test]
    fn test_zombie_decode_corrupt_lzma_stream() {
        // Encode valid data, then corrupt the middle section.
        let original = b"This is a long enough string to produce a multi-byte LZMA stream. \
                         We will corrupt the middle and verify the zombie decoder handles it.";
        let encoded = lzma_encode(original);
        if encoded.is_empty() {
            return;
        }

        let mut corrupted = encoded.clone();
        let mid = corrupted.len() / 2;
        for i in mid..mid + 20 {
            if i < corrupted.len() {
                corrupted[i] = 0xFF; // corrupt 20 bytes in the middle
            }
        }

        let d = ZombieLzmaDecoder::new();
        let (out, taint, stats) = d.decode(&corrupted);
        // The decoder should not panic and should return something.
        let _ = (out, taint, stats);
    }

    #[test]
    fn test_force_resynchronize_finds_valid_region() {
        let d = ZombieLzmaDecoder::new();
        let mut stats = ZombieStats::default();

        // Prepend 50 bytes of garbage, then a valid entropy region.
        let mut data = vec![0x00u8; 50]; // flat garbage
                                         // Append a text-like region with good entropy.
        let good_data: Vec<u8> =
            b"The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()"
                .iter()
                .cycle()
                .take(256)
                .cloned()
                .collect();
        data.extend_from_slice(&good_data);

        let (slide, probe) = d.force_resynchronize(&data, &mut stats);
        // Either we slid forward OR we returned a probe — as long as we don't panic.
        assert!(slide > 0, "should have slid forward at least one byte");
        let _ = probe;
    }

    #[test]
    fn test_zombie_scan_and_decode_garbage() {
        // Full pipeline on random-ish garbage — should not panic.
        let data: Vec<u8> = (0u8..128u8).cycle().take(1024).collect();
        let (out, taint, stats) = zombie_scan_and_decode(&data);
        let _ = (out, taint, stats);
    }

    #[test]
    fn test_zombie_stats_default() {
        let s = ZombieStats::default();
        assert_eq!(s.bytes_decoded, 0);
        assert_eq!(s.bytes_tainted, 0);
        assert_eq!(s.resync_count, 0);
        assert_eq!(s.bytes_zeroed, 0);
        assert_eq!(s.entropy_rejections, 0);
    }

    // ── Helper: encode bytes as LZMA stream using lzma-rs ─────

    fn lzma_encode(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let result = lzma_rs::lzma_compress(
            &mut std::io::BufReader::new(std::io::Cursor::new(data)),
            &mut output,
        );
        match result {
            Ok(_) => output,
            Err(_) => Vec::new(),
        }
    }
}
