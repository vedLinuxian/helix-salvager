# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email: **linuxlover94@gmail.com** (or use GitHub's private security reporting)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Security Considerations

Helix Salvager processes untrusted binary input. The following safeguards are in place:

### Decompression Bomb Protection
- **512 MB per-file limit** — No single decompressed file can exceed this
- **Entropy validation** — Shannon entropy analysis rejects noise output from LZMA

### Memory Safety
- Written in Rust — no buffer overflows, use-after-free, or null pointer dereferences
- All unsafe code: **zero** — the entire codebase is safe Rust
- Fuzz-tested against malformed inputs (ZIP, 7z, LZMA streams)

### Malicious Archive Handling
- **CVE-2018-0986 tested** — Known exploit RAR handled safely
- **No code execution** — Archives are parsed, never executed
- **No path traversal** — File names from archives are sanitized (no `../` escape)
- **No symlink following** — Extracted entries don't follow symbolic links

### Web Server
- **CORS restricted** — Configurable origin policy
- **Upload size limit** — Default 500 MB, configurable
- **No persistent storage** — Recovered files are held in memory and served once
- **Session-based isolation** — Tasks are scoped by session ID

## Dependency Audit

Run `cargo audit` to check for known vulnerabilities in dependencies.

The CI pipeline runs `rustsec/audit-check` on every push and weekly.

## Known Limitations

- The engine reads the entire input into memory. Very large files (> available RAM) will cause OOM.
- LZMA retry loops have a maximum iteration count to prevent infinite loops, but CPU-intensive malicious inputs could cause slow processing.
