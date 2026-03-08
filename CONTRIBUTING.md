# Contributing to Helix Salvager

Thank you for your interest in contributing! This project recovers files from corrupt archives — every improvement directly helps people save their data.

## Quick Start

```bash
git clone https://github.com/vedLinuxian/helix-salvager.git
cd helix-salvager
cargo build
cargo test
```

## Development Flow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Ensure all checks pass:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --workspace -- -D warnings
   cargo test --workspace
   ```
5. Commit with a descriptive message
6. Open a Pull Request

## What We Need Help With

### High Impact
- **New file signatures** — Add detection for more file types (see `CarvedFileType` enum in `salvager.rs`)
- **RAR native extraction** — We detect RAR but can't decompress it yet
- **WASM build** — Make the core engine run in the browser
- **Parallel carving** — Multi-threaded Aho-Corasick scanning for large files

### Good First Issues
- Add more corruption patterns to `real_world_tests.rs`
- Improve file type validation (e.g., check JPEG segment structure)
- Add archive format detection for more types (cab, arj, lha)
- CLI output formatting improvements

### Documentation
- Tutorial blog posts
- Architecture explanations
- Comparison benchmarks against other tools

## Code Guidelines

### Rust Style
- **MSRV: 1.88** — do not use features requiring a newer compiler
- Follow `rustfmt` defaults (run `cargo fmt`)
- Zero clippy warnings — `cargo clippy -- -D warnings`
- All public APIs must have doc comments
- Error handling: use `Result` where possible, `panic` only for genuine invariant violations

### Adding a New File Signature

1. Add variant to `CarvedFileType` enum in `salvager.rs`
2. Add magic bytes to the `SIGNATURES` array
3. Add extraction logic with size bounds in `carve_files()`
4. Add validation if applicable
5. Add tests in `salvager_integration.rs`
6. Update the README signature table

### Adding a New Archive Format

1. Add detection in `detect_archive_type()`
2. Implement extraction in a new method on `SalvageEngine`
3. Wire it into `salvage()` dispatch
4. Add tests with real files (download from a public source, add to `test_real_world/`)
5. Add corruption tests

### Test Philosophy
- Every feature needs tests
- Use real files when possible (from corkami/pocs or other public sources)
- Test both success and graceful failure
- The engine must **never panic** on any input — fuzz it if you can

## Commit Messages

Use conventional commits:
```
feat: add TIFF file carving support
fix: handle zero-length ZIP entries without panic
test: add NAND degradation test for gzip archives
docs: update architecture diagram
perf: parallelize AhoCorasick scanning
```

## Reporting Bugs

Use the [Bug Report template](https://github.com/vedLinuxian/helix-salvager/issues/new?template=bug_report.md). Include:
- The corrupt file (or a minimal reproduction)
- Expected vs actual recovery results
- `salvager inspect <file> --json` output

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 dual license.
