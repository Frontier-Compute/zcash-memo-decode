# Contributing

Contributions are welcome. This crate is intended as shared Zcash ecosystem infrastructure.

## Before you start

- Check existing issues and PRs
- For new memo format support, open an issue first to discuss the detection rules

## Code style

- `cargo fmt --all` before committing
- `cargo clippy --all-targets` with no warnings
- All tests pass: `cargo test --all-targets`

## Adding a new memo format

1. Add a variant to `MemoFormat` in `src/lib.rs`
2. Add detection logic in the `decode()` function
3. Add a label in the `label()` function
4. Add tests covering: valid input, malformed input, edge cases
5. Update README.md with the new format

The decoder must never panic on any input. Unknown formats are classified as `MemoFormat::Unknown`, not errors.

## TVLV module

The `src/tvlv.rs` module implements ZIP 302 TVLV encoding. Changes here must match the Bitcoin-style CompactSize spec and the ZIP 302 draft (PR #638 on zcash/zips).

## Testing

```bash
cargo test --all-targets
cargo run --example wallet_integration
cargo run -- 68656c6c6f  # CLI smoke test
```

## License

By contributing, you agree that your contributions will be licensed under the MIT license.
