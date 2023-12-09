# Deployment Checklist

1. Run `cargo fmt` and `cargo clippy`
2. Run `cargo test --release`
3. Update version in `Cargo.toml`
4. Update version in `Readme.md`
5. Update version in `lib.rs` documentation comment
6. Update examples in `Readme.md` and `lib.rs`
7. Tag a commit with the release
8. Mark a release on GitHub
9. Run `cargo publish`
