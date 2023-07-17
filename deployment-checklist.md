# Deployment Checklist

1. Run `cargo fmt`
2. Run `cargo test --release`
3. Update version in `Cargo.toml`
4. Update version in `Readme.md`
5. Update examples in `Readme.md` and `lib.rs`
6. Tag a commit with the release
7. Mark a release on GitHub
8. Run `cargo publish`
