# Third-party notices

planguard is MIT licensed. It links the following Rust crates. Exact versions
are recorded in [`Cargo.lock`](Cargo.lock); each crate is used under the license
terms published by its authors.

| Crate | License | Project |
| --- | --- | --- |
| `anyhow` | MIT OR Apache-2.0 | https://github.com/dtolnay/anyhow |
| `clap` | MIT OR Apache-2.0 | https://github.com/clap-rs/clap |
| `serde` | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| `serde_json` | MIT OR Apache-2.0 | https://github.com/serde-rs/json |

The test suite uses `tempfile` under MIT OR Apache-2.0.

Rust, Cargo, and the standard library are distributed under their own licenses.
They are build tooling and a runtime dependency, not vendored source.
