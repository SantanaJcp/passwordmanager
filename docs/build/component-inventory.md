# Initial build component inventory

This is a mechanical snapshot of package metadata in `Cargo.lock`, plus the fixed C input. It is **not** a final license, notice, source-correspondence, vulnerability, or compatibility audit. Package license expressions below are upstream metadata declarations and still require artifact-level review before release.

Runtime/build classification and enabled features are determined by `cargo tree`; `scripts/verify-build-inputs.sh` rejects the forbidden libsodium `fetch-latest` feature. Future tickets must update this inventory when they change the graph.

| Component | Version | Source | Declared license |
|---|---:|---|---|
| adler32 | 1.2.0 | crates.io lock | Zlib |
| allocator-api2 | 0.2.21 | crates.io lock | MIT OR Apache-2.0 |
| aws-lc-rs | 1.18.1 | crates.io lock | ISC AND (Apache-2.0 OR ISC) |
| aws-lc-sys | 0.45.0 | crates.io lock | composite ISC/Apache-2.0/MIT/BSD-3-Clause expression |
| base64 | 0.23.1 | crates.io lock | MIT OR Apache-2.0 |
| bitflags | 2.13.2 | crates.io lock | MIT OR Apache-2.0 |
| bumpalo | 3.20.3 | crates.io lock | MIT OR Apache-2.0 |
| bytes | 1.12.1 | crates.io lock | MIT |
| cc | 1.4.5 | crates.io lock | MIT OR Apache-2.0 |
| cfg-if | 1.0.4 | crates.io lock | MIT OR Apache-2.0 |
| cmake | 0.1.58 | crates.io lock | MIT OR Apache-2.0 |
| crc32fast | 1.5.2 | crates.io lock | MIT OR Apache-2.0 |
| dary_heap | 0.3.9 | crates.io lock | MIT OR Apache-2.0 |
| dunce | 1.0.5 | crates.io lock | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| equivalent | 1.0.2 | crates.io lock | Apache-2.0 OR MIT |
| errno | 0.3.14 | crates.io lock | MIT OR Apache-2.0 |
| fallible-iterator | 0.3.0 | crates.io lock | MIT/Apache-2.0 |
| fallible-streaming-iterator | 0.1.9 | crates.io lock | MIT/Apache-2.0 |
| filetime | 0.2.29 | crates.io lock | MIT/Apache-2.0 |
| find-msvc-tools | 0.1.12 | crates.io lock | MIT OR Apache-2.0 |
| flate2 | 1.1.10 | crates.io lock | MIT OR Apache-2.0 |
| foldhash | 0.2.0 | crates.io lock | Zlib |
| fs_extra | 1.3.0 | crates.io lock | MIT |
| getrandom | 0.2.17, 0.4.3 | crates.io lock | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | crates.io lock | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | crates.io lock | MIT OR Apache-2.0 |
| hashlink | 0.12.2 | crates.io lock | MIT OR Apache-2.0 |
| http | 1.5.0 | crates.io lock | MIT OR Apache-2.0 |
| httparse | 1.10.1 | crates.io lock | MIT OR Apache-2.0 |
| indexmap | 2.14.2 | crates.io lock | Apache-2.0 OR MIT |
| itoa | 1.0.18 | crates.io lock | MIT OR Apache-2.0 |
| jobserver | 0.1.35 | crates.io lock | MIT OR Apache-2.0 |
| js-sys | 0.3.105 | crates.io lock | MIT OR Apache-2.0 |
| libc | 0.2.189 | crates.io lock | MIT OR Apache-2.0 |
| libflate | 2.3.2 | crates.io lock | MIT |
| libflate_lz77 | 2.3.0 | crates.io lock | MIT |
| libsodium-sys-stable | 1.24.0 | crates.io lock | MIT OR Apache-2.0 |
| libsqlite3-sys | 0.38.2 | crates.io lock | MIT |
| linux-raw-sys | 0.12.1 | crates.io lock | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| log | 0.4.34 | crates.io lock | MIT OR Apache-2.0 |
| memchr | 2.8.3 | crates.io lock | Unlicense OR MIT |
| minicbor | 2.3.0 | crates.io lock | BlueOak-1.0.0 |
| minisign-verify | 0.2.5 | crates.io lock | MIT |
| no_std_io2 | 0.9.4 | crates.io lock | Apache-2.0 OR MIT |
| once_cell | 1.21.4 | crates.io lock | MIT OR Apache-2.0 |
| percent-encoding | 2.3.2 | crates.io lock | MIT OR Apache-2.0 |
| pkg-config | 0.3.34 | crates.io lock | MIT OR Apache-2.0 |
| pm-cli | 0.1.0 | workspace | AGPL-3.0-only |
| pm-crypto | 0.1.0 | workspace | AGPL-3.0-only |
| pm-custody | 0.1.0 | workspace | AGPL-3.0-only |
| pm-process-runner | 0.1.0 | workspace | AGPL-3.0-only |
| pm-vault | 0.1.0 | workspace | AGPL-3.0-only |
| proc-macro2 | 1.0.107 | crates.io lock | MIT OR Apache-2.0 |
| quote | 1.0.47 | crates.io lock | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | crates.io lock | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| ring | 0.17.14 | crates.io lock | Apache-2.0 AND ISC |
| rle-decode-fast | 1.0.3 | crates.io lock | MIT OR Apache-2.0 |
| rsqlite-vfs | 0.1.1 | crates.io lock | MIT |
| rusqlite | 0.40.2 | crates.io lock | MIT |
| rustix | 1.1.4 | crates.io lock | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustversion | 1.0.23 | crates.io lock | MIT OR Apache-2.0 |
| rustls | 0.23.44 | crates.io lock | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | crates.io lock | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.15 | crates.io lock | ISC |
| shlex | 2.0.1 | crates.io lock | MIT OR Apache-2.0 |
| simd-adler32 | 0.3.10 | crates.io lock | MIT |
| smallvec | 1.16.1 | crates.io lock | MIT OR Apache-2.0 |
| subtle | 2.6.1 | crates.io lock | BSD-3-Clause |
| sqlite-wasm-rs | 0.5.5 | crates.io lock | MIT |
| syn | 3.0.5 | crates.io lock | MIT OR Apache-2.0 |
| tar | 0.4.46 | crates.io lock | MIT OR Apache-2.0 |
| thiserror | 2.0.20 | crates.io lock | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.20 | crates.io lock | MIT OR Apache-2.0 |
| typed-path | 0.12.3 | crates.io lock | MIT OR Apache-2.0 |
| unicode-ident | 1.0.24 | crates.io lock | (MIT OR Apache-2.0) AND Unicode-3.0 |
| untrusted | 0.7.1, 0.9.0 | crates.io lock | ISC |
| ureq | 3.4.1 | crates.io lock | MIT OR Apache-2.0 |
| ureq-proto | 0.6.2 | crates.io lock | MIT OR Apache-2.0 |
| utf8-zero | 0.8.1 | crates.io lock | MIT OR Apache-2.0 |
| vcpkg | 0.2.15 | crates.io lock | MIT/Apache-2.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | crates.io lock | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.128 | crates.io lock | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.128 | crates.io lock | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.128 | crates.io lock | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.128 | crates.io lock | MIT OR Apache-2.0 |
| windows-link | 0.2.1 | crates.io lock | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | crates.io lock | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | crates.io lock | MIT OR Apache-2.0 |
| windows-targets and eight architecture crates | 0.52.6 | crates.io lock | MIT OR Apache-2.0 |
| xattr | 1.6.1 | crates.io lock | MIT OR Apache-2.0 |
| zip | 8.6.0 | crates.io lock | MIT |
| zlib-rs | 0.6.7 | crates.io lock | Zlib |
| zopfli | 0.8.3 | crates.io lock | Apache-2.0 |
| zeroize | 1.9.0 | crates.io lock | Apache-2.0 OR MIT |
| libsodium C | 1.0.22 | committed, SHA-256 pinned archive | ISC |

The Rust toolchain is fixed separately at 1.98.1 and is a build tool, not a packaged runtime. Its own bundled third-party inventory must be reviewed if a release ever redistributes it.
