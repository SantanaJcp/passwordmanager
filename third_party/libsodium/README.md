# Fixed libsodium C build input

`LATEST.tar.gz` is the filename required by `libsodium-sys-stable` 1.24.0,
but its content is fixed here to libsodium **1.0.22**. The upstream archive and
minisign signature are committed so a build never downloads C source. Cargo's
build script verifies the signature; `scripts/verify-build-inputs.sh` verifies
the pinned SHA-256 and the version declared inside the archive before a build.

For native MSVC, `scripts/prepare-windows-libsodium.ps1` separately verifies
the same signature with the fixed upstream key, extracts this source, and
builds the committed `vs2026` project as `ReleaseLIB|ARM64` with toolset `v145`
and `/MT`. Only the verified output directory is then passed through
`SODIUM_LIB_DIR`. This separate signature gate is required because the binding
does not authenticate a library supplied through `SODIUM_LIB_DIR`; the script
does not use the binding's precompiled-ZIP fallback.

Source: <https://download.libsodium.org/libsodium/releases/LATEST.tar.gz>

License: ISC (`LICENSE` inside the source archive). This record is an initial
build-input inventory, not a final release-license or vulnerability audit.
