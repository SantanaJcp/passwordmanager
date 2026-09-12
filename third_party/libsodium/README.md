# Fixed libsodium C build input

`LATEST.tar.gz` is the filename required by `libsodium-sys-stable` 1.24.0,
but its content is fixed here to libsodium **1.0.22**. The upstream archive and
minisign signature are committed so a build never downloads C source. Cargo's
build script verifies the signature; `scripts/verify-build-inputs.sh` verifies
the pinned SHA-256 and the version declared inside the archive before a build.

Source: <https://download.libsodium.org/libsodium/releases/LATEST.tar.gz>

License: ISC (`LICENSE` inside the source archive). This record is an initial
build-input inventory, not a final release-license or vulnerability audit.
