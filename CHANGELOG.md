# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-11-20

### Security

- The curve stack moved to the RustCrypto 0.14 line in one tree (`ecdsa` 0.17,
  `elliptic-curve` 0.14, `sha2` 0.11). The 0.13 line pulled `crypto-bigint` 0.5,
  flagged as RUSTSEC-2026-0387, into every consumer's build.

### Added

- brainpoolP256r1 and brainpoolP384r1 in pure Rust: features `curve-bp256` and
  `curve-bp384`, with `BrainpoolP256r1Signer` and `BrainpoolP384r1Signer`. A build
  without OpenSSL now checks six of the seven `[OCMF Tab. 22]` algorithms.
- `ocmf sign --curve brainpool-p256r1 | brainpool-p384r1`.
- `brew install hupe1980/tap/ocmf`.

### Changed

- **Breaking:** `curves-pure` enables six curves instead of four.
- **Breaking:** an `EVCCID` `ID` is well-formed when it is even-length hex of at most
  12 characters (≤ 6 bytes, ISO 15118-2), following the specification at `e0a26be`;
  it was "at most 6 characters". The conformance suite has 163 cases.
- `curve-p192` depends on `p192` 0.14.0-rc.15, the only pre-release in the graph;
  no other feature pulls it in.
- The OpenSSL backend is needed only for secp192k1.
- Releases publish to crates.io by Trusted Publishing.

## [0.1.0] — 2026-09-02

First release.

[Unreleased]: https://github.com/hupe1980/ocmf/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hupe1980/ocmf/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/ocmf/releases/tag/v0.1.0
