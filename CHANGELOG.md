# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/jdx/sigstore-verification/compare/v0.2.1...v0.2.2) - 2026-04-04

### Added

- add builder pattern for customizable GitHub API URL ([#36](https://github.com/jdx/sigstore-verification/pull/36))

### Fixed

- generate Cargo.lock before security audit ([#24](https://github.com/jdx/sigstore-verification/pull/24))

### Other

- *(deps)* pin dtolnay/rust-toolchain action to 29eef33 ([#33](https://github.com/jdx/sigstore-verification/pull/33))
- *(deps)* update jdx/mise-action digest to 1648a78 ([#34](https://github.com/jdx/sigstore-verification/pull/34))
- *(deps)* update jdx/mise-action action to v4 ([#31](https://github.com/jdx/sigstore-verification/pull/31))
- *(deps)* update swatinem/rust-cache digest to e18b497 ([#30](https://github.com/jdx/sigstore-verification/pull/30))
- *(deps)* update release-plz/action digest to 1528104 ([#29](https://github.com/jdx/sigstore-verification/pull/29))
- *(deps)* update jdx/mise-action digest to 5228313 ([#28](https://github.com/jdx/sigstore-verification/pull/28))
- *(deps)* update jdx/mise-action digest to e79ddf6 ([#27](https://github.com/jdx/sigstore-verification/pull/27))
- *(deps)* pin dependencies ([#26](https://github.com/jdx/sigstore-verification/pull/26))

## [0.2.1](https://github.com/jdx/sigstore-verification/compare/v0.2.0...v0.2.1) - 2026-02-15

### Added

- support snappy compressed bundles ([#22](https://github.com/jdx/sigstore-verification/pull/22))

### Fixed

- set github auth token only for api.github.com ([#23](https://github.com/jdx/sigstore-verification/pull/23))

### Other

- use fine-grained PAT for release-plz ([#21](https://github.com/jdx/sigstore-verification/pull/21))
- *(deps)* bump sigstore from 0.12 to 0.13 ([#19](https://github.com/jdx/sigstore-verification/pull/19))
- *(deps)* update rustsec/audit-check action to v2 ([#15](https://github.com/jdx/sigstore-verification/pull/15))
- add release-plz and cargo-semver-checks ([#18](https://github.com/jdx/sigstore-verification/pull/18))
- *(deps)* update actions/checkout digest to de0fac2 ([#17](https://github.com/jdx/sigstore-verification/pull/17))
- *(deps)* update jdx/mise-action digest to 6d1e696 ([#16](https://github.com/jdx/sigstore-verification/pull/16))
- *(deps)* update jdx/mise-action action to v3 ([#14](https://github.com/jdx/sigstore-verification/pull/14))
- *(deps)* update actions/checkout action to v6 ([#13](https://github.com/jdx/sigstore-verification/pull/13))
