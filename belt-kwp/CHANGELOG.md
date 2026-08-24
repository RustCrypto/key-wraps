# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- `wrap_key_in_place` and `unwrap_key_in_place` methods ([#98])

[#98]: https://github.com/RustCrypto/key-wraps/pull/98

## 0.2.0 (2026-05-27)
### Added
- Optional `zeroize` support ([#88])
- Implementation of `Clone`, `Copy`, `Eq`, `PartialEq`, and `Hash` traits for `Error` ([#89])

### Removed
- `std` and `alloc` crate features ([#87])
- Implementation of `Copy` for `BeltKwp` ([#88])

[#87]: https://github.com/RustCrypto/key-wraps/pull/87
[#88]: https://github.com/RustCrypto/key-wraps/pull/88
[#89]: https://github.com/RustCrypto/key-wraps/pull/89

## 0.1.1 (2026-05-27)
### Changed
- Use `doc_cfg` instead of `doc_auto_cfg` ([#83])

[#83]: https://github.com/RustCrypto/key-wraps/pull/83

## 0.1.0 (2026-04-10)
Initial release ([#31])

[#31]: https://github.com/RustCrypto/key-wraps/pull/31
