# RustCrypto: Key Wrapping Functions

[![dependency status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image]

Collection of symmetric [Key Wrapping Functions][KW] (KW) written in pure Rust.

## About

"Key Wrapping" describes symmetric encryption algorithms designed for encrypting
cryptographic key material under another symmetric key, known as a
"Key-Encrypting-Key" (KEK).

They're intended for applications such as protecting keys while in untrusted
storage or transmitting keys over untrusted communications networks.

## Supported Algorithms

| Algorithm | Crate  | Crates.io     | Documentation | MSRV |
|-----------|--------|:-------------:|:-------------:|:----:|
| [AES-KW] and [AES-KWP] | [`aes‑kw`] | [![crates.io](https://img.shields.io/crates/v/aes-kw.svg)](https://crates.io/crates/aes-kw) | [![Documentation](https://docs.rs/aes-kw/badge.svg)](https://docs.rs/aes-kw) | ![MSRV 1.81][msrv-1.81] |
| [`belt-kwp`][belt-kwp-spec] | [`belt-kwp`][belt-kwp-crate] | [![crates.io](https://img.shields.io/crates/v/belt-kwp.svg)](https://crates.io/crates/belt-kwp) | [![Documentation](https://docs.rs/belt-kwp/badge.svg)](https://docs.rs/belt-kwp) | ![MSRV 1.81][msrv-1.81] |

*NOTE: for modern proven KWs (e.g. AES-SIV, AES-GCM-SIV), please see [RustCrypto/AEADs]*

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/key-wraps/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/key-wraps
[msrv-1.81]: https://img.shields.io/badge/rustc-1.81.0+-blue.svg

[//]: # (crates)

[`aes‑kw`]: ./aes-kw
[belt-kwp-crate]: ./belt-kwp

[//]: # (algorithms)

[KW]: https://en.wikipedia.org/wiki/Key_Wrap
[AES-KW]: https://datatracker.ietf.org/doc/html/rfc3394
[AES-KWP]: https://datatracker.ietf.org/doc/html/rfc5649
[belt-kwp-spec]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
[RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs
