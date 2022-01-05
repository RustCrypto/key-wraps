# RustCrypto: Key Wrapping Functions

[![dependency status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image]

Collection of [Key Wrapping Functions][KW] (KW) written in pure Rust.

## Supported Algorithms

| Algorithm | Crate  | Crates.io     | Documentation | MSRV |
|-----------|--------|:-------------:|:-------------:|:----:|
| [AES‑KW]    | [`aes‑kw`] | [![crates.io](https://img.shields.io/crates/v/aes-kw.svg)](https://crates.io/crates/aes-kw) | [![Documentation](https://docs.rs/aes-kw/badge.svg)](https://docs.rs/aes-kw) | ![MSRV 1.56][msrv-1.56] |

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
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg

[//]: # (crates)

[`aes‑kw`]: ./aes-kw

[//]: # (algorithms)

[KW]: https://en.wikipedia.org/wiki/Key_Wrap
[AES‑KW]: https://datatracker.ietf.org/doc/html/rfc3394
[RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs
