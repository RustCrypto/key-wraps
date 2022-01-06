# RustCrypto: AES Key Wrap Algorithm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [NIST AES-KW Key Wrapping Method] also
described in [RFC3394].

## About

RFC3394 § 2 describes AES-KW as follows:

> The AES key wrap algorithm is designed to wrap or encrypt key data.
> The key wrap operates on blocks of 64 bits.  Before being wrapped,
> the key data is parsed into n blocks of 64 bits.
> 
> The only restriction the key wrap algorithm places on n is that n be
> at least two.  (For key data with length less than or equal to 64
> bits, the constant field used in this specification and the key data
> form a single 128-bit codebook input making this key wrap
> unnecessary.)  The key wrap algorithm accommodates all supported AES
> key sizes.  However, other cryptographic values often need to be
> wrapped.  One such value is the seed of the random number generator
> for DSS.  This seed value requires n to be greater than four.
> Undoubtedly other values require this type of protection. Therefore,
> no upper bound is imposed on n.
> 
> The AES key wrap can be configured to use any of the three key sizes
> supported by the AES codebook.  The choice of a key size affects the
> overall security provided by the key wrap, but it does not alter the
> description of the key wrap algorithm.  Therefore, in the description
> that follows, the key wrap is described generically; no key size is
> specified for the KEK.

## Minimum Supported Rust Version

This crate requires **Rust 1.56** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/aes-kw.svg
[crate-link]: https://crates.io/crates/aes-kw
[docs-image]: https://docs.rs/aes-kw/badge.svg
[docs-link]: https://docs.rs/aes-kw/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[build-image]: https://github.com/RustCrypto/key-wraps/actions/workflows/aes-kw.yml/badge.svg
[build-link]: https://github.com/RustCrypto/key-wraps/actions/workflows/aes-kw.yml

[//]: # (links)

[NIST AES-KW Key Wrapping Method]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
[RFC3394]: https://datatracker.ietf.org/doc/html/rfc3394
