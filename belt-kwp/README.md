# RustCrypto: BelT Key Wrap Algorithm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [BelT Key Wrap].

# Usage

The most common way to use BelT-KWP is as follows: you provide the Key Wrapping Key and the key-to-be-wrapped, then wrap it, or provide a wrapped-key and unwrap it.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# #[cfg(feature = "std")]
# {
use hex_literal::hex;
use belt_kwp::BeltKwp;

let x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D");
let i = hex!("5BE3D612 17B96181 FE6786AD 716B890B");
let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
let y = hex!("49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76 E487B055 C69BCF54 1176169F 1DC9F6C8");

let mut wrapped = [0u8; 48];
let mut unwrapped = [0u8; 48];

let kek = BeltKwp::new(&k.into());

kek.wrap_key(&x, &i, &mut wrapped).unwrap();
assert_eq!(y, wrapped);

kek.unwrap_key(&y, &i, &mut unwrapped).unwrap();
assert_eq!(x, unwrapped[..32]);
# }
# Ok(())
# }
```

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

[crate-image]: https://img.shields.io/crates/v/bel-kwp.svg
[crate-link]: https://crates.io/crates/belt-kwp
[docs-image]: https://docs.rs/belt-kwp/badge.svg
[docs-link]: https://docs.rs/belt-kwp/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[build-image]: https://github.com/RustCrypto/key-wraps/actions/workflows/belt-kwp.yml/badge.svg
[build-link]: https://github.com/RustCrypto/key-wraps/actions/workflows/belt-kwp.yml

[//]: # (links)
[BelT Key Wrap]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
