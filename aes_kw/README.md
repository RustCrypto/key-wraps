# RustCrypto: key-wraps

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Pure Rust implementation of KW, the [NIST AES-KW key Wrapping Method](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf). Original implementation by @dignifiedquire [here](https://github.com/rpgp/rpgp/blob/master/src/crypto/aes_kw.rs).

# Usage

The most common way to use KW is as follows: you provide the Key Wrapping Key
and the key-to-be-wrapped, then wrap it, or provide a wrapped-key and unwrap it.

```rust
use aes_kw::*;
use hex_literal::hex;
use std::{assert_eq,assert};

let kek = hex!("000102030405060708090A0B0C0D0E0F");
let input_key = hex!("00112233445566778899AABBCCDDEEFF");

let wrapped_key = wrap(&kek, &input_key).unwrap();
assert_eq!(wrapped_key, hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));

let unwrapped_key = unwrap(&kek, &wrapped_key);

match unwrapped_key {
  Ok(unwrapped_key) => {
    assert_eq!(unwrapped_key, input_key);
  }
  Err(err) => {
    assert!(false,"Unwrap key failed {:?}", err);
  }
}
```

Implemented for 128/192/256bit keys.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/aes-kw.svg
[crate-link]: https://crates.io/crates/aes-kw
[docs-image]: https://docs.rs/aes-kw/badge.svg
[docs-link]: https://docs.rs/aes-kw/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[build-image]: https://github.com/RustCrypto/key-wraps/workflows/aes-kw/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/key-wraps/actions?query=workflow:aes-kw
