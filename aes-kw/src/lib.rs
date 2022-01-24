#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/aes-kw/0.1.0"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
//! The most common way to use AES-KW is as follows: you provide the Key Wrapping Key
//! and the key-to-be-wrapped, then wrap it, or provide a wrapped-key and unwrap it.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "std")]
//! # {
//! use aes_kw::Kek;
//! use hex_literal::hex;
//!
//! let kek = Kek::from(hex!("000102030405060708090A0B0C0D0E0F"));
//! let input_key = hex!("00112233445566778899AABBCCDDEEFF");
//!
//! let wrapped_key = kek.wrap_vec(&input_key)?;
//! assert_eq!(wrapped_key, hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));
//!
//! let unwrapped_key = kek.unwrap_vec(&wrapped_key)?;
//! assert_eq!(unwrapped_key, input_key);
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! Alternatively, AES-KWP can be used to wrap keys which are not a multiple of 8 bytes
//! long.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "std")]
//! # {
//! use aes_kw::Kek;
//! use hex_literal::hex;
//!
//! let kek = Kek::from(hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
//! let input_key = hex!("c37b7e6492584340bed12207808941155068f738");
//!
//! let wrapped_key = kek.wrap_with_padding_vec(&input_key)?;
//! assert_eq!(wrapped_key, hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"));
//!
//! let unwrapped_key = kek.unwrap_with_padding_vec(&wrapped_key)?;
//! assert_eq!(unwrapped_key, input_key);
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! Implemented for 128/192/256bit keys.

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
mod kek;

pub use error::{Error, Result};
pub use kek::{Kek, KekAes128, KekAes192, KekAes256, IV, IV_LEN};
