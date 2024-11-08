#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "oid")]
mod oid;

mod ctx;
mod error;
mod kw;
mod kwp;

pub use error::Error;
pub use kw::Kw;
pub use kwp::Kwp;

pub use aes;
pub use aes::cipher;
pub use aes::cipher::{crypto_common::InnerInit, KeyInit};

/// AES-128 key wrapping
pub type KwAes128 = Kw<aes::Aes128>;
/// AES-192 key wrapping
pub type KwAes192 = Kw<aes::Aes192>;
/// AES-256 key wrapping
pub type KwAes256 = Kw<aes::Aes256>;

/// AES-128 key wrapping
pub type KwpAes128 = Kwp<aes::Aes128>;
/// AES-192 key wrapping
pub type KwpAes192 = Kwp<aes::Aes192>;
/// AES-256 key wrapping
pub type KwpAes256 = Kwp<aes::Aes256>;

/// Size of an AES "semiblock" in bytes.
///
/// From NIST SP 800-38F § 4.1:
///
/// > semiblock: given a block cipher, a bit string whose length is half of the block size.
pub const SEMIBLOCK_SIZE: usize = 8;

/// Size of an AES-KW and AES-KWP initialization vector in bytes.
pub const IV_LEN: usize = SEMIBLOCK_SIZE;
