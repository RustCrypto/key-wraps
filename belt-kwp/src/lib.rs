#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;

pub use error::{Error, Result};

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use belt_block::cipher::consts::U32;
use belt_block::cipher::generic_array::GenericArray;
use belt_block::{belt_wblock_dec, belt_wblock_enc, to_u32};

/// Block size for BelT-KWP
pub const SEMIBLOCK_LEN: usize = 8;

/// Size of an BelT-block "semiblock" in bytes.
pub const IV_LEN: usize = 16;

impl From<GenericArray<u8, U32>> for BeltKwp {
    fn from(kek: GenericArray<u8, U32>) -> Self {
        BeltKwp::new(&kek)
    }
}

impl From<[u8; 32]> for BeltKwp {
    fn from(kek: [u8; 32]) -> Self {
        BeltKwp::new(&kek.into())
    }
}

impl TryFrom<&[u8]> for BeltKwp {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() == 32 {
            Ok(BeltKwp::new(value.into()))
        } else {
            Err(Error::InvalidKekSize { size: value.len() })
        }
    }
}

/// A Key-Encrypting-Key (KEK) that can be used to wrap and unwrap other
/// keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BeltKwp {
    /// Initialized key
    key: [u32; 8],
}

impl BeltKwp {
    /// Constructs a new Kek based on the appropriate raw key material.
    pub fn new(key: &GenericArray<u8, U32>) -> Self {
        Self {
            key: to_u32::<8>(key),
        }
    }

    /// BelT Key Wrap, as defined in STB 34.101.34-2020.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 16 bytes) longer than the length of `data`.
    pub fn wrap_key(&self, x: &[u8], iv: &[u8], out: &mut [u8]) -> Result<()> {
        if x.len() % SEMIBLOCK_LEN != 0 || x.len() < 32 || iv.len() != IV_LEN {
            return Err(Error::InvalidDataSize);
        }

        if out.len() != (x.len() + IV_LEN) {
            return Err(Error::InvalidOutputSize {
                expected: x.len() + IV_LEN,
            });
        }

        out[..x.len()].copy_from_slice(x);
        out[x.len()..].copy_from_slice(iv);

        // 1. Y ← belt-wblock(X || I, K)
        belt_wblock_enc(out, &self.key).map_err(|_| Error::InvalidDataSize)
    }

    /// BelT Key Unwrap, as defined in STB 34.101.31-2020.
    ///
    /// The `out` buffer will be overwritten, and it length must be exactly the length of `data`.
    pub fn unwrap_key(&self, y: &[u8], iv: &[u8], out: &mut [u8]) -> Result<()> {
        // 1. If |Y| mod 8 ≠ 0 or |Y| < 32 or |I| ≠ 16 then return error
        if y.len() % SEMIBLOCK_LEN != 0 || y.len() < 32 || iv.len() != IV_LEN {
            return Err(Error::InvalidDataSize);
        }

        if out.len() != y.len() {
            return Err(Error::InvalidOutputSize { expected: y.len() });
        }

        out.copy_from_slice(y);

        // 2. (X || r) ← belt-wblock^(-1)(Y, K)
        belt_wblock_dec(out, &self.key).map_err(|_| Error::InvalidDataSize)?;
        // 3. If r ≠ I then return error
        if &out[y.len() - IV_LEN..] != iv {
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(())
    }

    /// Computes [`Self::wrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn wrap_vec(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; data.len() + IV_LEN];
        self.wrap_key(data, iv, &mut out)?;
        Ok(out)
    }

    /// Computes [`Self::unwrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn unwrap_vec(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; data.len()];
        self.unwrap_key(data, iv, &mut out)?;
        Ok(out)
    }
}
