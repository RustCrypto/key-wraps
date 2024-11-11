#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use belt_block::{
    belt_wblock_dec, belt_wblock_enc,
    cipher::{
        array::ArraySize,
        consts::U16,
        typenum::{GrEq, IsGreaterOrEqual, NonZero, Sum, Unsigned},
        Array,
    },
    BeltBlock,
};
use core::{fmt, ops::Add};

pub use belt_block::cipher::{self, Key, KeyInit, KeySizeUser};

/// Size of wrapping "header" represented as a `typenum` type.
pub type IvLen = U16;
/// Type alias representing wrapped key roughly equivalent to `[u8; N + IV_LEN]`.
pub type WrappedKey<N> = Array<u8, Sum<N, IvLen>>;
/// Size of wrapping "header".
pub const IV_LEN: usize = IvLen::USIZE;

/// BelT Key Wrap instance as defined in STB 34.101.34-2020.
#[derive(Clone, Copy, PartialEq)]
pub struct BeltKwp {
    key: [u32; 8],
}

impl fmt::Debug for BeltKwp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltKwp { ... }")
    }
}

impl BeltKwp {
    /// Wrap key `x` with given `iv` and write result to `out`.
    ///
    /// Size of `x` must be bigger than 16 bytes.
    /// Size of `out` must be bigger or equal to x.len() + [IV_LEN].
    #[inline]
    pub fn wrap_key<'a>(
        &self,
        x: &[u8],
        iv: &[u8; IV_LEN],
        out: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if x.len() < 16 {
            return Err(Error::InvalidDataSize);
        }

        let out_len = x.len() + IV_LEN;
        if out.len() < out_len {
            return Err(Error::InvalidOutputSize {
                expected: x.len() + IV_LEN,
            });
        }
        let out = &mut out[..out_len];

        let (l, r) = out.split_at_mut(x.len());
        l.copy_from_slice(x);
        r.copy_from_slice(iv);

        belt_wblock_enc(out, &self.key).map_err(|_| Error::InvalidDataSize)?;
        Ok(out)
    }

    /// Wrap fixed-size key `x` with given `iv` and return resulting array.
    ///
    /// This method is roughly equivalent to:
    /// ```ignore
    /// fn wrap_fixed_key<const N: usize>(
    ///     &self,
    ///     x: &[u8; N],
    ///     iv: &[u8; IV_LEN],
    /// ) -> [u8; N + IV_LEN]
    /// where
    ///     // This bound enforces that N is not smaller than `IV_LEN`
    ///     [(); N - IV_LEN]: Sized,
    /// { ... }
    /// ```
    /// but uses [`hybrid_array::Array`][Array] instead of built-in arrays
    /// to work around current limitations of the const generics system.
    #[inline]
    pub fn wrap_fixed_key<N>(&self, x: &Array<u8, N>, iv: &[u8; IV_LEN]) -> WrappedKey<N>
    where
        N: ArraySize + Add<IvLen> + IsGreaterOrEqual<IvLen>,
        Sum<N, IvLen>: ArraySize,
        GrEq<N, IvLen>: NonZero,
    {
        let mut res = WrappedKey::<N>::default();
        let (l, r) = res.split_at_mut(x.len());
        l.copy_from_slice(x);
        r.copy_from_slice(iv);

        belt_wblock_enc(&mut res, &self.key).expect("res has correct size");
        res
    }

    /// Unwrap key in `y` with given `iv` and write result to `out`.
    ///
    /// Size of wrapped data `y` must be bigger or equal to 32 bytes.
    /// Size of `out` must be bigger or equal to the size of `y`.
    #[inline]
    pub fn unwrap_key<'a>(
        &self,
        y: &[u8],
        iv: &[u8; IV_LEN],
        out: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if y.len() < 32 {
            return Err(Error::InvalidDataSize);
        }

        if out.len() < y.len() {
            return Err(Error::InvalidOutputSize { expected: y.len() });
        }

        let out = &mut out[..y.len()];
        out.copy_from_slice(y);

        belt_wblock_dec(out, &self.key).map_err(|_| Error::InvalidDataSize)?;

        let (key, rem) = out.split_at_mut(y.len() - IV_LEN);

        let calc_iv = u128::from_ne_bytes(rem.try_into().unwrap());
        let expected_iv = u128::from_ne_bytes(*iv);
        // We expect that comparison of `u128`s will be constant-time
        if calc_iv == expected_iv {
            Ok(key)
        } else {
            key.fill(0);
            rem.fill(0);
            Err(Error::IntegrityCheckFailed)
        }
    }

    /// Unwrap key in `y` with given `iv` and return resulting key.
    ///
    /// This method is roughly equivalent to:
    /// ```ignore
    /// fn unwrap_fixed_key<const N: usize>(
    ///     &self,
    ///     x: &[u8; N + IV_LEN],
    ///     iv: &[u8; IV_LEN],
    /// ) -> [u8; N]
    /// where
    ///     // This bound enforces that N is not smaller than `IV_LEN`
    ///     [(); N - IV_LEN]: Sized,
    /// { ... }
    /// ```
    /// but uses [`hybrid_array::Array`][Array] instead of built-in arrays
    /// to work around current limitations of the const generics system.
    #[inline]
    pub fn unwrap_fixed_key<N>(
        &self,
        y: &WrappedKey<N>,
        iv: &[u8; IV_LEN],
    ) -> Result<Array<u8, N>, IntegrityCheckFailed>
    where
        N: ArraySize + Add<IvLen> + IsGreaterOrEqual<IvLen>,
        Sum<N, IvLen>: ArraySize,
        GrEq<N, IvLen>: NonZero,
    {
        let mut y = y.clone();

        belt_wblock_dec(&mut y, &self.key).expect("y has correct size");

        // We could've used `Array:split`, but it's easier to do it this way
        let (key, rem) = y.split_at(N::USIZE);

        let calc_iv = u128::from_ne_bytes(rem.try_into().unwrap());
        let expected_iv = u128::from_ne_bytes(*iv);
        // We expect that comparison of `u128`s will be constant-time
        if calc_iv == expected_iv {
            Ok(key.try_into().unwrap())
        } else {
            Err(IntegrityCheckFailed)
        }
    }
}

impl KeyInit for BeltKwp {
    fn new(key: &Key<Self>) -> Self {
        let mut res = [0u32; 8];
        res.iter_mut()
            .zip(key.chunks_exact(4))
            .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));

        Self { key: res }
    }
}

impl KeySizeUser for BeltKwp {
    type KeySize = <BeltBlock as KeySizeUser>::KeySize;

    fn key_size() -> usize {
        BeltBlock::key_size()
    }
}

/// Errors emitted from the wrap and unwrap operations.
#[derive(Debug)]
pub enum Error {
    /// Input data length invalid.
    InvalidDataSize,

    /// Output buffer size invalid.
    InvalidOutputSize {
        /// Expected size in bytes.
        expected: usize,
    },

    /// Integrity check did not pass.
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidDataSize => f.write_str("invalid data size"),
            Error::InvalidOutputSize { expected } => {
                write!(f, "invalid output buffer size: expected {expected}")
            }
            Error::IntegrityCheckFailed => f.write_str("integrity check failed"),
        }
    }
}

impl core::error::Error for Error {}

/// Error that indicates integrity check failure.
#[derive(Clone, Copy, Debug)]
pub struct IntegrityCheckFailed;

impl fmt::Display for IntegrityCheckFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("integrity check failed")
    }
}

impl core::error::Error for IntegrityCheckFailed {}
