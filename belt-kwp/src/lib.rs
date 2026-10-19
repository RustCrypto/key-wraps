#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use belt_block::{
    BeltBlock, belt_wblock_dec, belt_wblock_enc,
    cipher::{
        Array,
        array::ArraySize,
        consts::U16,
        typenum::{GrEq, IsGreaterOrEqual, NonZero, Sum, Unsigned},
    },
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
#[derive(Clone, PartialEq)]
pub struct BeltKwp {
    key: [u32; 8],
}

impl fmt::Debug for BeltKwp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltKwp { ... }")
    }
}

impl BeltKwp {
    /// Wrap `key` with given `iv` and write result to `dst`.
    /// The resulting slice will have size equal to `key.len() + IV_LEN`.
    ///
    /// ## Errors
    /// - If size of `key` is smaller than 16 bytes.
    /// - If size of `dst` is smaller than to `key.len() + IV_LEN`.
    #[inline]
    pub fn wrap_key<'a>(
        &self,
        key: &[u8],
        iv: &[u8; IV_LEN],
        dst: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let key_len = key.len();
        if key_len < 16 {
            return Err(Error::InvalidDataSize);
        }

        let dst = key_len
            .checked_add(IV_LEN)
            .and_then(|out_len| dst.get_mut(..out_len))
            .ok_or(Error::InvalidOutputSize {
                expected: key_len + IV_LEN,
            })?;

        let (key_dst, iv_dst) = dst.split_at_mut(key_len);
        key_dst.copy_from_slice(key);
        iv_dst.copy_from_slice(iv);

        belt_wblock_enc(dst, &self.key).expect("`dst` has correct size");
        Ok(dst)
    }

    /// Wrap the key held in `buf[..key_len]` with given `iv` in place and
    /// return the wrapped key, i.e. `buf[..key_len + IV_LEN]`.
    ///
    /// ## Errors
    /// - If `key_len` is smaller than 16 bytes.
    /// - If size of `buf` is smaller than to `key.len() + IV_LEN`.
    #[inline]
    pub fn wrap_key_in_place<'a>(
        &self,
        buf: &'a mut [u8],
        key_len: usize,
        iv: &[u8; IV_LEN],
    ) -> Result<&'a [u8], Error> {
        if key_len < 16 {
            return Err(Error::InvalidDataSize);
        }

        let dst = key_len
            .checked_add(IV_LEN)
            .and_then(|out_len| buf.get_mut(..out_len))
            .ok_or(Error::InvalidOutputSize {
                expected: key_len + IV_LEN,
            })?;

        dst[key_len..].copy_from_slice(iv);

        belt_wblock_enc(dst, &self.key).expect("`dst` has correct size");
        Ok(dst)
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
    /// ## Errors
    /// - If size of `y` is smaller than 32 bytes.
    /// - If size of `dst` is smaller than `y.len()`.
    /// - If computed IV does not match `iv`.
    #[inline]
    pub fn unwrap_key<'a>(
        &self,
        y: &[u8],
        iv: &[u8; IV_LEN],
        dst: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let out = dst
            .get_mut(..y.len())
            .ok_or(Error::InvalidOutputSize { expected: y.len() })?;
        out.copy_from_slice(y);

        self.unwrap_key_in_place(out, iv)
    }

    /// Unwrap the key held in `buf` with given `iv` in place and return the
    /// unwrapped key, i.e. `buf[..buf.len() - IV_LEN]`.
    ///
    /// ## Errors
    /// - If size of `buf` is smaller than 32 bytes.
    /// - If computed IV does not match `iv`.
    #[inline]
    pub fn unwrap_key_in_place<'a>(
        &self,
        buf: &'a mut [u8],
        iv: &[u8; IV_LEN],
    ) -> Result<&'a [u8], Error> {
        belt_wblock_dec(buf, &self.key).map_err(|_| Error::InvalidDataSize)?;

        let expected_iv = u128::from_ne_bytes(*iv);
        let (key, iv) = buf
            .split_last_chunk_mut::<IV_LEN>()
            .expect("`belt_wblock_dec` ensures that `buf.len() >= 32`");

        let calc_iv = u128::from_ne_bytes(*iv);

        // We expect that comparison of `u128`s will be constant-time
        if calc_iv == expected_iv {
            Ok(key)
        } else {
            // TODO(MSRV-?): use `buf.fill(0);`
            key.fill(0);
            iv.fill(0);
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
        let (key, calc_iv) = y
            .split_last_chunk::<IV_LEN>()
            .expect("`belt_wblock_dec` ensures that `buf.len() >= 32`");

        let calc_iv = u128::from_ne_bytes(*calc_iv);
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

impl Drop for BeltKwp {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.key.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for BeltKwp {}

/// Errors emitted from the wrap and unwrap operations.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
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
