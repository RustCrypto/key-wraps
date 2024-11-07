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

mod error;

pub use error::Error;

use aes::cipher::{
    crypto_common::InnerUser, typenum::U16, Block, BlockCipherDecBackend, BlockCipherDecClosure,
    BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockSizeUser,
};

pub use aes::cipher::{self, crypto_common::InnerInit, KeyInit};

/// Size of an AES "semiblock" in bytes.
///
/// From NIST SP 800-38F § 4.1:
///
/// > semiblock: given a block cipher, a bit string whose length is half of the block size.
pub const SEMIBLOCK_SIZE: usize = 8;

/// Maximum length of the AES-KWP input data (2^32 bytes).
pub const KWP_MAX_LEN: usize = u32::MAX as usize;

/// Size of an AES-KW and AES-KWP initialization vector in bytes.
pub const IV_LEN: usize = SEMIBLOCK_SIZE;

/// Default Initial Value for AES-KW as defined in RFC3394 § 2.2.3.1.
///
/// <https://datatracker.ietf.org/doc/html/rfc3394#section-2.2.3.1>
///
/// ```text
/// The default initial value (IV) is defined to be the hexadecimal
/// constant:
///
///     A[0] = IV = A6A6A6A6A6A6A6A6
///
/// The use of a constant as the IV supports a strong integrity check on
/// the key data during the period that it is wrapped.  If unwrapping
/// produces A[0] = A6A6A6A6A6A6A6A6, then the chance that the key data
/// is corrupt is 2^-64.  If unwrapping produces A[0] any other value,
/// then the unwrap must return an error and not return any key data.
/// ```
pub const IV: [u8; IV_LEN] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// Alternative Initial Value constant prefix for AES-KWP as defined in
/// RFC3394 § 3.
///
/// <https://datatracker.ietf.org/doc/html/rfc5649#section-3>
///
/// ```text
/// The Alternative Initial Value (AIV) required by this specification is
//  a 32-bit constant concatenated to a 32-bit MLI.  The constant is (in
//  hexadecimal) A65959A6 and occupies the high-order half of the AIV.
/// ```
pub const KWP_IV_PREFIX: [u8; IV_LEN / 2] = [0xA6, 0x59, 0x59, 0xA6];

/// A Key-Encrypting-Key (KEK) that can be used to wrap and unwrap other keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kek<C> {
    /// Initialized cipher
    cipher: C,
}

/// AES-128 KEK
pub type KekAes128 = Kek<aes::Aes128>;

/// AES-192 KEK
pub type KekAes192 = Kek<aes::Aes192>;

/// AES-256 KEK
pub type KekAes256 = Kek<aes::Aes256>;

impl<C: BlockCipherEncrypt<BlockSize = U16>> Kek<C> {
    /// AES Key Wrap, as defined in RFC 3394.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) longer than the length of `data`.
    pub fn wrap(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 {
            return Err(Error::InvalidDataSize);
        }

        let expected_len = data.len() + IV_LEN;
        if out.len() != expected_len {
            return Err(Error::InvalidOutputSize { expected_len });
        }

        // 1) Initialize variables

        // Set A to the IV
        let block = &mut Block::<C>::default();
        block[..IV_LEN].copy_from_slice(&IV);

        // 2) Calculate intermediate values
        out[IV_LEN..].copy_from_slice(data);

        self.cipher.encrypt_with_backend(Ctx {
            blocks_len,
            block,
            out,
        });

        // 3) Output the results
        out[..IV_LEN].copy_from_slice(&block[..IV_LEN]);

        Ok(())
    }

    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    ///
    /// The `out` buffer will be overwritten, and must be the smallest
    /// multiple of [`SEMIBLOCK_SIZE`] (i.e. 8) which is at least [`IV_LEN`]
    /// bytes (i.e. 8 bytes) longer than the length of `data`.
    pub fn wrap_with_padding(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if data.len() > KWP_MAX_LEN {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        // number of 64 bit blocks in the input data (padded)
        let n = data.len().div_ceil(SEMIBLOCK_SIZE);

        let expected_len = n * SEMIBLOCK_SIZE + IV_LEN;
        if out.len() != expected_len {
            return Err(Error::InvalidOutputSize { expected_len });
        }

        // 32-bit MLI equal to the number of bytes in the input data, big endian
        let mli = (data.len() as u32).to_be_bytes();

        // 2) Wrapping

        // 2.1) Initialize variables

        // Set A to the AIV
        let block = &mut Block::<C>::default();
        block[..IV_LEN / 2].copy_from_slice(&KWP_IV_PREFIX);
        block[IV_LEN / 2..IV_LEN].copy_from_slice(&mli);

        // If n is 1, the plaintext is encrypted as a single AES block
        if n == 1 {
            // 1) Append padding

            // Arrays should be zero by default, but zeroize again to be sure
            for i in data.len()..n * SEMIBLOCK_SIZE {
                block[IV_LEN + i] = 0;
            }

            block[IV_LEN..IV_LEN + data.len()].copy_from_slice(data);

            self.cipher.encrypt_block(block);
            out.copy_from_slice(block);
        } else {
            // 1) Append padding

            // Don't trust the caller to provide a zeroized out buffer, zeroize again to be sure
            for i in data.len()..n * SEMIBLOCK_SIZE {
                out[IV_LEN + i] = 0;
            }

            // 2.2) Calculate intermediate values
            out[IV_LEN..IV_LEN + data.len()].copy_from_slice(data);

            self.cipher.encrypt_with_backend(Ctx {
                blocks_len: n,
                block,
                out,
            });

            // 2.3) Output the results
            out[..IV_LEN].copy_from_slice(&block[..IV_LEN]);
        }

        Ok(())
    }
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> Kek<C> {
    /// AES Key Unwrap, as defined in RFC 3394.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) shorter than the length of `data`.
    pub fn unwrap(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 || blocks_len < 1 {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        let blocks_len = blocks_len - 1;

        let expected_len = blocks_len * SEMIBLOCK_SIZE;
        if out.len() != expected_len {
            return Err(Error::InvalidOutputSize { expected_len });
        }

        // 1) Initialize variables

        let block = &mut Block::<C>::default();
        block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

        //   for i = 1 to n: R[i] = C[i]
        out.copy_from_slice(&data[IV_LEN..]);

        // 2) Calculate intermediate values

        self.cipher.decrypt_with_backend(Ctx {
            blocks_len,
            block,
            out,
        });

        // 3) Output the results

        let expected_iv = u64::from_ne_bytes(IV);
        let calc_iv = u64::from_ne_bytes(block[..IV_LEN].try_into().unwrap());
        if calc_iv == expected_iv {
            Ok(())
        } else {
            out.fill(0);
            Err(Error::IntegrityCheckFailed)
        }
    }

    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) shorter than the length of `data`.
    /// This method returns a slice of `out`, truncated to the appropriate
    /// length by removing the padding.
    pub fn unwrap_with_padding<'a>(
        &self,
        data: &[u8],
        out: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 || blocks_len < 1 {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        let n = blocks_len - 1;
        let expected_len = n * SEMIBLOCK_SIZE;
        if out.len() != expected_len {
            return Err(Error::InvalidOutputSize { expected_len });
        }

        // 1) Key unwrapping

        // 1.1) Initialize variables

        let block = &mut Block::<C>::default();

        // If n is 1, the plaintext is encrypted as a single AES block
        if n == 1 {
            block.copy_from_slice(data);

            self.cipher.decrypt_block(block);
            out.copy_from_slice(&block[IV_LEN..]);
        } else {
            block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

            //   for i = 1 to n: R[i] = C[i]
            out.copy_from_slice(&data[IV_LEN..]);

            // 1.2) Calculate intermediate values

            self.cipher.decrypt_with_backend(Ctx {
                blocks_len: n,
                block,
                out,
            });
        }

        // 2) AIV verification

        // Checks as defined in RFC5649 § 3

        if block[..IV_LEN / 2] != KWP_IV_PREFIX {
            out.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        let mli = u32::from_be_bytes(block[IV_LEN / 2..IV_LEN].try_into().unwrap()) as usize;
        if !(SEMIBLOCK_SIZE * (n - 1) < mli && mli <= SEMIBLOCK_SIZE * n) {
            out.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        let b = SEMIBLOCK_SIZE * n - mli;
        if !out.iter().rev().take(b).all(|&x| x == 0) {
            out.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        // 3) Output the results

        Ok(&out[..mli])
    }
}

impl<C> InnerUser for Kek<C> {
    type Inner = C;
}

impl<C> InnerInit for Kek<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Kek { cipher }
    }
}

struct Ctx<'a> {
    blocks_len: usize,
    block: &'a mut Block<Self>,
    out: &'a mut [u8],
}

impl BlockSizeUser for Ctx<'_> {
    type BlockSize = U16;
}

/// Very similar to the W(S) function defined by NIST in SP 800-38F, Section 6.1
impl BlockCipherEncClosure for Ctx<'_> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        for j in 0..=5 {
            for (i, chunk) in self.out.chunks_mut(SEMIBLOCK_SIZE).skip(1).enumerate() {
                // A | R[i]
                self.block[IV_LEN..].copy_from_slice(chunk);
                // B = AES(K, ..)
                backend.encrypt_block(self.block.into());

                // A = MSB(64, B) ^ t
                let t = (self.blocks_len * j + (i + 1)) as u64;
                for (ai, ti) in self.block[..IV_LEN].iter_mut().zip(&t.to_be_bytes()) {
                    *ai ^= ti;
                }

                // R[i] = LSB(64, B)
                chunk.copy_from_slice(&self.block[IV_LEN..]);
            }
        }
    }
}

/// Very similar to the W^-1(S) function defined by NIST in SP 800-38F, Section 6.1
impl BlockCipherDecClosure for Ctx<'_> {
    #[inline(always)]
    fn call<B: BlockCipherDecBackend<BlockSize = U16>>(self, backend: &B) {
        for j in (0..=5).rev() {
            for (i, chunk) in self.out.chunks_mut(SEMIBLOCK_SIZE).enumerate().rev() {
                // A ^ t
                let t = (self.blocks_len * j + (i + 1)) as u64;
                for (ai, ti) in self.block[..IV_LEN].iter_mut().zip(&t.to_be_bytes()) {
                    *ai ^= ti;
                }

                // (A ^ t) | R[i]
                self.block[IV_LEN..].copy_from_slice(chunk);

                // B = AES-1(K, ..)
                backend.decrypt_block(self.block.into());

                // A = MSB(64, B)
                // already set

                // R[i] = LSB(64, B)
                chunk.copy_from_slice(&self.block[IV_LEN..]);
            }
        }
    }
}
