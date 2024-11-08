use crate::{ctx::Ctx, Error, IV_LEN, SEMIBLOCK_SIZE};
use aes::cipher::{
    crypto_common::{InnerInit, InnerUser},
    typenum::U16,
    Block, BlockCipherDecrypt, BlockCipherEncrypt,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Maximum length of the AES-KWP input data (2^32 bytes).
const KWP_MAX_LEN: usize = u32::MAX as usize;

/// Alternative Initial Value constant prefix for AES-KWP as defined in RFC 3394 § 3.
///
/// <https://datatracker.ietf.org/doc/html/rfc5649#section-3>
///
/// ```text
/// The Alternative Initial Value (AIV) required by this specification is
//  a 32-bit constant concatenated to a 32-bit MLI.  The constant is (in
//  hexadecimal) A65959A6 and occupies the high-order half of the AIV.
/// ```
const KWP_IV_PREFIX: [u8; IV_LEN / 2] = [0xA6, 0x59, 0x59, 0xA6];

/// AES Key Wrapper with Padding (KWP), as defined in [RFC 5649].
///
/// [RFC 5649]: https://www.rfc-editor.org/rfc/rfc5649.txt
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AesKwp<C> {
    cipher: C,
}

impl<C> InnerUser for AesKwp<C> {
    type Inner = C;
}

impl<C> InnerInit for AesKwp<C> {
    #[inline]
    fn inner_init(cipher: Self::Inner) -> Self {
        AesKwp { cipher }
    }
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> AesKwp<C> {
    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    /// The `out` buffer will be overwritten, and must be the smallest
    /// multiple of [`SEMIBLOCK_SIZE`] (i.e. 8) which is at least [`IV_LEN`]
    /// bytes (i.e. 8 bytes) longer than the length of `data`.
    #[inline]
    pub fn wrap<'a>(&self, data: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if data.len() > KWP_MAX_LEN {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        // number of 64 bit blocks in the input data (padded)
        let semiblocks_len = data.len().div_ceil(SEMIBLOCK_SIZE);

        let expected_len = semiblocks_len * SEMIBLOCK_SIZE + IV_LEN;
        let buf = buf
            .get_mut(..expected_len)
            .ok_or(Error::InvalidOutputSize { expected_len })?;

        // 2) Wrapping

        // 2.1) Initialize variables

        // Set A to the AIV
        let block = &mut Block::<C>::default();
        let (prefix, mli) = block[..IV_LEN].split_at_mut(IV_LEN / 2);
        prefix.copy_from_slice(&KWP_IV_PREFIX);
        // 32-bit MLI equal to the number of bytes in the input data, big endian
        mli.copy_from_slice(&(data.len() as u32).to_be_bytes());

        // If semiblocks_len is 1, the plaintext is encrypted as a single AES block
        if semiblocks_len == 1 {
            // 1) Append padding

            block[IV_LEN..][..data.len()].copy_from_slice(data);
            self.cipher
                .encrypt_block_b2b(block, buf.try_into().unwrap());
        } else {
            // 1) Append padding

            // 2.2) Calculate intermediate values
            buf[IV_LEN..][..data.len()].copy_from_slice(data);

            self.cipher.encrypt_with_backend(Ctx {
                blocks_len: semiblocks_len,
                block,
                buf,
            });

            // 2.3) Output the results
            buf[..IV_LEN].copy_from_slice(&block[..IV_LEN]);
        }

        Ok(buf)
    }

    /// Computes [`Self::wrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn wrap_vec(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let n = data.len().div_ceil(SEMIBLOCK_SIZE);
        let mut out = vec![0u8; n * SEMIBLOCK_SIZE + IV_LEN];
        self.wrap(data, &mut out)?;
        Ok(out)
    }
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> AesKwp<C> {
    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) shorter than the length of `data`.
    /// This method returns a slice of `out`, truncated to the appropriate
    /// length by removing the padding.
    #[inline]
    pub fn unwrap<'a>(&self, data: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 || blocks_len < 1 || data.len() > KWP_MAX_LEN {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        let blocks_len = blocks_len - 1;
        let expected_len = blocks_len * SEMIBLOCK_SIZE;
        let buf = buf
            .get_mut(..expected_len)
            .ok_or(Error::InvalidOutputSize { expected_len })?;

        // 1) Key unwrapping

        // 1.1) Initialize variables

        let block = &mut Block::<C>::default();

        // If n is 1, the plaintext is encrypted as a single AES block
        if blocks_len == 1 {
            block.copy_from_slice(data);
            self.cipher.decrypt_block(block);
            buf.copy_from_slice(&block[IV_LEN..]);
        } else {
            block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

            //   for i = 1 to n: R[i] = C[i]
            buf.copy_from_slice(&data[IV_LEN..]);

            // 1.2) Calculate intermediate values

            self.cipher.decrypt_with_backend(Ctx {
                blocks_len,
                block,
                buf,
            });
        }

        // 2) AIV verification

        // Checks as defined in RFC5649 § 3

        let prefix_calc = u32::from_ne_bytes(block[..IV_LEN / 2].try_into().unwrap());
        let prefix_exp = u32::from_ne_bytes(KWP_IV_PREFIX);
        if prefix_calc != prefix_exp {
            buf.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        let mli_bytes = block[IV_LEN / 2..IV_LEN].try_into().unwrap();
        let mli: usize = usize::try_from(u32::from_be_bytes(mli_bytes)).map_err(|_| {
            buf.fill(0);
            Error::IntegrityCheckFailed
        })?;
        if mli.div_ceil(SEMIBLOCK_SIZE) != blocks_len {
            buf.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        let (res, pad) = buf.split_at_mut(mli);
        if !pad.iter().all(|&b| b == 0) {
            res.fill(0);
            pad.fill(0);
            return Err(Error::IntegrityCheckFailed);
        }

        Ok(res)
    }

    /// Computes [`Self::unwrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn unwrap_vec(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let out_len = data
            .len()
            .checked_sub(IV_LEN)
            .ok_or(Error::InvalidDataSize)?;

        let mut out = vec![0u8; out_len];

        let out_len = self.unwrap(data, &mut out)?.len();
        out.truncate(out_len);
        Ok(out)
    }
}
