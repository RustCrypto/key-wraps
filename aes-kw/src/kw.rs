use crate::{ctx::Ctx, Error, IV_LEN, SEMIBLOCK_SIZE};
use aes::cipher::{
    crypto_common::{InnerInit, InnerUser},
    typenum::U16,
    Block, BlockCipherDecrypt, BlockCipherEncrypt,
};

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
const IV: [u8; IV_LEN] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// AES Key Wrapper (KW), as defined in [RFC 3394].
///
/// [RFC 3394]: https://www.rfc-editor.org/rfc/rfc3394.txt
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AesKw<C> {
    cipher: C,
}

impl<C> InnerUser for AesKw<C> {
    type Inner = C;
}

impl<C> InnerInit for AesKw<C> {
    #[inline]
    fn inner_init(cipher: Self::Inner) -> Self {
        AesKw { cipher }
    }
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> AesKw<C> {
    /// Wrap `data` and write result to `buf`.
    ///
    /// Returns slice which points to `buf` and contains wrapped data.
    ///
    /// Length of `data` must be multiple of [`SEMIBLOCK_SIZE`] and bigger than zero.
    /// Length of `buf` must be bigger or equal to `data.len() + IV_LEN`.
    #[inline]
    pub fn wrap<'a>(&self, data: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 {
            return Err(Error::InvalidDataSize);
        }

        let expected_len = data.len() + IV_LEN;
        let buf = buf
            .get_mut(..expected_len)
            .ok_or(Error::InvalidOutputSize { expected_len })?;

        // 1) Initialize variables

        // Set A to the IV
        let block = &mut Block::<C>::default();
        block[..IV_LEN].copy_from_slice(&IV);

        // 2) Calculate intermediate values
        buf[IV_LEN..].copy_from_slice(data);

        self.cipher.encrypt_with_backend(Ctx {
            blocks_len,
            block,
            buf,
        });

        // 3) Output the results
        buf[..IV_LEN].copy_from_slice(&block[..IV_LEN]);

        Ok(buf)
    }
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> AesKw<C> {
    /// Unwrap `data` and write result to `buf`.
    ///
    /// Returns slice which points to `buf` and contains unwrapped data.
    ///
    /// Length of `data` must be multiple of [`SEMIBLOCK_SIZE`] and bigger than zero.
    /// Length of `buf` must be bigger or equal to `data.len()`.
    #[inline]
    pub fn unwrap<'a>(&self, data: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let blocks_len = data.len() / SEMIBLOCK_SIZE;
        let blocks_rem = data.len() % SEMIBLOCK_SIZE;
        if blocks_rem != 0 || blocks_len < 1 {
            return Err(Error::InvalidDataSize);
        }

        // 0) Prepare inputs

        let blocks_len = blocks_len - 1;

        let expected_len = blocks_len * SEMIBLOCK_SIZE;
        let buf = buf
            .get_mut(..expected_len)
            .ok_or(Error::InvalidOutputSize { expected_len })?;

        // 1) Initialize variables

        let block = &mut Block::<C>::default();
        block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

        //   for i = 1 to n: R[i] = C[i]
        buf.copy_from_slice(&data[IV_LEN..]);

        // 2) Calculate intermediate values

        self.cipher.decrypt_with_backend(Ctx {
            blocks_len,
            block,
            buf,
        });

        // 3) Output the results

        let expected_iv = u64::from_ne_bytes(IV);
        let calc_iv = u64::from_ne_bytes(block[..IV_LEN].try_into().unwrap());
        if calc_iv == expected_iv {
            Ok(buf)
        } else {
            buf.fill(0);
            Err(Error::IntegrityCheckFailed)
        }
    }
}
