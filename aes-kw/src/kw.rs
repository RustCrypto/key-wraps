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

/// A Key-Encrypting-Key (KEK) that can be used to wrap and unwrap other keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kw<C> {
    cipher: C,
}

impl<C> InnerUser for Kw<C> {
    type Inner = C;
}

impl<C> InnerInit for Kw<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Kw { cipher }
    }
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> Kw<C> {
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
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> Kw<C> {
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
}
