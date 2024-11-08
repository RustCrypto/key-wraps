use crate::{ctx::Ctx, Error, IV_LEN, SEMIBLOCK_SIZE};
use aes::cipher::{
    crypto_common::{InnerInit, InnerUser},
    typenum::U16,
    Block, BlockCipherDecrypt, BlockCipherEncrypt,
};

/// Maximum length of the AES-KWP input data (2^32 bytes).
pub const KWP_MAX_LEN: usize = u32::MAX as usize;

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
const KWP_IV_PREFIX: [u8; IV_LEN / 2] = [0xA6, 0x59, 0x59, 0xA6];

/// A Key-Encrypting-Key (KEK) that can be used to wrap and unwrap other keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kwp<C> {
    cipher: C,
}

impl<C> InnerUser for Kwp<C> {
    type Inner = C;
}

impl<C> InnerInit for Kwp<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Kwp { cipher }
    }
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> Kwp<C> {
    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    ///
    /// The `out` buffer will be overwritten, and must be the smallest
    /// multiple of [`SEMIBLOCK_SIZE`] (i.e. 8) which is at least [`IV_LEN`]
    /// bytes (i.e. 8 bytes) longer than the length of `data`.
    pub fn wrap(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
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

impl<C: BlockCipherDecrypt<BlockSize = U16>> Kwp<C> {
    /// AES Key Wrap with Padding, as defined in RFC 5649.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) shorter than the length of `data`.
    /// This method returns a slice of `out`, truncated to the appropriate
    /// length by removing the padding.
    pub fn unwrap<'a>(&self, data: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Error> {
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
