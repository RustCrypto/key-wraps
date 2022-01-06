use crate::{Error, Result};
use aes::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::BlockCipher;
use generic_array::typenum::{Unsigned, U16, U24, U32};
use generic_array::GenericArray;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Size of an AES-KW initialization vector in bytes.
pub const IV_LEN: usize = 8;

/// Default Initial Value as defined in RFC3394 § 2.2.3.1.
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

/// A Key-Encrypting-Key (KEK) that can be used to wrap and unwrap other
/// keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kek<Aes>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    /// Initialized cipher
    cipher: Aes,
}

/// AES-128 KEK
pub type KekAes128 = Kek<aes::Aes128>;

/// AES-192 KEK
pub type KekAes192 = Kek<aes::Aes192>;

/// AES-256 KEK
pub type KekAes256 = Kek<aes::Aes256>;

impl From<GenericArray<u8, U16>> for KekAes128 {
    fn from(kek: GenericArray<u8, U16>) -> Self {
        Kek::new(&kek)
    }
}

impl From<GenericArray<u8, U24>> for KekAes192 {
    fn from(kek: GenericArray<u8, U24>) -> Self {
        Kek::new(&kek)
    }
}

impl From<GenericArray<u8, U32>> for KekAes256 {
    fn from(kek: GenericArray<u8, U32>) -> Self {
        Kek::new(&kek)
    }
}

impl From<[u8; 16]> for KekAes128 {
    fn from(kek: [u8; 16]) -> Self {
        Kek::new(&kek.into())
    }
}

impl From<[u8; 24]> for KekAes192 {
    fn from(kek: [u8; 24]) -> Self {
        Kek::new(&kek.into())
    }
}

impl From<[u8; 32]> for KekAes256 {
    fn from(kek: [u8; 32]) -> Self {
        Kek::new(&kek.into())
    }
}

impl<Aes> TryFrom<&[u8]> for Kek<Aes>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() == Aes::KeySize::to_usize() {
            Ok(Kek::new(GenericArray::from_slice(value)))
        } else {
            Err(Error::InvalidKekSize(value.len() * 8))
        }
    }
}

impl<Aes> Kek<Aes>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    /// Constructs a new Kek based on the appropriate raw key material.
    pub fn new(key: &GenericArray<u8, Aes::KeySize>) -> Self {
        let cipher = Aes::new(key);
        Kek { cipher }
    }

    /// AES Key Wrap, as defined in RFC 3394.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) longer than the length of `data`.
    pub fn wrap(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        if out.len() != data.len() + IV_LEN {
            return Err(Error::InvalidOutputSize {
                expected: data.len() + IV_LEN,
            });
        }

        // 0) Prepare inputs

        // number of 64 bit blocks in the input data
        let n = data.len() / 8;

        // 1) Initialize variables

        // Set A to the IV
        let mut block = GenericArray::<u8, Aes::BlockSize>::default();
        block[..IV_LEN].copy_from_slice(&IV);

        // 2) calculate intermediate values
        out[IV_LEN..].copy_from_slice(data);

        for j in 0..=5 {
            for (i, chunk) in out[IV_LEN..].chunks_mut(8).enumerate() {
                // A | R[i]
                block[IV_LEN..].copy_from_slice(chunk);
                // B = AES(K, ..)
                self.cipher.encrypt_block(&mut block);

                // A = MSB(64, B) ^ t
                let t = (n * j + (i + 1)) as u64;
                for (ai, ti) in block[..IV_LEN].iter_mut().zip(&t.to_be_bytes()) {
                    *ai ^= ti;
                }

                // R[i] = LSB(64, B)
                chunk.copy_from_slice(&block[IV_LEN..]);
            }
        }

        // 3) output the results
        out[..IV_LEN].copy_from_slice(&block[..IV_LEN]);

        Ok(())
    }

    /// Computes [`Self::wrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn wrap_vec(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; data.len() + IV_LEN];
        self.wrap(data, &mut out)?;
        Ok(out)
    }

    /// AES Key Unwrap, as defined in RFC 3394.
    ///
    /// The `out` buffer will be overwritten, and must be exactly [`IV_LEN`]
    /// bytes (i.e. 8 bytes) shorter than the length of `data`.
    pub fn unwrap(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        // 0) Prepare inputs

        let n = (data.len() / 8)
            .checked_sub(1)
            .ok_or(Error::InvalidDataLength)?;

        if out.len() != n * 8 {
            return Err(Error::InvalidOutputSize { expected: n * 8 });
        }

        // 1) Initialize variables

        let mut block = GenericArray::<u8, Aes::BlockSize>::default();
        block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

        //   for i = 1 to n: R[i] = C[i]
        out.copy_from_slice(&data[IV_LEN..]);

        // 2) calculate intermediate values

        for j in (0..=5).rev() {
            for (i, chunk) in out.chunks_mut(8).enumerate().rev() {
                // A ^ t
                let t = (n * j + (i + 1)) as u64;
                for (ai, ti) in block[..IV_LEN].iter_mut().zip(&t.to_be_bytes()) {
                    *ai ^= ti;
                }

                // (A ^ t) | R[i]
                block[IV_LEN..].copy_from_slice(chunk);

                // B = AES-1(K, ..)
                self.cipher.decrypt_block(&mut block);

                // A = MSB(64, B)
                // already set

                // R[i] = LSB(64, B)
                chunk.copy_from_slice(&block[IV_LEN..]);
            }
        }

        // 3) output the results

        if block[..IV_LEN] == IV[..] {
            Ok(())
        } else {
            Err(Error::IntegrityCheckFailed)
        }
    }

    /// Computes [`Self::unwrap`], allocating a [`Vec`] for the return value.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn unwrap_vec(&self, data: &[u8]) -> Result<Vec<u8>> {
        let out_len = data
            .len()
            .checked_sub(IV_LEN)
            .ok_or(Error::InvalidDataLength)?;

        let mut out = vec![0u8; out_len];
        self.unwrap(data, &mut out)?;
        Ok(out)
    }
}
