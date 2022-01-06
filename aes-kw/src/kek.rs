use aes::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::BlockCipher;
use generic_array::typenum::{Unsigned, U16, U24, U32};
use generic_array::GenericArray;

const IV_LEN: usize = 8;
const IV: [u8; IV_LEN] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

use crate::Error;

/// A KEK that can be used to wrap and unwrap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Kek<Aes>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    /// Initialized cipher
    cipher: Aes,
}

impl From<GenericArray<u8, U16>> for Kek<aes::Aes128> {
    fn from(kek: GenericArray<u8, U16>) -> Self {
        Kek::new(&kek)
    }
}

impl From<GenericArray<u8, U24>> for Kek<aes::Aes192> {
    fn from(kek: GenericArray<u8, U24>) -> Self {
        Kek::new(&kek)
    }
}

impl From<GenericArray<u8, U32>> for Kek<aes::Aes256> {
    fn from(kek: GenericArray<u8, U32>) -> Self {
        Kek::new(&kek)
    }
}

impl From<[u8; 16]> for Kek<aes::Aes128> {
    fn from(kek: [u8; 16]) -> Self {
        Kek::new(&kek.into())
    }
}

impl From<[u8; 24]> for Kek<aes::Aes192> {
    fn from(kek: [u8; 24]) -> Self {
        Kek::new(&kek.into())
    }
}

impl From<[u8; 32]> for Kek<aes::Aes256> {
    fn from(kek: [u8; 32]) -> Self {
        Kek::new(&kek.into())
    }
}

impl<Aes> std::convert::TryFrom<&[u8]> for Kek<Aes>
where
    Aes: NewBlockCipher + BlockCipher<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
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
    pub fn wrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        // 0) Prepare inputs

        // number of 64 bit blocks in the input data
        let n = data.len() / 8;

        // 1) Initialize variables

        // Set A to the IV
        let mut block = GenericArray::<u8, Aes::BlockSize>::default();
        block[..IV_LEN].copy_from_slice(&IV);

        // 2) calculate intermediate values

        let mut out = vec![0u8; data.len() + IV_LEN];
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

        Ok(out)
    }

    /// AES Key Unwrap, as defined in RFC 3394.
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        // 0) Prepare inputs

        let n = (data.len() / 8) - 1;

        // 1) Initialize variables

        let mut block = GenericArray::<u8, Aes::BlockSize>::default();
        block[..IV_LEN].copy_from_slice(&data[..IV_LEN]);

        //   for i = 1 to n: R[i] = C[i]
        let mut out = vec![0u8; n * 8];
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
            Ok(out)
        } else {
            Err(Error::IntegrityCheckFailed)
        }
    }
}
