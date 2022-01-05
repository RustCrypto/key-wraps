use aes::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::BlockCipher;
use generic_array::typenum::{U16, U24, U32};
use generic_array::GenericArray;

const IV_LEN: usize = 8;
const IV: [u8; IV_LEN] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

use crate::Error;

/// A KEK that can be used to wrap and unwrap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kek {
    /// 128bit sized Kek
    Aes128(GenericArray<u8, U16>),
    /// 192bit sized Kek
    Aes192(GenericArray<u8, U24>),
    /// 256bit sized Kek
    Aes256(GenericArray<u8, U32>),
}

impl From<GenericArray<u8, U16>> for Kek {
    fn from(kek: GenericArray<u8, U16>) -> Self {
        Kek::Aes128(kek)
    }
}

impl From<GenericArray<u8, U24>> for Kek {
    fn from(kek: GenericArray<u8, U24>) -> Self {
        Kek::Aes192(kek)
    }
}

impl From<GenericArray<u8, U32>> for Kek {
    fn from(kek: GenericArray<u8, U32>) -> Self {
        Kek::Aes256(kek)
    }
}

impl From<[u8; 16]> for Kek {
    fn from(kek: [u8; 16]) -> Self {
        Kek::Aes128(kek.into())
    }
}

impl From<[u8; 24]> for Kek {
    fn from(kek: [u8; 24]) -> Self {
        Kek::Aes192(kek.into())
    }
}

impl From<[u8; 32]> for Kek {
    fn from(kek: [u8; 32]) -> Self {
        Kek::Aes256(kek.into())
    }
}

impl std::convert::TryFrom<&[u8]> for Kek {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() * 8 {
            128 => Ok(Kek::Aes128(GenericArray::clone_from_slice(value))),
            192 => Ok(Kek::Aes192(GenericArray::clone_from_slice(value))),
            256 => Ok(Kek::Aes256(GenericArray::clone_from_slice(value))),
            v => Err(Error::InvalidKekSize(v)),
        }
    }
}

impl std::convert::TryFrom<Vec<u8>> for Kek {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.len() * 8 {
            128 => Ok(Kek::Aes128(GenericArray::clone_from_slice(&value))),
            192 => Ok(Kek::Aes192(GenericArray::clone_from_slice(&value))),
            256 => Ok(Kek::Aes256(GenericArray::clone_from_slice(&value))),
            v => Err(Error::InvalidKekSize(v)),
        }
    }
}

impl Kek {
    /// AES Key Wrap
    /// As defined in RFC 3394.
    pub fn wrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        match self {
            Kek::Aes128(kek) => {
                let cipher = aes::Aes128::new(kek);
                let res = wrap_inner(cipher, data);
                Ok(res)
            }
            Kek::Aes192(kek) => {
                let cipher = aes::Aes192::new(kek);
                let res = wrap_inner(cipher, data);
                Ok(res)
            }
            Kek::Aes256(kek) => {
                let cipher = aes::Aes256::new(kek);
                let res = wrap_inner(cipher, data);
                Ok(res)
            }
        }
    }

    /// AES Key Unwrap
    /// As defined in RFC 3394.
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() % 8 != 0 {
            return Err(Error::InvalidDataLength);
        }

        match self {
            Kek::Aes128(kek) => {
                let cipher = aes::Aes128::new(kek);
                unwrap_inner(cipher, data)
            }
            Kek::Aes192(kek) => {
                let cipher = aes::Aes192::new(kek);
                unwrap_inner(cipher, data)
            }
            Kek::Aes256(kek) => {
                let cipher = aes::Aes256::new(kek);
                unwrap_inner(cipher, data)
            }
        }
    }
}

#[inline]
fn wrap_inner<T: BlockEncrypt + BlockCipher + Clone>(cipher: T, data: &[u8]) -> Vec<u8> {
    // 0) Prepare inputs

    // number of 64 bit blocks in the input data
    let n = data.len() / 8;

    // 1) Initialize variables

    // Set A to the IV
    let mut block = GenericArray::<u8, T::BlockSize>::default();
    block[..IV_LEN].copy_from_slice(&IV);

    // 2) calculate intermediate values

    let mut out = vec![0u8; data.len() + IV_LEN];
    out[IV_LEN..].copy_from_slice(data);

    for j in 0..=5 {
        for (i, chunk) in out[IV_LEN..].chunks_mut(8).enumerate() {
            // A | R[i]
            block[IV_LEN..].copy_from_slice(chunk);
            // B = AES(K, ..)
            cipher.encrypt_block(&mut block);

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
    out
}

#[inline]
fn unwrap_inner<T: BlockDecrypt + BlockCipher + Clone>(
    cipher: T,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    // 0) Prepare inputs

    let n = (data.len() / 8) - 1;

    // 1) Initialize variables

    let mut block = GenericArray::<u8, T::BlockSize>::default();
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
            cipher.decrypt_block(&mut block);

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
