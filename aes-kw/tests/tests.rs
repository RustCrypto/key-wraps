use aes_kw::Kek;

use std::assert_eq;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes_kw {
        ($name:ident, $kek_typ:ty, $kek:expr, $input:expr, $output:expr) => {
            #[test]
            fn $name() {
                use std::convert::TryFrom;

                let kek = Kek::<$kek_typ>::try_from(&hex::decode($kek).unwrap()[..]).unwrap();
                let input_bin = hex::decode($input).unwrap();
                let output_bin = hex::decode($output).unwrap();

                assert_eq!(
                    hex::encode(kek.wrap(&input_bin).unwrap()),
                    $output.to_lowercase(),
                    "failed wrap"
                );
                assert_eq!(
                    hex::encode(kek.unwrap(&output_bin).unwrap()),
                    $input.to_lowercase(),
                    "failed unwrap"
                );
            }
        };
    }

    test_aes_kw!(
        wrap_unwrap_128_key_128_kek,
        aes::Aes128,
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    );

    test_aes_kw!(
        wrap_unwrap_128_key_192_kek,
        aes::Aes192,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    );

    test_aes_kw!(
        wrap_unwrap_128_key_256_kek,
        aes::Aes256,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    );
    test_aes_kw!(
        wrap_unwrap_192_key_192_kek,
        aes::Aes192,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    );
    test_aes_kw!(
        wrap_unwrap_192_key_256_kek,
        aes::Aes256,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    );
    test_aes_kw!(
        wrap_unwrap_256_key_256_kek,
        aes::Aes256,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    );
}
