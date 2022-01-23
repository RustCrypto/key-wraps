use aes_kw::Error;
use aes_kw::Kek;
use aes_kw::IV_LEN;
use hex_literal::hex;
use std::assert_eq;

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes_kwp {
        ($name:ident, $kek_typ:ty, $kek:expr, $input:expr, $output:expr) => {
            #[test]
            fn $name() {
                let kek = Kek::<$kek_typ>::from($kek);

                let mut wrapped = [0u8; $output.len()];
                kek.wrap_with_padding(&$input, &mut wrapped).unwrap();

                let mut unwrapped = [0u8; $output.len() - IV_LEN];
                let unwrapped_slice = kek.unwrap_with_padding(&wrapped, &mut unwrapped).unwrap();

                assert_eq!($output, wrapped, "failed wrap");
                assert_eq!($input, unwrapped_slice, "failed unwrap");
            }
        };
    }

    test_aes_kwp!(
        wrap_unwrap_160_key_192_kek,
        aes::Aes192,
        hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"),
        hex!("c37b7e6492584340bed12207808941155068f738"),
        hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
    );
    test_aes_kwp!(
        wrap_unwrap_56_key_192_kek,
        aes::Aes192,
        hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"),
        hex!("466f7250617369"),
        hex!("afbeb0f07dfbf5419200f2ccb50bb24f")
    );

    // These test vectors were obtained using NIST's ACVP system

    test_aes_kwp!(
        wrap_unwrap_24_key_128_kek,
        aes::Aes128,
        hex!("AF83AE6624FC006DA13B3C37B8A5933B"),
        hex!("13126A"),
        hex!("A661F530339C9F344FA4755AD4CC3558")
    );
    test_aes_kwp!(
        wrap_unwrap_24_key_192_kek,
        aes::Aes192,
        hex!("BA0CFC260103DDD629FA8826982F5547D245F5AB0711F10F"),
        hex!("C01990"),
        hex!("91E3B5E73A25EC91E91D337D0485B960")
    );
    test_aes_kwp!(
        wrap_unwrap_24_key_256_kek,
        aes::Aes256,
        hex!("6D60C0D0941CF3750B864C6F1FA580AE074C00EDEB386F9FC299178A70FCCCD1"),
        hex!("6B54A0"),
        hex!("24255140B4A9F8A9E35B9DA2BFA0E0C3")
    );
    test_aes_kwp!(
        wrap_unwrap_64_key_128_kek,
        aes::Aes128,
        hex!("D19C43011C2A0242A38BD58B8D76456D"),
        hex!("4202C90D7298CB4B"),
        hex!("65BEFAEAACBB4620D1A5D64E7B57A760")
    );
    test_aes_kwp!(
        wrap_unwrap_64_key_192_kek,
        aes::Aes192,
        hex!("D65980B811B696A44AFB3DE6DDCA07910FAB2A4C898B51AF"),
        hex!("E63D206E6321CBCA"),
        hex!("7F3B9764D9B28AA7D2E4EDA430AFBA21")
    );
    test_aes_kwp!(
        wrap_unwrap_64_key_256_kek,
        aes::Aes256,
        hex!("EB950B844B97145A594B7F91AA81844045874AAA46DB522CF91144F63A6FED37"),
        hex!("A4CE3F7D7C49B11A"),
        hex!("F5939D472407E28EE6D7269FA75DAC88")
    );
    test_aes_kwp!(
        wrap_unwrap_128_key_128_kek,
        aes::Aes128,
        hex!("EBEE1B9211AADEFD06D258605F7134FB"),
        hex!("4029F7DA4F8C29E4BB951A6F9D7F5305"),
        hex!("634194EACA80D77A21D11DD3E739DC5AA3FECA2CE0990507")
    );
    test_aes_kwp!(
        wrap_unwrap_128_key_192_kek,
        aes::Aes192,
        hex!("029194F464DCF06C0E7CA8F05927874A3AC4AA93262459FC"),
        hex!("D45E4B35D47F2F559EE2B78D71E73C23"),
        hex!("2519D224F9CAB21C69ED5758F41BEB4D145FC68A3387BADF")
    );
    test_aes_kwp!(
        wrap_unwrap_128_key_256_kek,
        aes::Aes256,
        hex!("314A549913256A71C6348EAAB9B85EFC755FE736568F0DBC9F6F8BC3CA3D12EE"),
        hex!("3B700E9682275D8DBE61CA7C1EC900E8"),
        hex!("70C684C49112AD8B8C3E13B99992127B58DCB9B59CE5C3FD")
    );
    test_aes_kwp!(
        wrap_unwrap_144_key_128_kek,
        aes::Aes128,
        hex!("83696B21D199C224415370F2C9857E67"),
        hex!("8D6220459626A496036389DF998B45029CE7"),
        hex!("C255C96564C96F0A381A8A8091389D654357AB826C9F1ACF16EA8E1DB2F820E9")
    );
    test_aes_kwp!(
        wrap_unwrap_144_key_192_kek,
        aes::Aes192,
        hex!("2F65E32F3BC3F0F3EA7E74E86ED66162A7447E723D30E72F"),
        hex!("CB4BE52BAB46B64322FFFFF30D1A39D17359"),
        hex!("4C27BAE9E7A7814B78946A6F06902A14C51DA65344524EAA645BE30F14C400D5")
    );
    test_aes_kwp!(
        wrap_unwrap_144_key_256_kek,
        aes::Aes256,
        hex!("F2882A99E67FD1F0E024D2E973EE55BF2AE94D6798BC3B3A7EF94BFC9197A7F6"),
        hex!("13CDD6837C4C40FDE0B9EC150093713771AC"),
        hex!("D096D3702EA4252DA0D36666D01F1F450BCD26C87814A8041F8EEFD229EC4828")
    );

    #[test]
    fn padding_cleared() {
        let kek = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let input = hex!("c37b7e6492584340bed12207808941155068f738");
        let output = hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        let kek = Kek::<aes::Aes192>::from(kek);

        let mut wrapped = [0u8; 32];
        // The following positions should be zeroized by wrap (padding).
        wrapped[20] = 0xFF;
        wrapped[21] = 0xFF;
        wrapped[22] = 0xFF;
        wrapped[23] = 0xFF;
        kek.wrap_with_padding(&input, &mut wrapped).unwrap();

        assert_eq!(output, wrapped, "failed wrap");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn unwrap_with_padding_vec_truncated() {
        let kek = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let input = hex!("c37b7e6492584340bed12207808941155068f738");
        let output = hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        let kek = Kek::<aes::Aes192>::from(kek);

        let unwrapped = kek.unwrap_with_padding_vec(&output).unwrap();

        assert_eq!(input.to_vec(), unwrapped, "failed unwrap");
    }

    #[test]
    fn error_invalid_data_size() {
        let kek = hex!("EBEE1B9211AADEFD06D258605F7134FB");
        let output = hex!("634194EACA80D77A21D11DD3E739DC5AA3FECA2CE09905");

        let kek = Kek::<aes::Aes128>::from(kek);

        let mut unwrapped = [0u8; 16];
        let result = kek.unwrap_with_padding(&output, &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidDataSize));

        let mut unwrapped = [0u8; 0];
        let result = kek.unwrap_with_padding(&[], &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidDataSize));
    }

    #[test]
    fn error_invalid_kek_size() {
        let kek = hex!("EBEE1B9211AADEFD06D258605F7134");

        let result = Kek::<aes::Aes128>::try_from(&kek[..]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidKekSize { size: 15 }
        ));
    }

    #[test]
    fn error_invalid_output_size() {
        let kek = hex!("EBEE1B9211AADEFD06D258605F7134FB");
        let input = hex!("4029F7DA4F8C29E4BB951A6F9D7F5305");
        let output = hex!("634194EACA80D77A21D11DD3E739DC5AA3FECA2CE0990507");

        let kek = Kek::<aes::Aes128>::from(kek);

        let mut wrapped = [0u8; 23];
        let result = kek.wrap_with_padding(&input, &mut wrapped);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidOutputSize { expected: 24 }
        ));

        let mut unwrapped = [0u8; 15];
        let result = kek.unwrap_with_padding(&output, &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidOutputSize { expected: 16 }
        ));

        // Make sure we also test the padded case

        let kek = hex!("AF83AE6624FC006DA13B3C37B8A5933B");
        let input = hex!("13126A");
        let output = hex!("A661F530339C9F344FA4755AD4CC3558");

        let kek = Kek::<aes::Aes128>::from(kek);

        let mut wrapped = [0u8; 11];
        let result = kek.wrap_with_padding(&input, &mut wrapped);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidOutputSize { expected: 16 }
        ));

        let mut unwrapped = [0u8; 3];
        let result = kek.unwrap_with_padding(&output, &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidOutputSize { expected: 8 }
        ));
    }

    #[test]
    fn error_integrity_check_failed() {
        let kek = hex!("EBEE1B9211AADEFD06D258605F7134FB");
        let output = hex!("634194EACA80D77A21D11DD3E739DC5AA3FECA2CE0990508");

        let kek = Kek::<aes::Aes128>::from(kek);

        let mut unwrapped = [0u8; 16];
        let result = kek.unwrap_with_padding(&output, &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::IntegrityCheckFailed));

        // Make sure we also test the padded case

        let kek = hex!("AF83AE6624FC006DA13B3C37B8A5933B");
        let output = hex!("A661F530339C9F344FA4755AD4CC3559");

        let kek = Kek::<aes::Aes128>::from(kek);

        let mut unwrapped = [0u8; 8];
        let result = kek.unwrap_with_padding(&output, &mut unwrapped);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::IntegrityCheckFailed));
    }
}
