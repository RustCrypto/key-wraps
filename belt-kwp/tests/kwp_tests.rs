#[cfg(test)]
mod tests {
    use belt_kwp::BeltKwp;
    use hex_literal::hex;

    #[test]
    fn test_key_wrap() {
        let x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D");
        let i = hex!("5BE3D612 17B96181 FE6786AD 716B890B");
        let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
        let y = hex!("49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76 E487B055 C69BCF54 1176169F 1DC9F6C8");

        let mut wrapped = [0u8; 48];
        let mut unwrapped = [0u8; 48];

        let kek = BeltKwp::new(&k.into());

        kek.wrap_key(&x, &i, &mut wrapped).unwrap();
        assert_eq!(y, wrapped);

        kek.unwrap_key(&y, &i, &mut unwrapped).unwrap();
        assert_eq!(x, unwrapped[..32]);
    }

    #[test]
    fn test_key_unwrap() {
        let y = hex!("49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76 E487B055 C69BCF54 1176169F 1DC9F6C8");
        let i = hex!("5BE3D612 17B96181 FE6786AD 716B890B");
        let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
        let x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D");

        let mut unwrapped = [0u8; 48];
        let mut wrapped = [0u8; 48];

        let kek = BeltKwp::new(&k.into());

        kek.unwrap_key(&y, &i, &mut unwrapped).unwrap();
        assert_eq!(x, unwrapped[..32]);

        kek.wrap_key(&x, &i, &mut wrapped).unwrap();
        assert_eq!(y, wrapped);
    }
}
