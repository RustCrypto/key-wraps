//! Test vectors from STB 4.101.31-2020 (section A.10, tables A.21-A.22):
//! https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
use belt_kwp::BeltKwp;
use hex_literal::hex;

#[test]
fn belt_kwp() {
    // Table A.21
    let x1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D");
    let i1 = hex!("5BE3D612 17B96181 FE6786AD 716B890B");
    let k1 = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let y1 = hex!(
        "49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76"
        "E487B055 C69BCF54 1176169F 1DC9F6C8"
    );

    // Table A.22
    let x2 = hex!("92632EE0 C21AD9E0 9A39343E 5C07DAA4 889B03F2 E6847EB1 52EC99F7 A4D9F154");
    let i2 = hex!("B5EF68D8 E4A39E56 7153DE13 D72254EE");
    let k2 = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let y2 = hex!(
        "E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
        "F33C657B 637C306A DD4EA779 9EB23D31"
    );

    let mut buf = [0u8; 48];

    let kw = BeltKwp::new(&k1);
    let res = kw.wrap_key(&x1, &i1, &mut buf).unwrap();
    assert_eq!(y1, res);
    let res = kw.unwrap_key(&y1, &i1, &mut buf).unwrap();
    assert_eq!(x1, res);

    let kw = BeltKwp::new(&k2);
    let res = kw.wrap_key(&x2, &i2, &mut buf).unwrap();
    assert_eq!(y2, res);
    let res = kw.unwrap_key(&y2, &i2, &mut buf).unwrap();
    assert_eq!(x2, res);
}
