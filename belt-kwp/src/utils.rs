/// Helper function for transforming BelT keys and blocks from a byte array
/// to an array of `u32`s.
///
/// # Panics
/// If length of `src` is not equal to `4 * N`.
// #[inline(always)]
pub(crate) fn to_u32<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    res.iter_mut()
        .zip(src.chunks_exact(4))
        .for_each(|(dst, src)| *dst = u32::from_le_bytes(src.try_into().unwrap()));
    res
}
