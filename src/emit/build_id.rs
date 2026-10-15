pub(super) fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut state = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    let blocks = (bytes.len() + 9).div_ceil(64);
    for index in 0..blocks {
        let mut block = [0u8; 64];
        let start = index * 64;
        let size = bytes.len().saturating_sub(start).min(64);
        if size != 0 {
            block[..size].copy_from_slice(&bytes[start..start + size]);
        }
        if start <= bytes.len() && bytes.len() < start + 64 {
            block[bytes.len() - start] = 0x80;
        }
        if index + 1 == blocks {
            block[56..].copy_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
        }
        let mut words = [0u32; 80];
        for (word, input) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(input.try_into().unwrap());
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (i, word) in words.into_iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a827999u32),
                20..40 => (b ^ c ^ d, 0x6ed9eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (value, addend) in state.iter_mut().zip([a, b, c, d, e]) {
            *value = value.wrapping_add(addend);
        }
    }
    let mut digest = [0u8; 20];
    for (output, word) in digest.chunks_exact_mut(4).zip(state) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::sha1;

    #[test]
    fn standard_sha1_vectors() {
        for (bytes, expected) in [
            (b"".as_slice(), "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (
                b"abc".as_slice(),
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ] {
            let actual: String = sha1(bytes).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(actual, expected);
        }
    }
}
