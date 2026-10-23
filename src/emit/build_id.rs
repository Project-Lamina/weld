const INITIAL: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

pub(super) fn sha1(bytes: &[u8]) -> [u8; 20] {
    let mut state = INITIAL;
    let full = bytes.len() / 64 * 64;
    compress_blocks(&mut state, &bytes[..full]);

    let rest = bytes.len() - full;
    let mut tail = [0u8; 128];
    tail[..rest].copy_from_slice(&bytes[full..]);
    tail[rest] = 0x80;
    let tail_len = if rest < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
    compress_blocks(&mut state, &tail[..tail_len]);

    let mut digest = [0u8; 20];
    for (output, word) in digest.chunks_exact_mut(4).zip(state) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the required CPU features were detected above.
            unsafe { shani::compress_blocks(state, blocks) };
            return;
        }
    }
    compress_blocks_scalar(state, blocks);
}

fn compress_blocks_scalar(state: &mut [u32; 5], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (word, input) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(input.try_into().unwrap());
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
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
}

#[cfg(target_arch = "x86_64")]
mod shani {
    use std::arch::x86_64::*;

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
        let byte_order = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);
        let mut abcd = _mm_shuffle_epi32::<0x1b>(unsafe { _mm_loadu_si128(state.as_ptr().cast()) });
        for block in blocks.chunks_exact(64) {
            let saved_abcd = abcd;
            let saved_e = state[4];
            let e_start = _mm_set_epi32(saved_e as i32, 0, 0, 0);
            let mut w = [_mm_setzero_si128(); 4];
            for (i, slot) in w.iter_mut().enumerate() {
                let raw = unsafe { _mm_loadu_si128(block.as_ptr().add(16 * i).cast()) };
                *slot = _mm_shuffle_epi8(raw, byte_order);
            }
            let mut prev = abcd;
            for group in 0..20 {
                if group >= 4 {
                    let t = _mm_xor_si128(
                        _mm_sha1msg1_epu32(w[group % 4], w[(group + 1) % 4]),
                        w[(group + 2) % 4],
                    );
                    w[group % 4] = _mm_sha1msg2_epu32(t, w[(group + 3) % 4]);
                }
                let words = w[group % 4];
                let e_in = if group == 0 {
                    _mm_add_epi32(e_start, words)
                } else {
                    _mm_sha1nexte_epu32(prev, words)
                };
                prev = abcd;
                abcd = match group / 5 {
                    0 => _mm_sha1rnds4_epu32::<0>(abcd, e_in),
                    1 => _mm_sha1rnds4_epu32::<1>(abcd, e_in),
                    2 => _mm_sha1rnds4_epu32::<2>(abcd, e_in),
                    _ => _mm_sha1rnds4_epu32::<3>(abcd, e_in),
                };
            }
            let a_before_last = _mm_extract_epi32::<3>(prev) as u32;
            let e_out = saved_e.wrapping_add(a_before_last.rotate_left(30));
            abcd = _mm_add_epi32(abcd, saved_abcd);
            state[4] = e_out;
            let mut lanes = [0u32; 4];
            unsafe { _mm_storeu_si128(lanes.as_mut_ptr().cast(), _mm_shuffle_epi32::<0x1b>(abcd)) };
            state[..4].copy_from_slice(&lanes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{INITIAL, compress_blocks_scalar, sha1};

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

    #[test]
    fn accelerated_matches_scalar_across_lengths() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        for len in (0..300).chain([1000]) {
            let mut scalar = INITIAL;
            let full = len / 64 * 64;
            compress_blocks_scalar(&mut scalar, &data[..full]);
            let mut tail = [0u8; 128];
            let rest = len - full;
            tail[..rest].copy_from_slice(&data[full..len]);
            tail[rest] = 0x80;
            let tail_len = if rest < 56 { 64 } else { 128 };
            tail[tail_len - 8..tail_len].copy_from_slice(&((len as u64) * 8).to_be_bytes());
            compress_blocks_scalar(&mut scalar, &tail[..tail_len]);
            let mut expected = [0u8; 20];
            for (output, word) in expected.chunks_exact_mut(4).zip(scalar) {
                output.copy_from_slice(&word.to_be_bytes());
            }
            assert_eq!(sha1(&data[..len]), expected, "length {len}");
        }
    }
}
