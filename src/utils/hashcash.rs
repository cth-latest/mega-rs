use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::header;

const TOKEN_LEN: usize = 48;
const COPIES: usize = 262_144;
const PREFIX_LEN: usize = 4;
const SHA256_BLOCK_LEN: usize = 64;
const MESSAGE_LEN: usize = PREFIX_LEN + COPIES * TOKEN_LEN;
const FULL_DATA_BLOCKS: usize = MESSAGE_LEN / SHA256_BLOCK_LEN;
const FIXED_BLOCKS_AFTER_FIRST: usize = FULL_DATA_BLOCKS - 1;
const PATTERN_REPEATS: usize = FIXED_BLOCKS_AFTER_FIRST / 3;
const PATTERN_TAIL: usize = FIXED_BLOCKS_AFTER_FIRST % 3;
const MESSAGE_BITS: u64 = (MESSAGE_LEN as u64) * 8;

type State = [u32; 8];
type Schedule = [u32; 64];

const H256_256: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K32: Schedule = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// The logical Hashcash message is `[4-byte nonce][48-byte token repeated]`.
// After the first SHA-256 block, the 64-byte block contents repeat at token
// offsets 12, 28, and 44 until the final padding block.
struct HashcashBlocks {
    first_block: [u8; SHA256_BLOCK_LEN],
    block12: Schedule,
    block28: Schedule,
    block44: Schedule,
    padding: Schedule,
}

pub fn gencash(token_b64: &str, easiness: u8) -> String {
    let threshold: u32 = {
        let low = ((easiness & 0b00_111111) as u32) << 1 | 1;
        let shift = ((easiness >> 6) as u32) * 7 + 3;
        low << shift
    };

    let token_bytes = URL_SAFE_NO_PAD
        .decode(token_b64)
        .expect("token must be valid Base64");
    assert_eq!(
        token_bytes.len(),
        TOKEN_LEN,
        "token must decode to 48 bytes"
    );

    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&token_bytes);

    let blocks = HashcashBlocks::new(&token);
    let nonce = search_hashcash(&blocks, threshold);
    STANDARD_NO_PAD.encode(nonce.to_le_bytes())
}

pub fn parse_hashcash_header(value: &header::HeaderValue) -> Option<(String, u8)> {
    let raw = value.to_str().ok()?.trim();
    let mut parts = raw.splitn(4, ':');

    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("1"), Some(eas), Some(_ts), Some(token)) => {
            let easiness: u8 = eas.parse().ok()?;
            if token.len() == 64 {
                Some((token.to_owned(), easiness))
            } else {
                None
            }
        }
        _ => None,
    }
}

impl HashcashBlocks {
    fn new(token: &[u8; TOKEN_LEN]) -> Self {
        let mut first_block = [0u8; SHA256_BLOCK_LEN];
        fill_repeated(&mut first_block[PREFIX_LEN..], token, 0);

        let mut block12 = [0u8; SHA256_BLOCK_LEN];
        fill_repeated(&mut block12, token, 12);

        let mut block28 = [0u8; SHA256_BLOCK_LEN];
        fill_repeated(&mut block28, token, 28);

        let mut block44 = [0u8; SHA256_BLOCK_LEN];
        fill_repeated(&mut block44, token, 44);

        let mut padding = [0u8; SHA256_BLOCK_LEN];
        padding[..4].copy_from_slice(&token[44..48]);
        padding[4] = 0x80;
        padding[56..64].copy_from_slice(&MESSAGE_BITS.to_be_bytes());

        Self {
            first_block,
            block12: schedule_block(&block12),
            block28: schedule_block(&block28),
            block44: schedule_block(&block44),
            padding: schedule_block(&padding),
        }
    }
}

fn fill_repeated(dst: &mut [u8], token: &[u8; TOKEN_LEN], start: usize) {
    for (offset, byte) in dst.iter_mut().enumerate() {
        *byte = token[(start + offset) % TOKEN_LEN];
    }
}

fn search_hashcash(blocks: &HashcashBlocks, threshold: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        return unsafe { search_hashcash_aarch64(blocks, threshold) };
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
    {
        return unsafe { search_hashcash_x86(blocks, threshold) };
    }

    search_hashcash_soft(blocks, threshold)
}

fn search_hashcash_soft(blocks: &HashcashBlocks, threshold: u32) -> u32 {
    let mut first_block = blocks.first_block;
    let mut nonce = 0u32;

    loop {
        nonce = nonce.wrapping_add(1);
        first_block[..PREFIX_LEN].copy_from_slice(&nonce.to_le_bytes());

        let mut state = H256_256;
        let first_schedule = schedule_block(&first_block);
        compress_schedule_soft(&mut state, &first_schedule);
        compress_fixed_blocks_soft(&mut state, blocks);

        if state[0] <= threshold {
            return nonce;
        }
    }
}

fn compress_fixed_blocks_soft(state: &mut State, blocks: &HashcashBlocks) {
    for _ in 0..PATTERN_REPEATS {
        compress_schedule_soft(state, &blocks.block12);
        compress_schedule_soft(state, &blocks.block28);
        compress_schedule_soft(state, &blocks.block44);
    }

    if PATTERN_TAIL >= 1 {
        compress_schedule_soft(state, &blocks.block12);
    }
    if PATTERN_TAIL >= 2 {
        compress_schedule_soft(state, &blocks.block28);
    }

    compress_schedule_soft(state, &blocks.padding);
}

fn schedule_block(block: &[u8; SHA256_BLOCK_LEN]) -> Schedule {
    let mut w = [0u32; 64];

    for (word, bytes) in w[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap());
    }

    for i in 16..64 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    for (word, k) in w.iter_mut().zip(K32.iter()) {
        *word = word.wrapping_add(*k);
    }

    w
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn compress_schedule_soft(state: &mut State, schedule: &Schedule) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for wk in schedule {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(*wk);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
unsafe fn search_hashcash_aarch64(blocks: &HashcashBlocks, threshold: u32) -> u32 {
    use std::arch::aarch64::*;

    let mut first_block = blocks.first_block;
    let mut nonce = 0u32;

    loop {
        nonce = nonce.wrapping_add(1);
        first_block[..PREFIX_LEN].copy_from_slice(&nonce.to_le_bytes());

        let mut abcd = vld1q_u32(H256_256.as_ptr());
        let mut efgh = vld1q_u32(H256_256.as_ptr().add(4));
        let first_schedule = schedule_block(&first_block);
        compress_schedule_aarch64(&mut abcd, &mut efgh, &first_schedule);
        compress_fixed_blocks_aarch64(&mut abcd, &mut efgh, blocks);

        if vgetq_lane_u32::<0>(abcd) <= threshold {
            return nonce;
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn compress_fixed_blocks_aarch64(
    abcd: &mut std::arch::aarch64::uint32x4_t,
    efgh: &mut std::arch::aarch64::uint32x4_t,
    blocks: &HashcashBlocks,
) {
    for _ in 0..PATTERN_REPEATS {
        compress_schedule_aarch64(abcd, efgh, &blocks.block12);
        compress_schedule_aarch64(abcd, efgh, &blocks.block28);
        compress_schedule_aarch64(abcd, efgh, &blocks.block44);
    }

    if PATTERN_TAIL >= 1 {
        compress_schedule_aarch64(abcd, efgh, &blocks.block12);
    }
    if PATTERN_TAIL >= 2 {
        compress_schedule_aarch64(abcd, efgh, &blocks.block28);
    }

    compress_schedule_aarch64(abcd, efgh, &blocks.padding);
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn compress_schedule_aarch64(
    abcd: &mut std::arch::aarch64::uint32x4_t,
    efgh: &mut std::arch::aarch64::uint32x4_t,
    schedule: &Schedule,
) {
    use std::arch::aarch64::*;

    let abcd_orig = *abcd;
    let efgh_orig = *efgh;

    for chunk in schedule.chunks_exact(4) {
        let wk = vld1q_u32(chunk.as_ptr());
        let abcd_prev = *abcd;
        *abcd = vsha256hq_u32(abcd_prev, *efgh, wk);
        *efgh = vsha256h2q_u32(*efgh, abcd_prev, wk);
    }

    *abcd = vaddq_u32(*abcd, abcd_orig);
    *efgh = vaddq_u32(*efgh, efgh_orig);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn search_hashcash_x86(blocks: &HashcashBlocks, threshold: u32) -> u32 {
    let mut first_block = blocks.first_block;
    let mut nonce = 0u32;

    loop {
        nonce = nonce.wrapping_add(1);
        first_block[..PREFIX_LEN].copy_from_slice(&nonce.to_le_bytes());

        let mut state = H256_256;
        let first_schedule = schedule_block(&first_block);
        compress_schedule_x86(&mut state, &first_schedule);
        compress_fixed_blocks_x86(&mut state, blocks);

        if state[0] <= threshold {
            return nonce;
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn compress_fixed_blocks_x86(state: &mut State, blocks: &HashcashBlocks) {
    for _ in 0..PATTERN_REPEATS {
        compress_schedule_x86(state, &blocks.block12);
        compress_schedule_x86(state, &blocks.block28);
        compress_schedule_x86(state, &blocks.block44);
    }

    if PATTERN_TAIL >= 1 {
        compress_schedule_x86(state, &blocks.block12);
    }
    if PATTERN_TAIL >= 2 {
        compress_schedule_x86(state, &blocks.block28);
    }

    compress_schedule_x86(state, &blocks.padding);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn compress_schedule_x86(state: &mut State, schedule: &Schedule) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let state_ptr = state.as_ptr() as *const __m128i;
    let dcba = _mm_loadu_si128(state_ptr);
    let efgh = _mm_loadu_si128(state_ptr.add(1));

    let cdab = _mm_shuffle_epi32(dcba, 0xB1);
    let efgh = _mm_shuffle_epi32(efgh, 0x1B);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

    let abef_save = abef;
    let cdgh_save = cdgh;

    for chunk in schedule.chunks_exact(4) {
        let wk = _mm_set_epi32(
            chunk[3] as i32,
            chunk[2] as i32,
            chunk[1] as i32,
            chunk[0] as i32,
        );
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
        let wk_hi = _mm_shuffle_epi32(wk, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, wk_hi);
    }

    abef = _mm_add_epi32(abef, abef_save);
    cdgh = _mm_add_epi32(cdgh, cdgh_save);

    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let state_ptr_mut = state.as_mut_ptr() as *mut __m128i;
    _mm_storeu_si128(state_ptr_mut, dcba);
    _mm_storeu_si128(state_ptr_mut.add(1), hgef);
}

#[cfg(test)]
// https://github.com/meganz/sdk/blob/master/tests/unit/hashcash_test.cpp#L35
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn known_vectors() {
        let cases = [
            (
                "wFqIT_wY3tYKcrm5zqwaUoWym3ZCz32cCsrJOgYBgihtpaWUhGyWJ--EY-zfwI-i",
                180u8,
                "owAAAA",
            ),
            (
                "3NIjq_fgu6bTyepwHuKiaB8a1YRjISBhktWK1fjhRx86RhOqKZNAcOZht0wJvmhQ",
                180u8,
                "AQAAAA",
            ),
        ];

        for (token, easiness, expected) in cases {
            assert_eq!(gencash(token, easiness), expected);
        }
    }

    #[test]
    fn soft_solver_known_vector() {
        let token_bytes = URL_SAFE_NO_PAD
            .decode("3NIjq_fgu6bTyepwHuKiaB8a1YRjISBhktWK1fjhRx86RhOqKZNAcOZht0wJvmhQ")
            .unwrap();
        let mut token = [0u8; TOKEN_LEN];
        token.copy_from_slice(&token_bytes);

        let threshold = 105u32 << 17;
        let blocks = HashcashBlocks::new(&token);

        assert_eq!(search_hashcash_soft(&blocks, threshold), 1);
    }

    #[test]
    fn generated_proofs_validate_against_reference_sha256() {
        let cases = [
            ([0x00; TOKEN_LEN], 255),
            ([0xff; TOKEN_LEN], 255),
            ([0x5a; TOKEN_LEN], 248),
            ([0xa5; TOKEN_LEN], 248),
            (core::array::from_fn(|i| i as u8), 240),
            (core::array::from_fn(|i| (TOKEN_LEN - i) as u8), 240),
        ];

        for (token, easiness) in cases {
            let token_b64 = URL_SAFE_NO_PAD.encode(token);
            let proof = gencash(&token_b64, easiness);

            assert!(
                reference_validate(&token, easiness, &proof),
                "proof did not validate for token {token_b64} and easiness {easiness}: {proof}"
            );
        }
    }

    fn reference_validate(token: &[u8; TOKEN_LEN], easiness: u8, proof_b64: &str) -> bool {
        let proof = STANDARD_NO_PAD.decode(proof_b64).unwrap();
        assert_eq!(proof.len(), PREFIX_LEN);

        let mut buffer = vec![0u8; MESSAGE_LEN];
        buffer[..PREFIX_LEN].copy_from_slice(&proof);
        for chunk in buffer[PREFIX_LEN..].chunks_exact_mut(TOKEN_LEN) {
            chunk.copy_from_slice(token);
        }

        let digest = Sha256::digest(&buffer);
        let first_u32 = u32::from_be_bytes(digest[..4].try_into().unwrap());

        let low = ((easiness & 0b00_111111) as u32) << 1 | 1;
        let shift = ((easiness >> 6) as u32) * 7 + 3;
        first_u32 <= (low << shift)
    }

    #[test]
    #[should_panic(expected = "valid Base64")]
    fn invalid_base64_panics() {
        let _ = gencash("not_base64!", 180);
    }
}
