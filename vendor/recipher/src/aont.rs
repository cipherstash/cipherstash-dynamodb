use crate::cipher::{Block, CipherText};
use aes::Aes128;
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};

// TODO: try smaller blocks (say 4-bytes) with bit-wise permutation
// But make sure that the last block is still large - probably 32-bytes ideally
// Maybe use a struct for this then

// N=32 and Block=4-bytes => 256 bit keys (assuming we can do bit-wise perm)
// Entropy would be 32! per block * 32! for the whole thing => ~235 bits of entropy

/// XOR block of data: *dst ^= *src, returning dst
pub(crate) fn xor_slice<'a>(dst: &'a mut [u8], src: &[u8]) -> &'a mut [u8] {
    // for now, require dst, src to be of equal length
    assert_eq!(
        dst.len(),
        src.len(),
        "xor_slice: dst and src must be the same length"
    );

    // Can we use zip? Yes. Should also auto-vectorise.
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }

    dst
}

fn hash<const B: usize>(input: &[Block<B>], result: &mut Block<B>) {
    let mut hasher = Sha256::new();
    for block in input {
        hasher.update(block);
    }
    result.copy_from_slice(&hasher.finalize()[..B]);
}

// TODO: These functions could be implemented on the CipherText type
// TODO: Return a Result type
// TODO: To handle larger Aont keys, could we spread them over several blocks of size B?
pub(crate) fn aont<const B: usize>(iv: &[u8; B], message: &[u8]) -> CipherText<B> {
    assert_eq!(
        message.len() % B,
        0,
        "Message length must be a multiple of the block size"
    );

    let mut output = CipherText::<B>::init(message.len() / B);
    let mut key: Block<B> = [0u8; B];
    key.copy_from_slice(iv);

    let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();

    // TODO: This needs to be able to take a counter (as per the paper '21)
    for (i, block) in message.chunks(B).enumerate() {
        // TODO: Make a set block function?
        output.data[i].copy_from_slice(block);

        // TODO: If we get the padding right, we can probably use a single AES call here instead
        mac.update(&i.to_be_bytes());
        let result = mac.finalize_reset();
        // Consider using _kxor_mask64 or _mm_xor_si128 et al
        // For Neon see https://developer.arm.com/documentation/102159/0400/Permutation---Neon-instructions
        xor_slice(&mut output.data[i], &result.into_bytes());
    }

    let mut aont_key = [0u8; B];
    aont_key.copy_from_slice(output.aont_key());
    hash(output.blocks(), &mut aont_key);

    xor_slice(&mut aont_key, &key);
    output.aont_key_mut().copy_from_slice(&aont_key);

    output
}

pub(crate) fn deont<const B: usize>(input: &CipherText<B>) -> Vec<u8> {
    let mut key: Block<B> = [0u8; B];
    let mut output: Vec<u8> = input.blocks().iter().flatten().copied().collect();
    let mut blocks_hash: Block<B> = [0u8; B];

    key.copy_from_slice(input.aont_key());
    hash(input.blocks(), &mut blocks_hash);
    xor_slice(&mut key, &blocks_hash);

    let mut mac = Cmac::<Aes128>::new_from_slice(&key).unwrap();

    for (i, x) in output.chunks_mut(16).enumerate() {
        mac.update(&i.to_be_bytes());
        let result = mac.finalize_reset();
        xor_slice(x, &result.into_bytes());
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand::{thread_rng, RngCore};

    #[test]
    fn round_trip_test() {
        let input = hex!("97f1c20d8e45c476ca524a507c1b79cea389ee462e611e5036d3ccdacfdabb411fd2d0b12b91d46f79bd163f6425a23f37dad7dfa2a11ba5b07da1681a11029b53ac079f45ec54f5293312e762f6628d0710b273e40395967e136dbc1b8307087d39ed24c3be12bb6f0787248b226236f2024c2fc94f92b5c04a6caf6f5a5b042c1cdff3de47fe196917daa136aeedcab8f564731f9a9f5c47ff74902bfca92da61159b784bdee9e41f5079e9c19422903cc2d0436d6e533aa7d7d8af1ce73b6c4893967a4ac630476ba46996a3f7a62324dffa9112846245848197684689b65ebe3113be3786df69cc161951d90459c966f3f837e5463422c3d550d568a55c3036e47a2c160c5122729fa4338243960823f9ba5d1749023d187d912ac5144536910a93fa891b298d2ca268f2f3a5978ab8be227ae46fb5c420166d489b7bc544c347820c4f61b60dae976612cbd984432149fa129a2568a581aaed55e1763981dea766ff231935c82575e2524cd670cd2fb11dac92a0ad45125f72f256ed85463bac0f74bceeb1a7e0ea906c85457902cc2825cd6f454d0b2f7d72e7d9bd92a3fb1e1193eef86137a8f326abdac51dcf0fa2aa92ad404d07a39b40cfd1e33fc58d69225d4ee8b133a38505e68d61fedb738d84f9f580e11818597f9eedd43856660a681d609036dff5e4cfe869408b87447456fa104e8f72c24881f209be044");
        let mut iv: [u8; 16] = Default::default();
        thread_rng().try_fill_bytes(&mut iv).unwrap();
        let transformed = aont::<16>(&iv, &input);
        assert_eq!(input.to_vec(), deont(&transformed));
    }
}
