use super::ciphertext::CipherText;
use crate::aont::xor_slice;
use crate::{aont, keyset::EncryptionKeySet};

// 16 blocks of size 16-bytes
//#[derive(Debug)]
pub struct SymmetricCipher<'s> {
    keyset: &'s EncryptionKeySet,
}

impl<'s> SymmetricCipher<'s> {
    pub fn new(keyset: &'s EncryptionKeySet) -> Self {
        Self { keyset }
    }

    // Encrypt a 512 byte message (32x16)
    // TODO: Maybe don't make the CT generic on block size
    pub fn encrypt<const B: usize>(&self, iv: &[u8; B], message: &[u8]) -> Vec<u8> {
        let mut output: CipherText<B> = aont::aont(iv, message);

        self.keyset.p3.permute_slice_mut(&mut output.data);
        let mut p2_target = *iv;

        for m in output.data.iter_mut() {
            // TODO: Consider doing this as a bit-level permutation
            self.keyset.p1.permute_slice_mut(m);
            self.keyset.p2.permute_slice_mut(&mut p2_target[..]);

            xor_slice(m, &p2_target);
            p2_target.copy_from_slice(m);
        }

        output.to_bytes()
    }

    pub fn decrypt<const B: usize>(&self, iv: &[u8; B], input: &[u8]) -> Vec<u8> {
        let mut ciphertext = CipherText::<B>::from_bytes(input);

        let mut p2_block = [0u8; B];
        p2_block.copy_from_slice(iv);

        for block in ciphertext.data.iter_mut() {
            let mut tmp = [0u8; B];
            tmp.copy_from_slice(block);
            self.keyset.p2.permute_slice_mut(&mut p2_block);
            xor_slice(block, &p2_block);
            p2_block.copy_from_slice(&tmp);
            self.keyset.p1.depermute_slice_mut(block);
        }

        self.keyset.p3.depermute_slice_mut(&mut ciphertext.data);

        aont::deont(&ciphertext)
    }
}
