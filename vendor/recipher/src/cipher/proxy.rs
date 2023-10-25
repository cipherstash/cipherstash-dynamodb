use super::ciphertext::CipherText;
use crate::{aont::xor_slice, keyset::ProxyKeySet};

pub struct ProxyCipher<'s> {
    keyset: &'s ProxyKeySet,
}

impl<'s> ProxyCipher<'s> {
    pub fn new(keyset: &'s ProxyKeySet) -> Self {
        Self { keyset }
    }

    pub fn reencrypt<const B: usize>(&self, iv: &[u8; B], input: &[u8]) -> Vec<u8> {
        let mut ciphertext = CipherText::<B>::from_bytes(input);

        let mut p2_block = [0u8; B];
        p2_block.copy_from_slice(iv); // TODO: Use clone?

        for block in ciphertext.data.iter_mut() {
            let mut tmp = [0u8; B];
            tmp.copy_from_slice(block); // TODO: Use clone?
            self.keyset.p2_from.permute_slice_mut(&mut p2_block);

            xor_slice(block, &p2_block);
            p2_block.copy_from_slice(&tmp);
            self.keyset.p1.permute_slice_mut(block);
        }

        self.keyset.p3.permute_slice_mut(&mut ciphertext.data[..]);

        p2_block.copy_from_slice(iv);

        for c in ciphertext.data.iter_mut() {
            self.keyset.p2_to.permute_slice_mut(&mut p2_block);
            xor_slice(c, &p2_block);
            p2_block.copy_from_slice(c);
        }

        ciphertext.to_bytes()
    }
}
