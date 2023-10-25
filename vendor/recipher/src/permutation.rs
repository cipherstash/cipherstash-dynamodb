use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Permutation {
    permutation: Vec<u8>,
}

impl Permutation {
    /*
     * Generate a PRP using a KnuthShuffle with the given size (< 256).
     */
    pub fn generate(key: &[u8; 32], size: u8) -> Self {
        let mut prg = ChaCha20Rng::from_seed(*key);
        let mut permutation: Vec<u8> = (0..size).collect();

        for i in (0..size).rev() {
            let j = prg.gen_range(0..=i);
            permutation.swap(i.into(), j.into());
        }

        Self { permutation }
    }

    /* Finds a permutation such that composing it with target results
     * in this permutation.
     * */
    pub fn complement(&self, target: &Self) -> Self {
        let mut permutation = vec![0u8; self.permutation.len()];
        for (i, a) in target.permutation.iter().enumerate() {
            for (j, b) in self.permutation.iter().enumerate() {
                if a == b {
                    permutation[j] = i as u8;
                    break;
                }
            }
        }

        Self { permutation }
    }

    pub fn permute_slice_mut<A: Copy>(&self, input: &mut [A]) {
        assert_eq!(
            self.permutation.len(),
            input.len(),
            "Slice must be same length as permutation"
        );

        for (i, perm) in self.permutation.iter().enumerate() {
            let mut index = *perm as usize;
            while (index) < i {
                index = self.permutation[index] as usize;
            }

            let tmp = input[i];
            input.swap(i, index);
            input[index] = tmp;
        }
    }

    pub fn depermute_slice_mut<A: Copy + Debug>(&self, input: &mut [A]) {
        assert_eq!(
            self.permutation.len(),
            input.len(),
            "Slice must be same length as permutation"
        );
        // TODO: See if we can do this without a copy (like permute_slice_mut)
        let mut buf: Vec<A> = input.to_vec();

        for (perm, input) in self.permutation.iter().zip(input.iter()) {
            buf[*perm as usize] = *input;
        }

        input.copy_from_slice(&buf);
    }

    pub fn clone(&self) -> Self {
        Self {
            permutation: self.permutation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complement_test() {
        let k1 = [8u8; 32];
        let k2 = [16u8; 32];
        let perm1 = Permutation::generate(&k1, 16);
        let perm2 = Permutation::generate(&k2, 16);
        let complement = perm1.complement(&perm2);

        let mut input1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut input2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        perm1.permute_slice_mut(&mut input1);

        perm2.permute_slice_mut(&mut input2);
        complement.permute_slice_mut(&mut input2);

        assert_eq!(input1, input2);
    }

    #[test]
    fn permute_array_identity() {
        let k = [8u8; 32];
        let perm = Permutation::generate(&k, 16);
        let mut input = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        perm.permute_slice_mut(&mut input);

        assert_eq!(input, perm.permutation);
    }

    #[test]
    fn permute_array_round_trip() {
        let k = [8u8; 32];
        let perm = Permutation::generate(&k, 8);
        let mut input = vec![1, 3, 2, 7, 5, 6, 0, 4];
        perm.permute_slice_mut(&mut input);
        perm.depermute_slice_mut(&mut input);

        assert_eq!(input, vec![1, 3, 2, 7, 5, 6, 0, 4]);
    }
}
