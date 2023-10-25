mod aont;
pub mod cipher;
pub mod errors;
pub mod key;
pub mod keyset;
mod permutation;

#[cfg(test)]
mod tests {
    use crate::{
        cipher::{ProxyCipher, SymmetricCipher},
        key::{GenRandom, Iv},
        keyset::{EncryptionKeySet, ProxyKeySet},
    };
    use hex_literal::hex;
    use rand::thread_rng;
    use std::error::Error;

    fn target_keyset() -> Result<EncryptionKeySet, Box<dyn Error>> {
        // Include ser/de in the test chain
        let keyset = EncryptionKeySet::generate()?;
        Ok(EncryptionKeySet::from_bytes(&keyset.to_bytes()?)?)
    }

    #[test]
    fn round_trip_test() -> Result<(), Box<dyn Error>> {
        // TODO: Use quickcheck for this!
        let kset_enc = EncryptionKeySet::generate()?;

        let message = hex!(
            "97f1c20d8e45c476ca524a507c1b79cea389ee462e611e5036d3ccdacfdabb411fd2d0b12b91d46f79bd163f6425a23f37dad7dfa2a11ba5b07da1681a11029b53ac079f45ec54f5293312e762f6628d0710b273e40395967e136dbc1b8307087d39ed24c3be12bb6f0787248b226236f2024c2fc94f92b5c04a6caf6f5a5b042c1cdff3de47fe196917daa136aeedcab8f564731f9a9f5c47ff74902bfca92da61159b784bdee9e41f5079e9c19422903cc2d0436d6e533aa7d7d8af1ce73b6c4893967a4ac630476ba46996a3f7a62324dffa9112846245848197684689b65ebe3113be3786df69cc161951d90459c966f3f837e5463422c3d550d568a55c3036e47a2c160c5122729fa4338243960823f9ba5d1749023d187d912ac5144536910a93fa891b298d2ca268f2f3a5978ab8be227ae46fb5c420166d489b7bc544c347820c4f61b60dae976612cbd984432149fa129a2568a581aaed55e1763981dea766ff231935c82575e2524cd670cd2fb11dac92a0ad45125f72f256ed85463bac0f74bceeb1a7e0ea906c85457902cc2825cd6f454d0b2f7d72e7d9bd92a3fb1e1193eef86137a8f326abdac51dcf0fa2aa92ad404d07a39b40cfd1e33fc58d69225d4ee8b133a38505e68d61fedb738d84f9f580e11818597f9eedd43856660a681d609036dff5e4cfe869408b87447456fa104e8f72c24881f209be044"
        ).to_vec();
        let cipher = SymmetricCipher::new(&kset_enc);
        let iv: Iv = GenRandom::gen_random(&mut thread_rng())?;

        assert_eq!(
            message.to_vec(),
            cipher.decrypt::<16>(&iv, &cipher.encrypt::<16>(&iv, &message))
        );

        Ok(())
    }

    #[test]
    fn rencryption_round_trip_test() -> Result<(), Box<dyn Error>> {
        let kset_enc = EncryptionKeySet::generate()?;
        let kset_target = target_keyset()?;
        let kset_proxy = ProxyKeySet::generate(&kset_enc, &kset_target);

        let message = hex!("97f1c20d8e45c476ca524a507c1b79cea389ee462e611e5036d3ccdacfdabb411fd2d0b12b91d46f79bd163f6425a23f37dad7dfa2a11ba5b07da1681a11029b53ac079f45ec54f5293312e762f6628d0710b273e40395967e136dbc1b8307087d39ed24c3be12bb6f0787248b226236f2024c2fc94f92b5c04a6caf6f5a5b042c1cdff3de47fe196917daa136aeedcab8f564731f9a9f5c47ff74902bfca92da61159b784bdee9e41f5079e9c19422903cc2d0436d6e533aa7d7d8af1ce73b6c4893967a4ac630476ba46996a3f7a62324dffa9112846245848197684689b65ebe3113be3786df69cc161951d90459c966f3f837e5463422c3d550d568a55c3036e47a2c160c5122729fa4338243960823f9ba5d1749023d187d912ac5144536910a93fa891b298d2ca268f2f3a5978ab8be227ae46fb5c420166d489b7bc544c347820c4f61b60dae976612cbd984432149fa129a2568a581aaed55e1763981dea766ff231935c82575e2524cd670cd2fb11dac92a0ad45125f72f256ed85463bac0f74bceeb1a7e0ea906c85457902cc2825cd6f454d0b2f7d72e7d9bd92a3fb1e1193eef86137a8f326abdac51dcf0fa2aa92ad404d07a39b40cfd1e33fc58d69225d4ee8b133a38505e68d61fedb738d84f9f580e11818597f9eedd43856660a681d609036dff5e4cfe869408b87447456fa104e8f72c24881f209be044");
        let cipher = SymmetricCipher::new(&kset_enc);
        let iv: Iv = GenRandom::gen_random(&mut thread_rng()).unwrap();
        let ct: Vec<u8> = cipher.encrypt::<16>(&iv, message.as_ref());

        // TODO: Pass as reference
        let re = ProxyCipher::new(&kset_proxy);
        let rct = re.reencrypt::<16>(&iv, &ct);
        let target_cipher = SymmetricCipher::new(&kset_target);

        assert_eq!(message.to_vec(), target_cipher.decrypt::<16>(&iv, &rct));

        Ok(())
    }

    #[test]
    fn homomorphism_test() -> Result<(), Box<dyn Error>> {
        // TODO: Randomize message
        let message = hex!("97f1c20d8e45c476ca524a507c1b79cea389ee462e611e5036d3ccdacfdabb411fd2d0b12b91d46f79bd163f6425a23f37dad7dfa2a11ba5b07da1681a11029b53ac079f45ec54f5293312e762f6628d0710b273e40395967e136dbc1b8307087d39ed24c3be12bb6f0787248b226236f2024c2fc94f92b5c04a6caf6f5a5b042c1cdff3de47fe196917daa136aeedcab8f564731f9a9f5c47ff74902bfca92da61159b784bdee9e41f5079e9c19422903cc2d0436d6e533aa7d7d8af1ce73b6c4893967a4ac630476ba46996a3f7a62324dffa9112846245848197684689b65ebe3113be3786df69cc161951d90459c966f3f837e5463422c3d550d568a55c3036e47a2c160c5122729fa4338243960823f9ba5d1749023d187d912ac5144536910a93fa891b298d2ca268f2f3a5978ab8be227ae46fb5c420166d489b7bc544c347820c4f61b60dae976612cbd984432149fa129a2568a581aaed55e1763981dea766ff231935c82575e2524cd670cd2fb11dac92a0ad45125f72f256ed85463bac0f74bceeb1a7e0ea906c85457902cc2825cd6f454d0b2f7d72e7d9bd92a3fb1e1193eef86137a8f326abdac51dcf0fa2aa92ad404d07a39b40cfd1e33fc58d69225d4ee8b133a38505e68d61fedb738d84f9f580e11818597f9eedd43856660a681d609036dff5e4cfe869408b87447456fa104e8f72c24881f209be044");

        let kset_target = EncryptionKeySet::generate()?;

        let kset_enc_1 = EncryptionKeySet::generate()?;
        let kset_enc_2 = EncryptionKeySet::generate()?;
        let kset_proxy_1 = ProxyKeySet::generate(&kset_enc_1, &kset_target);
        let kset_proxy_2 = ProxyKeySet::generate(&kset_enc_2, &kset_target);

        let iv: Iv = GenRandom::gen_random(&mut thread_rng()).unwrap();
        let ct1: Vec<u8> = SymmetricCipher::new(&kset_enc_1).encrypt::<16>(&iv, message.as_ref());
        let rct1 = ProxyCipher::new(&kset_proxy_1).reencrypt::<16>(&iv, &ct1);

        let ct2: Vec<u8> = SymmetricCipher::new(&kset_enc_2).encrypt::<16>(&iv, message.as_ref());
        let rct2 = ProxyCipher::new(&kset_proxy_2).reencrypt::<16>(&iv, &ct2);

        assert_eq!(rct1, rct2);

        Ok(())
    }
}
