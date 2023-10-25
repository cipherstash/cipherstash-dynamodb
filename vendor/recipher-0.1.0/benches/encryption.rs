use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use rand::thread_rng;
use recipher::{
    cipher::{ProxyCipher, SymmetricCipher},
    key::{GenRandom, Iv},
    keyset::{EncryptionKeySet, ProxyKeySet},
};

#[inline]
fn encrypt(iv: &[u8; 16], message: &[u8], cipher: &SymmetricCipher) -> Vec<u8> {
    cipher.encrypt::<16>(iv, message)
}

#[inline]
fn reencrypt(cipher: &ProxyCipher, iv: &[u8; 16], ct: &[u8]) -> Vec<u8> {
    cipher.reencrypt::<16>(iv, ct)
}

fn criterion_benchmark(c: &mut Criterion) {
    let kset_enc = EncryptionKeySet::generate().unwrap();
    let kset_target = EncryptionKeySet::generate().unwrap();
    let kset_reenc = ProxyKeySet::generate(&kset_enc, &kset_target);

    let message = hex!(
        "97f1c20d8e45c476ca524a507c1b79cea389ee462e611e5036d3ccdacfdabb411fd2d0b12b91d46f79bd163f6425a23f37dad7dfa2a11ba5b07da1681a11029b53ac079f45ec54f5293312e762f6628d0710b273e40395967e136dbc1b8307087d39ed24c3be12bb6f0787248b226236f2024c2fc94f92b5c04a6caf6f5a5b042c1cdff3de47fe196917daa136aeedcab8f564731f9a9f5c47ff74902bfca92da61159b784bdee9e41f5079e9c19422903cc2d0436d6e533aa7d7d8af1ce73b6c4893967a4ac630476ba46996a3f7a62324dffa9112846245848197684689b65ebe3113be3786df69cc161951d90459c966f3f837e5463422c3d550d568a55c3036e47a2c160c5122729fa4338243960823f9ba5d1749023d187d912ac5144536910a93fa891b298d2ca268f2f3a5978ab8be227ae46fb5c420166d489b7bc544c347820c4f61b60dae976612cbd984432149fa129a2568a581aaed55e1763981dea766ff231935c82575e2524cd670cd2fb11dac92a0ad45125f72f256ed85463bac0f74bceeb1a7e0ea906c85457902cc2825cd6f454d0b2f7d72e7d9bd92a3fb1e1193eef86137a8f326abdac51dcf0fa2aa92ad404d07a39b40cfd1e33fc58d69225d4ee8b133a38505e68d61fedb738d84f9f580e11818597f9eedd43856660a681d609036dff5e4cfe869408b87447456fa104e8f72c24881f209be044"
    ).to_vec();
    let cipher = SymmetricCipher::new(&kset_enc);
    let proxy = ProxyCipher::new(&kset_reenc);

    let iv: Iv = GenRandom::gen_random(&mut thread_rng()).unwrap();
    let ct = cipher.encrypt::<16>(&iv, &message);

    c.bench_function("encrypt", |b| {
        b.iter(|| encrypt(black_box(&iv), black_box(&message), black_box(&cipher)))
    });
    c.bench_function("re-encrypt", |b| {
        b.iter(|| reencrypt(black_box(&proxy), black_box(&iv), black_box(&ct)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
