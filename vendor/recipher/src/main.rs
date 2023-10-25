use recipher::keyset::{EncryptionKeySet, ProxyKeySet};

fn main() {
    let keyset_raw = "a3627031a16b7065726d75746174696f6e900b07050a0f010c06040309020e0d0008627032a16b7065726d75746174696f6e900a090f06050b070d0e020c0103080400627033a16b7065726d75746174696f6e9821181b00091503181a182017140b0618190a08130e181d020d181c04181805120f11181e16070c1001181f";
    let keyset = EncryptionKeySet::from_bytes(&hex::decode(keyset_raw).unwrap()).unwrap();
    let kset_target = EncryptionKeySet::generate().unwrap();
    let kset_proxy = ProxyKeySet::generate(&keyset, &kset_target);

    println!("{}", hex::encode(kset_proxy.to_bytes().unwrap()));
}
