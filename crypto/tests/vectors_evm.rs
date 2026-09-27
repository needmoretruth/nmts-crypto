//! The EVM wallets (NCF-3 §1.9) against frozen vectors made by a different implementation
//! (`tests/vectors/ncf3-evm.json`, written by `web/scripts/gen-evm-vectors.mjs` with `@noble/hashes`
//! and `@noble/curves`, every address checked again against viem). An EVM address is where a
//! person's Filecoin funds sit, so these bytes are as fixed as a Sui wallet's: a change here is a
//! wallet somebody funded that no longer derives.

use nmts_crypto::kdf::{
    evm_address_checksummed, evm_address_of_key, evm_key_from_root, evm_key_from_seed,
    evm_seed_from_root, EVM_SEED_LEN, INFO_EVM_WALLET_PREFIX,
};

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/ncf3-evm.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json")
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "hex length");
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

fn text(v: &serde_json::Value) -> &str {
    v.as_str().expect("string")
}

#[test]
fn the_fixture_names_this_crates_label_and_length() {
    let v = vectors();
    assert_eq!(text(&v["label_prefix"]), INFO_EVM_WALLET_PREFIX);
    assert_eq!(v["seed_len"].as_u64(), Some(EVM_SEED_LEN as u64));
}

#[test]
fn every_wallet_derives_the_same_seed_key_and_address() {
    let v = vectors();
    let accounts = v["accounts"].as_array().expect("accounts");
    assert_eq!(accounts.len(), 3, "the three ncf3.json accounts");
    let mut checked = 0;
    for account in accounts {
        let root: [u8; 32] = bytes(text(&account["wallet_root_hex"]));
        for w in account["wallets"].as_array().expect("wallets") {
            let index = u32::try_from(w["index"].as_u64().expect("index")).expect("u32");
            let seed = evm_seed_from_root(&root, index);
            assert_eq!(
                &seed[..],
                &bytes::<48>(text(&w["seed_hex"]))[..],
                "seed {index}"
            );
            let key = evm_key_from_root(&root, index);
            assert_eq!(
                &key[..],
                &bytes::<32>(text(&w["key_hex"]))[..],
                "key {index}"
            );
            let address = evm_address_of_key(&key).expect("a derived key has an address");
            assert_eq!(
                evm_address_checksummed(&address),
                text(&w["address"]),
                "address {index}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 9);
}

#[test]
fn the_reduction_edges_match() {
    let v = vectors();
    let cases = v["reduction"].as_array().expect("reduction");
    assert_eq!(cases.len(), 4);
    for c in cases {
        let seed: [u8; 48] = bytes(text(&c["seed_hex"]));
        assert_eq!(
            &evm_key_from_seed(&seed)[..],
            &bytes::<32>(text(&c["key_hex"]))[..],
            "{}",
            text(&c["why"])
        );
    }
}

#[test]
fn private_key_one_is_the_generator_address() {
    let v = vectors();
    let key: [u8; 32] = bytes(text(&v["generator_key_one"]["key_hex"]));
    let address = evm_address_of_key(&key).expect("valid");
    assert_eq!(
        evm_address_checksummed(&address),
        text(&v["generator_key_one"]["address"])
    );
}
