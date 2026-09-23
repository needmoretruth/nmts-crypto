//! The recovery phrase against frozen vectors made by a different implementation
//! (`tests/vectors/ncf3-words.json`, from `@scure/bip39`). A phrase is the account code in another
//! spelling, so these words are as fixed as the code's own symbols: a change here means a phrase
//! somebody wrote down no longer opens their account.

use nmts_crypto::{parse_key_or_phrase, AccountCode, PhraseLanguage};

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/ncf3-words.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json")
}

fn bytes(hex: &str) -> [u8; 20] {
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
}

#[test]
fn every_case_spells_and_reads_back_in_both_lists() {
    let v = vectors();
    let cases = v["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 5);
    for case in cases {
        let code = AccountCode::from_bytes(bytes(case["code_bytes_hex"].as_str().expect("hex")));
        for (tag, lang) in [
            ("en", PhraseLanguage::English),
            ("ko", PhraseLanguage::Korean),
        ] {
            let expected = case[tag].as_str().expect("phrase");
            assert_eq!(code.to_phrase(lang), expected, "{tag} spelling");
            assert_eq!(
                parse_key_or_phrase(expected).expect("reads back"),
                code,
                "{tag} reading"
            );
        }
    }
}

#[test]
fn every_refusal_is_refused_the_way_it_says() {
    let v = vectors();
    let refusals = v["refusals"].as_array().expect("refusals");
    assert_eq!(refusals.len(), 4);
    for r in refusals {
        let err = parse_key_or_phrase(r["input"].as_str().expect("input")).expect_err("refused");
        assert_eq!(
            err.to_string(),
            r["error"].as_str().expect("error"),
            "{}",
            r["why"]
        );
    }
}
