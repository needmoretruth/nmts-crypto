//! Conformance fixture for the OPENER layer (NCF-3 §1.7) — `tests/vectors/ncf3-openers.json`.
//!
//! ⛔ ITS OWN FILE, AND `ncf3.json` IS NOT TOUCHED. That artifact is the frozen format; this layer
//! is deliberately not frozen (§1.7), so mixing the two would put a re-wrappable record inside the
//! file whose whole promise is that nothing in it ever moves.
//!
//! What it pins, and why each one is here rather than assumed:
//!
//! 1. **The message, byte for byte** — two inputs (with and without an `App:` line), as hex, as a
//!    length and as a SHA-256. The message is what a person reads in a wallet popup and what the
//!    wrapping key comes from; a character of drift between the browser, the CLI and the recovery
//!    tool is a slot that no longer opens, with no symptom but a sign-in that stops working.
//! 2. **Every refusal the review's disposition table names** — `0` as an account number, an
//!    uppercased address, a short address, an address carrying a trailing LF or a CRLF, the three
//!    refused scheme flags, an unknown flag, and an accepted flag at the wrong length. A refusal
//!    that quietly became an acceptance is the failure an allow list exists to prevent.
//! 3. **Signature → locator for all three accepted schemes.** The locator is what the server files
//!    a slot under, so two implementations disagreeing about it means a sign-in that finds nothing.
//! 4. **Seal and open, with a fixed nonce**, plus the negative that matters: a signature one bit
//!    away opens neither the slot nor the same locator.
//!
//! * Regenerate (writes the JSON):
//!   `cargo test --features vectors gen_opener_fixture -- --ignored --nocapture`
//! * Verify (default under `--features vectors`): `opener_fixture_reproducible` rebuilds the JSON
//!   in memory and asserts byte equality with the committed file; `opener_fixture_holds` re-derives
//!   every value in it through the shipped entry points.
#![cfg(feature = "vectors")]

use nmts_crypto::codes::ACCOUNT_CODE_BYTES;
use nmts_crypto::opener::{
    opener_from_signature, opener_message, OpenerRefusal, ECDSA_SERIALIZED_LEN,
    ED25519_SERIALIZED_LEN, FLAG_ED25519, FLAG_MULTISIG, FLAG_PASSKEY, FLAG_SECP256K1,
    FLAG_SECP256R1, FLAG_ZKLOGIN, KIND_WALLET_SIGNATURE, OPENER_LOCATOR_INFO, OPENER_WRAP_INFO,
    PURE_SIGNATURE_LEN, SLOT_LEN, SLOT_NONCE_LEN, SLOT_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The canonical test address: `0x` + 64 `a`. Deliberately the same shape every other wallet
/// fixture in this repo uses, so a reader comparing two files compares the parts that differ.
const ADDRESS_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A second address, one nibble apart, for the "a different wallet is a different message" case.
const ADDRESS_B: &str = "0xbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Fixed pure signature A: bytes 0x00..0x3F.
fn pure_a() -> [u8; PURE_SIGNATURE_LEN] {
    core::array::from_fn(|i| i as u8)
}

/// Fixed pure signature B: A with its last bit flipped — the "different signature" case.
fn pure_b() -> [u8; PURE_SIGNATURE_LEN] {
    let mut b = pure_a();
    b[63] ^= 0x01;
    b
}

/// Fixed NMTS key for the seal vector: 20 bytes, 0xA0..0xB3.
fn nmts_key() -> [u8; ACCOUNT_CODE_BYTES] {
    core::array::from_fn(|i| 0xa0 + i as u8)
}

/// Fixed slot nonce: bytes 0x40..0x57. ⛔ A caller-supplied nonce exists ONLY here and only under
/// the `vectors` feature — a production build that accepts one can be made to repeat one.
fn slot_nonce() -> [u8; SLOT_NONCE_LEN] {
    core::array::from_fn(|i| 0x40 + i as u8)
}

/// `flag || sig || pk`, the serialized form a Sui wallet hands back.
fn serialized(flag: u8, pure: &[u8; PURE_SIGNATURE_LEN], pk_len: usize) -> Vec<u8> {
    let mut out = vec![flag];
    out.extend_from_slice(pure);
    out.extend(std::iter::repeat_n(0x11u8, pk_len));
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("ncf3-openers.json")
}

/// One message vector: the literal bytes, their length and their digest.
fn message_case(label: &str, address: &str, account: u32, app: Option<&str>) -> Value {
    let bytes = opener_message(address, account, app).expect("canonical inputs");
    json!({
        "label": label,
        "address": address,
        "account": account,
        "app": app,
        "message_utf8": String::from_utf8(bytes.clone()).expect("ASCII"),
        "message_hex": hex::encode(&bytes),
        "message_len": bytes.len(),
        "message_sha256": sha256_hex(&bytes),
    })
}

/// One refused message: the inputs and the sentence the refusal must carry.
fn message_refusal(label: &str, address: &str, account: u32, app: Option<&str>) -> Value {
    let err = opener_message(address, account, app).expect_err("must refuse");
    json!({
        "label": label,
        "address": address,
        "account": account,
        "app": app,
        "refusal": format!("{err:?}").split(' ').next().unwrap_or("").to_string(),
        "refusal_message": err.to_string(),
    })
}

/// One accepted scheme: its serialized signature and the locator it yields.
fn signature_case(label: &str, flag: u8, pk_len: usize) -> Value {
    let ser = serialized(flag, &pure_a(), pk_len);
    let opener = opener_from_signature(&ser).expect("accepted scheme");
    json!({
        "label": label,
        "flag": flag,
        "serialized_len": ser.len(),
        "serialized_hex": hex::encode(&ser),
        "locator_hex": hex::encode(opener.locator()),
    })
}

/// One refused signature, with the sentence that has to reach the person.
fn signature_refusal(label: &str, serialized_bytes: &[u8]) -> Value {
    let err = opener_from_signature(serialized_bytes).expect_err("must refuse");
    json!({
        "label": label,
        "serialized_hex": hex::encode(serialized_bytes),
        "refusal_message": err.to_string(),
    })
}

/// Build the whole fixture from the shipped entry points.
fn build() -> Value {
    let ser_a = serialized(FLAG_ED25519, &pure_a(), 32);
    let ser_b = serialized(FLAG_ED25519, &pure_b(), 32);
    let opener_a = opener_from_signature(&ser_a).expect("accepted");
    let opener_b = opener_from_signature(&ser_b).expect("accepted");
    let key = nmts_key();
    let slot = opener_a
        .seal_with_nonce(&slot_nonce(), &key)
        .expect("known kind");

    let long_address = format!("0x{}b", &ADDRESS_A[2..]);
    let short_address = format!("0x{}", &ADDRESS_A[3..]);
    let upper_address = format!("0x{}", ADDRESS_A[2..].to_uppercase());
    let lf_address = format!("{ADDRESS_A}\n");
    let crlf_address = format!("{ADDRESS_A}\r\n");

    json!({
        "format": "NCF-3",
        "section": "1.7",
        "frozen": false,
        "note": "The opener layer is ADDITIVE and re-wrappable: a slot carries its own version \
                 byte. These vectors pin what today's slots are, not what slots must be forever.",
        "wrap_info": String::from_utf8_lossy(OPENER_WRAP_INFO),
        "locator_info": String::from_utf8_lossy(OPENER_LOCATOR_INFO),
        "slot_version": SLOT_VERSION,
        "kind_wallet_signature": KIND_WALLET_SIGNATURE,
        "slot_len": SLOT_LEN,

        "message": [
            message_case("plain", ADDRESS_A, 1, None),
            message_case("with_app", ADDRESS_B, 12, Some("example.com")),
        ],
        "message_negative": [
            message_refusal("account_zero", ADDRESS_A, 0, None),
            message_refusal("address_uppercase", &upper_address, 1, None),
            message_refusal("address_short", &short_address, 1, None),
            message_refusal("address_long", &long_address, 1, None),
            message_refusal("address_trailing_lf", &lf_address, 1, None),
            message_refusal("address_crlf", &crlf_address, 1, None),
            message_refusal("app_uppercase", ADDRESS_A, 1, Some("Example")),
            message_refusal("app_newline", ADDRESS_A, 1, Some("a\nWallet: 0x0")),
        ],

        "signature": [
            signature_case("ed25519", FLAG_ED25519, 32),
            signature_case("secp256k1", FLAG_SECP256K1, 33),
            signature_case("secp256r1", FLAG_SECP256R1, 33),
        ],
        "signature_negative": [
            signature_refusal("empty", &[]),
            signature_refusal("multisig", &serialized(FLAG_MULTISIG, &pure_a(), 32)),
            signature_refusal("zklogin", &serialized(FLAG_ZKLOGIN, &pure_a(), 32)),
            signature_refusal("passkey", &serialized(FLAG_PASSKEY, &pure_a(), 32)),
            signature_refusal("unknown_flag_04", &serialized(0x04, &pure_a(), 32)),
            signature_refusal("unknown_flag_ff", &serialized(0xff, &pure_a(), 32)),
            signature_refusal("ed25519_wrong_length", &serialized(FLAG_ED25519, &pure_a(), 33)),
            signature_refusal("secp256k1_wrong_length", &serialized(FLAG_SECP256K1, &pure_a(), 32)),
            signature_refusal("flag_only", &[FLAG_ED25519]),
        ],

        "slot": {
            "serialized_hex": hex::encode(&ser_a),
            "locator_hex": hex::encode(opener_a.locator()),
            "nmts_key_hex": hex::encode(key),
            "nonce_hex": hex::encode(slot_nonce()),
            "slot_hex": hex::encode(slot),
            "slot_sha256": sha256_hex(&slot),
        },
        "slot_negative": {
            "other_serialized_hex": hex::encode(&ser_b),
            "other_locator_hex": hex::encode(opener_b.locator()),
            "refusal_message": opener_b.open(&slot).expect_err("must refuse").to_string(),
        },
    })
}

/// Write the fixture. Ignored: it is the regenerator, not a judgement.
#[test]
#[ignore]
fn gen_opener_fixture() {
    let path = fixture_path();
    let text = format!("{:#}\n", build());
    std::fs::write(&path, text).expect("fixture is writable");
    println!("wrote {}", path.display());
}

/// The committed file is exactly what the code produces today.
#[test]
fn opener_fixture_reproducible() {
    let committed = std::fs::read_to_string(fixture_path()).expect("fixture is readable");
    assert_eq!(
        committed,
        format!("{:#}\n", build()),
        "the committed opener fixture no longer matches what the crate produces — regenerate it \
         deliberately, and say in the commit which value moved and whose slots have to be re-wrapped"
    );
}

/// Every value in the fixture, re-derived through the shipped entry points.
///
/// ⚠ Deliberately NOT a re-run of `build()`. That would only prove the file matches the function
/// that wrote it; this walks the committed JSON and asks the public API for each answer.
#[test]
fn opener_fixture_holds() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).expect("readable"))
            .expect("fixture parses");

    let mut judged = 0usize;

    for v in doc["message"].as_array().expect("message array") {
        let address = v["address"].as_str().unwrap();
        let account = v["account"].as_u64().unwrap() as u32;
        let app = v["app"].as_str();
        let bytes = opener_message(address, account, app).expect("canonical");
        assert_eq!(hex::encode(&bytes), v["message_hex"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, v["message_len"].as_u64().unwrap());
        assert_eq!(sha256_hex(&bytes), v["message_sha256"].as_str().unwrap());
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            v["message_utf8"].as_str().unwrap()
        );
        assert!(bytes.is_ascii() && !bytes.ends_with(b"\n") && !bytes.contains(&b'\r'));
        judged += 1;
    }
    assert!(judged >= 2, "only {judged} message vectors");

    judged = 0;
    for v in doc["message_negative"].as_array().expect("array") {
        let err = opener_message(
            v["address"].as_str().unwrap(),
            v["account"].as_u64().unwrap() as u32,
            v["app"].as_str(),
        )
        .expect_err("must refuse");
        assert_eq!(err.to_string(), v["refusal_message"].as_str().unwrap());
        judged += 1;
    }
    assert!(judged >= 8, "only {judged} message refusals");

    judged = 0;
    for v in doc["signature"].as_array().expect("array") {
        let ser = hex::decode(v["serialized_hex"].as_str().unwrap()).unwrap();
        let opener = opener_from_signature(&ser).expect("accepted");
        assert_eq!(
            hex::encode(opener.locator()),
            v["locator_hex"].as_str().unwrap(),
            "{}",
            v["label"]
        );
        assert_eq!(opener.kind(), KIND_WALLET_SIGNATURE);
        judged += 1;
    }
    assert_eq!(
        judged, 3,
        "the three accepted schemes, no more and no fewer"
    );

    judged = 0;
    let mut sentences = std::collections::BTreeSet::new();
    for v in doc["signature_negative"].as_array().expect("array") {
        let ser = hex::decode(v["serialized_hex"].as_str().unwrap()).unwrap();
        let err = opener_from_signature(&ser).expect_err("must refuse");
        assert_eq!(err.to_string(), v["refusal_message"].as_str().unwrap());
        sentences.insert(err.to_string());
        judged += 1;
    }
    assert!(judged >= 9, "only {judged} signature refusals");
    assert!(
        sentences.len() >= 6,
        "only {} distinct refusal sentences — two reasons share one",
        sentences.len()
    );

    let s = &doc["slot"];
    let ser = hex::decode(s["serialized_hex"].as_str().unwrap()).unwrap();
    let opener = opener_from_signature(&ser).expect("accepted");
    let key: [u8; ACCOUNT_CODE_BYTES] =
        hex::decode(s["nmts_key_hex"].as_str().unwrap()).unwrap()[..]
            .try_into()
            .unwrap();
    let nonce: [u8; SLOT_NONCE_LEN] = hex::decode(s["nonce_hex"].as_str().unwrap()).unwrap()[..]
        .try_into()
        .unwrap();
    let slot = opener.seal_with_nonce(&nonce, &key).expect("known kind");
    assert_eq!(hex::encode(slot), s["slot_hex"].as_str().unwrap());
    assert_eq!(slot.len(), SLOT_LEN);
    assert_eq!(*opener.open(&slot).expect("opens"), key);
    // ⛔ The key must not be sitting in the slot in the clear.
    assert!(!slot.windows(key.len()).any(|w| w == key));

    let n = &doc["slot_negative"];
    let other =
        opener_from_signature(&hex::decode(n["other_serialized_hex"].as_str().unwrap()).unwrap())
            .expect("accepted");
    assert_ne!(other.locator(), opener.locator());
    assert_eq!(
        hex::encode(other.locator()),
        n["other_locator_hex"].as_str().unwrap()
    );
    assert_eq!(
        other.open(&slot).expect_err("must refuse").to_string(),
        n["refusal_message"].as_str().unwrap()
    );
    assert_eq!(other.open(&slot), Err(OpenerRefusal::DoesNotOpen));

    // The two serialized lengths the allow list fixes, asserted rather than assumed.
    assert_eq!(ED25519_SERIALIZED_LEN, 97);
    assert_eq!(ECDSA_SERIALIZED_LEN, 98);
}
