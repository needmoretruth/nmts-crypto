//! Conformance fixture for the public link (NCF-3 §5.8) — `tests/vectors/ncf3-links.json`.
//!
//! ⛔ ITS OWN FILE, AND `ncf3.json` IS NOT TOUCHED. That artifact is the frozen format; the public
//! link is a new object built from frozen parts (two new AADs, `nmts/v3/link-wrap` and
//! `nmts/v3/link-secret`), and mixing the two would put its cases inside the file whose promise is
//! that nothing in it ever moves.
//!
//! What it pins, from a fixed link secret, a fixed DEK and fixed nonces, so a second implementation
//! can be held to it byte for byte:
//!
//! 1. **The link secret as the fragment spells it** — unpadded base64url, 43 characters.
//! 2. **The four values the server stores** — `wrapped = E(S, "nmts/v3/link-wrap", DEK)`, the §5.4
//!    re-seals `name` (the share document) and `hash` under the DEK, and
//!    `owner_secret = E(dataKey, "nmts/v3/link-secret", S)` under a fixed `dataKey`.
//! 3. **The refusals** — each a (secret, envelope) pair `unwrap_dek_from_link` must refuse: the
//!    wrong secret, the DEK sealed under the right secret with another role's label (`dek-wrap`,
//!    `share-name`), a flipped commitment byte, a flipped ciphertext byte, and a truncated envelope;
//!    and two `owner_secret` refusals for `open_link_secret`: another account's `dataKey`, and `S`
//!    sealed under the right `dataKey` with the `dek-wrap` label.
//!
//! * Regenerate: `cargo test --features vectors gen_links_fixture -- --ignored --nocapture`
//! * Verify (default under `--features vectors`): `links_fixture_reproducible` rebuilds the JSON in
//!   memory and asserts byte equality; `links_fixture_holds` opens every case through the shipped
//!   entry points.
#![cfg(feature = "vectors")]

use nmts_crypto::b64;
use nmts_crypto::wrap::{
    self, WrapError, AAD_DEK_WRAP, AAD_LINK_SECRET, AAD_LINK_WRAP, ENVELOPE_NONCE_LEN,
    LINK_SECRET_LEN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const AAD_SHARE_NAME: &[u8] = b"nmts/v3/share-name";
const AAD_SHARE_CONTENT_HASH: &[u8] = b"nmts/v3/share-content-hash";

const NAME_DOCUMENT: &str = r#"{"f":"nmts-share-file/1","name":"holiday.jpg","size":34}"#;
const BODY: &str = "the contents behind a public link.";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("ncf3-links.json")
}

fn ramp<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn refusal(label: &str, secret: &[u8], envelope: &[u8], why: &str) -> Value {
    json!({
        "label": label,
        "link_secret_hex": hex::encode(secret),
        "wrapped_hex": hex::encode(envelope),
        "why": why,
    })
}

fn build() -> Value {
    let secret: [u8; LINK_SECRET_LEN] = ramp(0xc0);
    let other_secret: [u8; LINK_SECRET_LEN] = ramp(0xe0);
    let dek: [u8; 32] = ramp(0xa0);
    let nonce_wrap: [u8; ENVELOPE_NONCE_LEN] = ramp(0x10);
    let nonce_name: [u8; ENVELOPE_NONCE_LEN] = ramp(0x30);
    let nonce_hash: [u8; ENVELOPE_NONCE_LEN] = ramp(0x50);
    let nonce_owner: [u8; ENVELOPE_NONCE_LEN] = ramp(0x70);
    let data_key: [u8; 32] = ramp(0x80);
    let other_data_key: [u8; 32] = ramp(0x90);
    let digest: [u8; 32] = Sha256::digest(BODY.as_bytes()).into();

    let wrapped = wrap::seal_with_nonce(&secret, &nonce_wrap, AAD_LINK_WRAP, &dek);
    let name_ct =
        wrap::seal_with_nonce(&dek, &nonce_name, AAD_SHARE_NAME, NAME_DOCUMENT.as_bytes());
    let hash_ct = wrap::seal_with_nonce(&dek, &nonce_hash, AAD_SHARE_CONTENT_HASH, &digest);
    let owner_secret = wrap::seal_with_nonce(&data_key, &nonce_owner, AAD_LINK_SECRET, &secret);

    let mut flipped_commitment = wrapped.clone();
    flipped_commitment[ENVELOPE_NONCE_LEN] ^= 0x01;
    let mut flipped_body = wrapped.clone();
    let last = flipped_body.len() - 1;
    flipped_body[last] ^= 0x01;

    json!({
        "comment": "NCF-3 section 5.8 public link. The link is https://nmts.me/l/<token>#<link_secret_b64url>; \
                    the server stores wrapped, name (absent when the link hides the name), hash and \
                    owner_secret beside the token and never sees the secret.",
        "link_secret_hex": hex::encode(secret),
        "link_secret_b64url": b64::encode(&secret),
        "dek_hex": hex::encode(dek),
        "wrap_nonce_hex": hex::encode(nonce_wrap),
        "wrapped_hex": hex::encode(&wrapped),
        "wrapped_b64url": b64::encode(&wrapped),
        "name_document": NAME_DOCUMENT,
        "name_nonce_hex": hex::encode(nonce_name),
        "name_hex": hex::encode(&name_ct),
        "body_utf8": BODY,
        "content_sha256_hex": hex::encode(digest),
        "hash_nonce_hex": hex::encode(nonce_hash),
        "hash_hex": hex::encode(&hash_ct),
        "data_key_hex": hex::encode(data_key),
        "owner_secret_nonce_hex": hex::encode(nonce_owner),
        "owner_secret_hex": hex::encode(&owner_secret),
        "owner_secret_refusals": [
            json!({
                "label": "other_data_key",
                "data_key_hex": hex::encode(other_data_key),
                "owner_secret_hex": hex::encode(&owner_secret),
                "why": "only the uploader's dataKey opens the sealed secret",
            }),
            json!({
                "label": "dek_wrap_label",
                "data_key_hex": hex::encode(data_key),
                "owner_secret_hex": hex::encode(wrap::seal_with_nonce(&data_key, &nonce_owner, AAD_DEK_WRAP, &secret)),
                "why": "the right dataKey and the right secret under the DEK-wrap label: a wrapped DEK is never a link secret",
            }),
        ],
        "refusals": [
            refusal("wrong_secret", &other_secret, &wrapped,
                "the envelope names exactly one key (section 3.2); another link's secret does not open it"),
            refusal("dek_wrap_label", &secret,
                &wrap::seal_with_nonce(&secret, &nonce_wrap, AAD_DEK_WRAP, &dek),
                "the right secret and the right DEK under the account-wrap label: the role is bound"),
            refusal("share_name_label", &secret,
                &wrap::seal_with_nonce(&secret, &nonce_wrap, AAD_SHARE_NAME, &dek),
                "the right secret and the right DEK under the share-name label: the role is bound"),
            refusal("flipped_commitment", &secret, &flipped_commitment,
                "one bit of the commitment changed; refused before decrypting"),
            refusal("flipped_ciphertext", &secret, &flipped_body,
                "one bit of the tag changed"),
            refusal("truncated", &secret, &wrapped[..ENVELOPE_NONCE_LEN + 8],
                "shorter than nonce + commitment + tag"),
        ],
    })
}

fn render() -> String {
    format!("{:#}\n", build())
}

/// Write the fixture. Ignored: it is the regenerator, not a judgement.
#[test]
#[ignore]
fn gen_links_fixture() {
    let path = fixture_path();
    std::fs::write(&path, render()).expect("fixture is writable");
    println!("wrote {}", path.display());
}

/// The committed file is exactly what the code produces today.
#[test]
fn links_fixture_reproducible() {
    let committed = std::fs::read_to_string(fixture_path()).expect("fixture is readable");
    assert_eq!(
        committed,
        render(),
        "the committed link fixture no longer matches what the crate produces — regenerate it \
         deliberately, and say in the commit which value moved"
    );
}

fn hex_field(doc: &Value, key: &str) -> Vec<u8> {
    hex::decode(doc[key].as_str().expect("hex field")).expect("valid hex")
}

/// Every case in the committed fixture, opened through the shipped entry points — the reader's
/// three steps of §5.8: the secret opens `wrapped`, the DEK opens `name` and `hash`, and the digest
/// is the body's.
#[test]
fn links_fixture_holds() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).expect("readable"))
            .expect("fixture parses");

    let fragment = doc["link_secret_b64url"].as_str().expect("fragment");
    assert_eq!(fragment.len(), 43, "the fragment is 32 bytes, unpadded");
    let secret: [u8; LINK_SECRET_LEN] = b64::decode(fragment)
        .expect("canonical base64url")
        .try_into()
        .expect("32 bytes");
    assert_eq!(secret.to_vec(), hex_field(&doc, "link_secret_hex"));

    let wrapped = hex_field(&doc, "wrapped_hex");
    assert_eq!(wrapped.len(), wrap::WRAPPED_DEK_LEN);
    assert_eq!(
        b64::decode(doc["wrapped_b64url"].as_str().expect("b64")).expect("b64"),
        wrapped
    );
    let dek = wrap::unwrap_dek_from_link(&secret, &wrapped).expect("the genuine link opens");
    assert_eq!(dek.to_vec(), hex_field(&doc, "dek_hex"));

    let name = wrap::open(&dek, AAD_SHARE_NAME, &hex_field(&doc, "name_hex")).expect("name opens");
    assert_eq!(
        Some(std::str::from_utf8(&name).expect("utf-8")),
        doc["name_document"].as_str()
    );

    // The §5.4 re-seal under the DEK with the share label (the crate's `open_content_hash` is the
    // `dataKey` role).
    let digest =
        wrap::open(&dek, AAD_SHARE_CONTENT_HASH, &hex_field(&doc, "hash_hex")).expect("hash opens");
    assert_eq!(digest, hex_field(&doc, "content_sha256_hex"));
    let body_digest: [u8; 32] =
        Sha256::digest(doc["body_utf8"].as_str().expect("body").as_bytes()).into();
    assert_eq!(digest, body_digest.to_vec());

    let refusals = doc["refusals"].as_array().expect("refusals");
    assert_eq!(refusals.len(), 6);
    for case in refusals {
        let label = case["label"].as_str().expect("label");
        let secret: [u8; LINK_SECRET_LEN] = hex_field(case, "link_secret_hex")
            .try_into()
            .expect("32 bytes");
        let envelope = hex_field(case, "wrapped_hex");
        let expected = if label == "truncated" {
            WrapError::TooShort
        } else {
            WrapError::Auth
        };
        assert_eq!(
            wrap::unwrap_dek_from_link(&secret, &envelope).map(|_| ()),
            Err(expected),
            "{label}"
        );
    }

    // The uploader's side: the sealed secret opens under the uploader's dataKey and gives back the
    // very `S` the fragment spells, so the whole link can be shown again.
    let data_key: [u8; 32] = hex_field(&doc, "data_key_hex")
        .try_into()
        .expect("32 bytes");
    let reopened = wrap::open_link_secret(&data_key, &hex_field(&doc, "owner_secret_hex"))
        .expect("the uploader reopens the secret");
    assert_eq!(*reopened, secret);

    let owner_refusals = doc["owner_secret_refusals"].as_array().expect("refusals");
    assert_eq!(owner_refusals.len(), 2);
    for case in owner_refusals {
        let label = case["label"].as_str().expect("label");
        let key: [u8; 32] = hex_field(case, "data_key_hex")
            .try_into()
            .expect("32 bytes");
        assert_eq!(
            wrap::open_link_secret(&key, &hex_field(case, "owner_secret_hex")).map(|_| ()),
            Err(WrapError::Auth),
            "{label}"
        );
    }
}
