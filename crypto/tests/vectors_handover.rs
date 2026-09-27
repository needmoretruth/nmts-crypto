//! Conformance fixture for the handover file and the public code file (NCF-3 §5.6, §5.7) —
//! `tests/vectors/ncf3-handover.json`.
//!
//! ⛔ ITS OWN FILE, AND `ncf3.json` IS NOT TOUCHED. That artifact is the frozen format; the handover
//! file is a new object built from frozen parts, and mixing the two would put its cases inside the
//! file whose promise is that nothing in it ever moves.
//!
//! What it pins, from three account codes and fixed nonces, so a second implementation can be held
//! to it byte for byte:
//!
//! 1. **The whole handover file text** — the exact JSON the reference writer produces, `note`
//!    included (`note` is where the two note lines live; §5.6 points here for them). Every sealed
//!    value in it is reproducible because every nonce and the encapsulation randomness are fixed.
//! 2. **The documents under the seals** — the name document with its two binding values
//!    (`network` and `parts_sha256`) and the parts document, as the writer spells them.
//! 3. **The refusals §5.6 lists**, each as a complete file text with the reader's network and the
//!    outcome a reader must reach: a parts list moved in from another handover of the same file, a
//!    parts list re-sealed by another holder of the file key, a relabelled network, the other
//!    network, an upper-case item, a swapped sender, the wrong recipient, a newer version, a version
//!    that is not a number, a non-canonical base64url value, an unknown key, and not a handover at all.
//! 4. **The public code file** of the recipient, and one whose identity is not the code's.
//!
//! The TypeScript readers — the browser's and the command-line tool's — read this same file
//! (`web/test/handover-vectors.test.ts`, `cli/test/handover-vectors.test.ts`).
//!
//! * Regenerate: `cargo test --features vectors gen_handover_fixture -- --ignored --nocapture`
//! * Verify (default under `--features vectors`): `handover_fixture_reproducible` rebuilds the
//!   JSON in memory and asserts byte equality; `handover_fixture_holds` opens every case through
//!   the shipped entry points.
#![cfg(feature = "vectors")]

use nmts_crypto::codes::ACCOUNT_CODE_BYTES;
use nmts_crypto::share::{self, SharePayload, SharePublicKey};
use nmts_crypto::wrap::{self, AAD_HANDOVER_PARTS, ENVELOPE_NONCE_LEN};
use nmts_crypto::{b64, kdf, AccountCode, DerivedKeys};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const AAD_SHARE_NAME: &[u8] = b"nmts/v3/share-name";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const AAD_SHARE_CONTENT_HASH: &[u8] = b"nmts/v3/share-content-hash";

const ITEM: &str = "3f2b1a90-0000-4000-8000-00000000c050";
const NAME: &str = "contract.pdf";
const BODY: &str = "the contents that were handed over";
const NETWORK: &str = "testnet";

/// The two lines every handover file carries in `note` (§5.6). The second is Korean, written here
/// as escapes so the source stays ASCII; the fixture carries it as JSON escapes for the same reason.
const NOTE_EN: &str = "An NMTS handover file. Sign in at nmts.me with the NMTS key it was made for, then open it from Shared with me \u{2192} Open handover file.";
const NOTE_KO: &str = "NMTS \u{ac74}\u{b124}\u{ae30} \u{d30c}\u{c77c}\u{c785}\u{b2c8}\u{b2e4}. \u{c774} \u{d30c}\u{c77c}\u{c744} \u{bc1b}\u{c744} NMTS \u{d0a4}\u{b85c} nmts.me\u{c5d0} \u{b85c}\u{adf8}\u{c778}\u{d55c} \u{b4a4} \u{300c}\u{bc1b}\u{c740} \u{acf5}\u{c720}\u{d568}\u{300d} \u{2192} \u{300c}\u{ac74}\u{b124}\u{ae30} \u{d30c}\u{c77c} \u{c5f4}\u{ae30}\u{300d}\u{c5d0}\u{c11c} \u{c5ec}\u{c2ed}\u{c2dc}\u{c624}.";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("ncf3-handover.json")
}

fn ramp<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

/// One account, from a fixed code, the way every client derives it.
struct Account {
    code: String,
    keys: DerivedKeys,
}

impl Account {
    fn new(start: u8) -> Self {
        let bytes: [u8; ACCOUNT_CODE_BYTES] = ramp(start);
        Self {
            code: AccountCode::from_bytes(bytes).display(),
            keys: kdf::derive_from_bytes(&bytes).expect("a fixed code derives"),
        }
    }
    fn identity(&self) -> SharePublicKey {
        share::public_key(
            &self.keys.share_kem_seed,
            &self.keys.share_auth_secret,
            &self.keys.share_sig_seed,
        )
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `JSON.stringify(value, null, 2) + "\n"` for a flat object whose values are strings, numbers or
/// arrays of strings — the reference writer's exact spelling, keys in the order given.
fn js_pretty(fields: &[(&str, Value)]) -> String {
    let mut out = String::from("{\n");
    for (i, (key, value)) in fields.iter().enumerate() {
        out.push_str("  ");
        out.push_str(&serde_json::to_string(key).expect("a key serialises"));
        out.push_str(": ");
        match value {
            Value::Array(items) => {
                out.push_str("[\n");
                for (j, item) in items.iter().enumerate() {
                    out.push_str("    ");
                    out.push_str(&serde_json::to_string(item).expect("an item serialises"));
                    if j + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str("  ]");
            }
            other => out.push_str(&serde_json::to_string(other).expect("a value serialises")),
        }
        if i + 1 < fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

/// A handover file's fields, in the writer's order.
fn handover_fields(
    network: &str,
    item: &str,
    sender: &str,
    envelope: &str,
    name: &str,
    hash: &str,
    parts: &str,
) -> Vec<(&'static str, Value)> {
    vec![
        ("format", json!("nmts-handover")),
        ("version", json!(1)),
        ("network", json!(network)),
        ("item", json!(item)),
        ("sender", json!(sender)),
        ("envelope", json!(envelope)),
        ("name", json!(name)),
        ("hash", json!(hash)),
        ("parts", json!(parts)),
        ("note", json!([NOTE_EN, NOTE_KO])),
    ]
}

/// Replace one field's value (or append a key) and write the text again.
fn with(fields: &[(&'static str, Value)], key: &'static str, value: Value) -> String {
    let mut out: Vec<(&'static str, Value)> = fields.to_vec();
    match out.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => out.push((key, value)),
    }
    js_pretty(&out)
}

fn parts_document(exp_patch: u32, exp_blob: u32, blob: &str) -> String {
    format!(
        "{{\"f\":\"nmts-handover-parts/1\",\"parts\":[{{\"i\":0,\"blob\":null,\"patch\":\"patch-p\",\"len\":108,\"exp\":{exp_patch}}},{{\"i\":1,\"blob\":\"{blob}\",\"patch\":null,\"len\":102,\"exp\":{exp_blob}}}]}}"
    )
}

fn name_document(network: &str, parts_sha256: &str) -> String {
    format!(
        "{{\"f\":\"nmts-share-file/1\",\"name\":\"{NAME}\",\"size\":{},\"network\":\"{network}\",\"parts_sha256\":\"{parts_sha256}\"}}",
        BODY.len()
    )
}

/// Non-ASCII as JSON escapes, so the fixture is plain ASCII and a repository gate that refuses
/// Korean text in published files reads it as it reads every other fixture.
fn ascii_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn build() -> Value {
    let sender = Account::new(0x21);
    let recipient = Account::new(0x41);
    let stranger = Account::new(0x61);
    let dek: [u8; 32] = ramp(0xa0);
    let digest = sha256(BODY.as_bytes());

    let hash_ct = wrap::seal_with_nonce(
        &dek,
        &ramp::<ENVELOPE_NONCE_LEN>(0x10),
        AAD_SHARE_CONTENT_HASH,
        &digest,
    );
    let parts_doc = parts_document(90, 12, "blob-b");
    let parts_ct =
        wrap::seal_with_nonce(&dek, &ramp(0x30), AAD_HANDOVER_PARTS, parts_doc.as_bytes());
    let parts_sha256 = b64::encode(&sha256(&parts_ct));
    let name_doc = name_document(NETWORK, &parts_sha256);
    let name_ct = wrap::seal_with_nonce(&dek, &ramp(0x50), AAD_SHARE_NAME, name_doc.as_bytes());

    let to = recipient.identity();
    let envelope = share::wrap_dek_for_with_randomness(
        &sender.keys.share_auth_secret,
        &sender.keys.share_sig_seed,
        &to,
        &to.address(),
        &dek,
        &SharePayload {
            item_id: ITEM.as_bytes(),
            name_ct: &name_ct,
            content_hash_ct: &hash_ct,
        },
        &share::EnvelopeRandomness {
            kem_eseed: &ramp(0x70),
            envelope_nonce: &ramp(0xc0),
        },
    )
    .expect("wrap to a verified recipient");

    let sender_identity = b64::encode(&sender.identity().to_bytes());
    let fields = handover_fields(
        NETWORK,
        ITEM,
        &sender_identity,
        &b64::encode(&envelope),
        &b64::encode(&name_ct),
        &b64::encode(&hash_ct),
        &b64::encode(&parts_ct),
    );
    let file_text = js_pretty(&fields);

    // Another handover of the same file, made before an extension: same key, its own parts list.
    let older_parts = wrap::seal_with_nonce(
        &dek,
        &ramp(0x90),
        AAD_HANDOVER_PARTS,
        parts_document(5, 5, "blob-b").as_bytes(),
    );
    // Another holder of the file key, naming a piece of their choosing.
    let chosen_parts = wrap::seal_with_nonce(
        &dek,
        &ramp(0xb0),
        AAD_HANDOVER_PARTS,
        parts_document(90, 12, "attacker-blob").as_bytes(),
    );
    // The same bytes of `hash`, spelled with a non-zero unused bit in the last character.
    let hash_text = b64::encode(&hash_ct);
    let last = B64URL
        .iter()
        .position(|&c| Some(c) == hash_text.bytes().last())
        .expect("alphabet");
    let noncanonical = format!(
        "{}{}",
        &hash_text[..hash_text.len() - 1],
        B64URL[last | 1] as char
    );
    let refusal = |label: &str,
                   reader: &str,
                   account: &str,
                   text: String,
                   outcome: &str,
                   why: &str| {
        json!({ "label": label, "reader_network": reader, "account": account, "file_text": text, "outcome": outcome, "why": why })
    };
    let refusals = vec![
        refusal("transplanted_parts", NETWORK, "recipient", with(&fields, "parts", json!(b64::encode(&older_parts))), "damaged",
            "the parts list of another handover of the same file: it opens under the file key, and its SHA-256 is not the one the name binds"),
        refusal("resealed_parts", NETWORK, "recipient", with(&fields, "parts", json!(b64::encode(&chosen_parts))), "damaged",
            "a parts list sealed by another holder of the file key: the same refusal, for the same reason"),
        refusal("relabelled_network", "mainnet", "recipient", with(&fields, "network", json!("mainnet")), "damaged",
            "the network field edited to the reader's: the name document still says testnet"),
        refusal("other_network", "mainnet", "recipient", file_text.clone(), "network",
            "a file made on the other network, refused before any key is used"),
        refusal("uppercase_item", NETWORK, "recipient", with(&fields, "item", json!(ITEM.to_uppercase())), "damaged",
            "the item id is compared as written and must be lowercase"),
        refusal("swapped_sender", NETWORK, "recipient", with(&fields, "sender", json!(b64::encode(&stranger.identity().to_bytes()))), "damaged",
            "the identity carried is not the one the envelope's first 16 bytes name"),
        refusal("not_for_me", NETWORK, "stranger", file_text.clone(), "not-for-me",
            "a genuine file opened with another NMTS key"),
        refusal("newer_version", NETWORK, "recipient", with(&fields, "version", json!(2)), "unknown-version",
            "an integer version above 1"),
        refusal("version_not_a_number", NETWORK, "recipient", with(&fields, "version", json!("1")), "damaged",
            "a version that is not an integer above 1 is a bad field"),
        refusal("noncanonical_base64url", NETWORK, "recipient", with(&fields, "hash", json!(noncanonical)), "damaged",
            "the unused bits of the last character are not zero"),
        refusal("unknown_key", NETWORK, "recipient", with(&fields, "extra", json!("x")), "damaged",
            "the key set is closed"),
        refusal("not_a_handover", NETWORK, "recipient", with(&fields, "format", json!("nmts-something")), "format",
            "the format string is not nmts-handover"),
    ];

    let recipient_code = to.address().display();
    let recipient_identity = b64::encode(&to.to_bytes());
    let public_code_file = js_pretty(&[
        ("format", json!("nmts-public-code")),
        ("version", json!(1)),
        ("code", json!(recipient_code)),
        ("identity", json!(recipient_identity)),
    ]);
    let lying_public_code_file = js_pretty(&[
        ("format", json!("nmts-public-code")),
        ("version", json!(1)),
        ("code", json!(stranger.identity().address().display())),
        ("identity", json!(recipient_identity)),
    ]);

    json!({
        "note": "NCF-3 §5.6 and §5.7 conformance. Every account is derived from its code by §1; every nonce and the encapsulation randomness are fixed, so `file_text` is reproducible byte for byte. A reader opens `file_text` as `recipient` on `network` and must reach `opened`; each case in `refusals` must end in its `outcome` (format, unknown-version, network, not-for-me, damaged). `file_text.note` holds the exact note lines.",
        "accounts": {
            "sender": sender.code,
            "recipient": recipient.code,
            "stranger": stranger.code,
        },
        "network": NETWORK,
        "item": ITEM,
        "dek_hex": hex::encode(dek),
        "body_utf8": BODY,
        "content_sha256_hex": hex::encode(digest),
        "name_document": name_doc,
        "parts_document": parts_doc,
        "file_text": file_text,
        "opened": {
            "name": NAME,
            "size": BODY.len(),
            "sender_code": sender.identity().address().display(),
            "parts": [
                { "blob": null, "patch": "patch-p", "len": 108, "exp": 90 },
                { "blob": "blob-b", "patch": null, "len": 102, "exp": 12 },
            ],
            "earliest_exp": 12,
        },
        "refusals": refusals,
        "public_code_file": {
            "text": public_code_file,
            "code": recipient_code,
        },
        "public_code_file_refusals": [
            { "label": "identity_of_another_code", "text": lying_public_code_file, "outcome": "damaged",
              "why": "the identity fingerprints to a different code than the one the file names" },
        ],
    })
}

fn render() -> String {
    ascii_json(&format!("{:#}\n", build()))
}

/// Write the fixture. Ignored: it is the regenerator, not a judgement.
#[test]
#[ignore]
fn gen_handover_fixture() {
    let path = fixture_path();
    std::fs::write(&path, render()).expect("fixture is writable");
    println!("wrote {}", path.display());
}

/// The committed file is exactly what the code produces today.
#[test]
fn handover_fixture_reproducible() {
    let committed = std::fs::read_to_string(fixture_path()).expect("fixture is readable");
    assert_eq!(
        committed,
        render(),
        "the committed handover fixture no longer matches what the crate produces — regenerate it \
         deliberately, and say in the commit which value moved"
    );
}

/// Open a file text as `account` with the crate's own primitives: the address check, the unwrap,
/// the name, the binding values, the parts. `Err` names the step that refused.
fn open(account: &Account, text: &str) -> Result<(String, String), &'static str> {
    let doc: Value = serde_json::from_str(text).map_err(|_| "json")?;
    let field = |k: &str| -> Result<Vec<u8>, &'static str> {
        b64::decode(doc[k].as_str().ok_or("field")?).map_err(|_| "base64")
    };
    let sender = SharePublicKey::from_bytes(&field("sender")?).map_err(|_| "sender")?;
    let envelope = field("envelope")?;
    let claimed = share::claimed_sender(&envelope).map_err(|_| "envelope")?;
    share::verify_address(&sender, &claimed).map_err(|_| "sender")?;
    let (name_ct, hash_ct, parts_ct) = (field("name")?, field("hash")?, field("parts")?);
    let item = doc["item"].as_str().ok_or("field")?;
    let dek = share::unwrap_dek(
        &account.keys.share_kem_seed,
        &account.keys.share_auth_secret,
        &account.keys.share_sig_seed,
        &sender,
        &envelope,
        &SharePayload {
            item_id: item.as_bytes(),
            name_ct: &name_ct,
            content_hash_ct: &hash_ct,
        },
    )
    .map_err(|_| "unwrap")?;
    let name = wrap::open(&dek, AAD_SHARE_NAME, &name_ct).map_err(|_| "name")?;
    let named: Value = serde_json::from_slice(&name).map_err(|_| "name")?;
    if named["parts_sha256"].as_str() != Some(b64::encode(&sha256(&parts_ct)).as_str()) {
        return Err("binding");
    }
    if named["network"] != doc["network"] {
        return Err("binding");
    }
    let parts = wrap::open(&dek, AAD_HANDOVER_PARTS, &parts_ct).map_err(|_| "parts")?;
    Ok((
        String::from_utf8(name).map_err(|_| "name")?,
        String::from_utf8(parts).map_err(|_| "parts")?,
    ))
}

/// Every case in the committed fixture, opened through the shipped entry points.
///
/// ⚠ Deliberately NOT a re-run of `build()`: this walks the committed JSON and asks the crate.
/// The format-level refusals (version, key set, base64url spelling, item case, network) are the
/// JSON readers' — the TypeScript tests hold those; here each must at least not open as the
/// genuine file does.
#[test]
fn handover_fixture_holds() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).expect("readable"))
            .expect("fixture parses");
    let accounts = [
        ("recipient", Account::new(0x41)),
        ("stranger", Account::new(0x61)),
    ];
    let as_account = |label: &str| -> &Account {
        &accounts
            .iter()
            .find(|(l, _)| *l == label)
            .expect("known account")
            .1
    };
    for (label, account) in &accounts {
        assert_eq!(doc["accounts"][label].as_str(), Some(account.code.as_str()));
    }

    let (name, parts) = open(
        as_account("recipient"),
        doc["file_text"].as_str().expect("text"),
    )
    .expect("the genuine file opens for its recipient");
    assert_eq!(Some(name.as_str()), doc["name_document"].as_str());
    assert_eq!(Some(parts.as_str()), doc["parts_document"].as_str());

    for case in doc["refusals"].as_array().expect("refusals") {
        let label = case["label"].as_str().expect("label");
        let text = case["file_text"].as_str().expect("text");
        let account = as_account(case["account"].as_str().expect("account"));
        match label {
            // The one step only the binding catches: both open under the key, neither is bound.
            "transplanted_parts" | "resealed_parts" | "relabelled_network" => {
                assert_eq!(open(account, text), Err("binding"), "{label}");
            }
            "not_for_me" | "uppercase_item" => {
                assert_eq!(open(account, text), Err("unwrap"), "{label}")
            }
            "swapped_sender" => assert_eq!(open(account, text), Err("sender"), "{label}"),
            _ => {} // refused by the JSON reader before any key is used
        }
    }
}
