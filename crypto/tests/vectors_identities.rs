//! Conformance fixture for NUMBERED share identities (NCF-3 §5.9) — `tests/vectors/ncf3-identities.json`.
//!
//! ⛔ ITS OWN FILE, AND `ncf3.json` IS NOT TOUCHED. That artifact's promise is that nothing in it
//! ever moves; §5.9 is an addition, so its vectors sit beside the frozen file and read from it.
//!
//! What it pins, and why each one is here rather than assumed:
//!
//! 1. **Identity 0 through the numbered path is the identity that already exists.** `R(0) = PRK`,
//!    so the three seeds the numbered path gives for index 0 are compared byte for byte with the
//!    seeds `ncf3.json` pins for the same account code, and the bundle builder at index 0 is
//!    compared with every identity `ncf3.json`'s `address` group pins. Both comparisons read the
//!    frozen file; neither re-derives the value it compares against.
//! 2. **`shareIdRoot`, `R(N)`, the three seeds, the root, the address and the bundle digest for
//!    N = 1, 2 and 10**, with identity 1's 4,989 bytes in full. 10 is there for the decimal rule:
//!    identity 10 is not identity 1 followed by a zero byte.
//! 3. **The refusal of N = 0** by the sub-root function, by its sentence.
//! 4. **A wrap to identity 1 at fixed randomness**, sent AS a numbered identity of another account,
//!    that opens with identity 1's secrets and is refused — with the one error every refusal gives —
//!    with identity 0's and identity 2's.
//!
//! * Regenerate (writes the JSON):
//!   `cargo test --features vectors gen_identity_fixture -- --ignored --nocapture`
//! * Verify (default under `--features vectors`): `identity_fixture_reproducible` rebuilds the JSON
//!   in memory and asserts byte equality with the committed file; `identity_fixture_holds`
//!   re-derives every value in it through the shipped entry points and an independent HKDF.
#![cfg(feature = "vectors")]

use hkdf::Hkdf;
use nmts_crypto::kdf::{
    self, share_seeds_from_root, KdfError, ShareSeeds, INFO_SHARE_ID_PREFIX, INFO_SHARE_ID_ROOT,
};
use nmts_crypto::share::{
    self, EnvelopeRandomness, ShareError, SharePayload, SharePublicKey, KEM_RANDOMNESS_LEN,
    SHARE_PUBLIC_LEN,
};
use nmts_crypto::wrap::ENVELOPE_NONCE_LEN;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// The `kdf` entry of `ncf3.json` whose account this fixture numbers.
const ACCOUNT_LABEL: &str = "fixed_pattern";
/// The numbers pinned in full: the first, the second, and the first with two decimal digits.
const NUMBERS: [u32; 3] = [1, 2, 10];
/// The recipient's number in the share vector.
const RECIPIENT_INDEX: u32 = 1;
/// The sender's number — deliberately not the recipient's, so an implementation that stamps one
/// side's number where the other belongs fails here instead of passing by coincidence.
const SENDER_INDEX: u32 = 3;

/// A run of `N` bytes starting at `base`, wrapping at 256 — the same helper `vectors.rs` uses.
fn ramp<const N: usize>(base: u8) -> [u8; N] {
    core::array::from_fn(|i| base.wrapping_add(i as u8))
}

/// The sender's `shareIdRoot`: bytes 0x60..0x7F. A stand-in parent, so the sender needs no
/// account code — any 32 bytes are a valid parent, and this also pins the sub-root rule once
/// without Argon2id in front of it.
fn sender_share_id_root() -> [u8; 32] {
    ramp(0x60)
}

/// The share row, the DEK and the two random inputs: the values `vectors.rs` uses for its `share`
/// group, so a reader comparing the two files compares only what differs.
fn item_id() -> &'static [u8] {
    b"6a0f2b1c-1111-4222-8333-444455556666"
}
fn name_ct() -> [u8; 61] {
    ramp(0x40)
}
fn content_hash_ct() -> [u8; 104] {
    ramp(0x80)
}
fn dek() -> [u8; 32] {
    ramp(0xE0)
}
fn eseed() -> [u8; KEM_RANDOMNESS_LEN] {
    ramp(0xD0)
}
fn envelope_nonce() -> [u8; ENVELOPE_NONCE_LEN] {
    ramp(0x1A)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

fn fixture_path() -> PathBuf {
    vectors_dir().join("ncf3-identities.json")
}

/// The frozen artifact, read — never rewritten — by this suite.
fn ncf3() -> Value {
    let text = std::fs::read_to_string(vectors_dir().join("ncf3.json")).expect("ncf3.json");
    serde_json::from_str(&text).expect("ncf3.json parses")
}

/// The `ncf3.json` `kdf` entry this fixture's account is.
fn ncf3_account(doc: &Value) -> Value {
    doc["kdf"]
        .as_array()
        .expect("kdf group")
        .iter()
        .find(|v| v["label"] == ACCOUNT_LABEL)
        .cloned()
        .expect("the account label is in ncf3.json")
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().expect("hex string")).expect("hex")[..]
        .try_into()
        .expect("32 bytes")
}

/// `R(N)` by an HKDF that is not the crate's code path: Expand(shareIdRoot, prefix || dec(N)).
fn sub_root_independently(share_id_root: &[u8; 32], index: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::from_prk(share_id_root)
        .expect("32 bytes")
        .expand(format!("nmts/v3/share-id/{index}").as_bytes(), &mut out)
        .expect("expand");
    out
}

/// The three §5.1 labels expanded under `root`, independently of the crate.
fn seeds_independently(root: &[u8; 32]) -> [[u8; 32]; 3] {
    let hk = Hkdf::<Sha256>::from_prk(root).expect("32 bytes");
    let mut out = [[0u8; 32]; 3];
    for (slot, label) in out.iter_mut().zip([
        &b"nmts/v3/share-kem"[..],
        b"nmts/v3/share-auth",
        b"nmts/v3/share-sig",
    ]) {
        hk.expand(label, slot).expect("expand");
    }
    out
}

fn identity(seeds: &ShareSeeds, index: u32) -> SharePublicKey {
    share::public_key_at(&seeds.kem, &seeds.auth, &seeds.sig, index)
}

fn payload<'a>(name: &'a [u8], hash: &'a [u8]) -> SharePayload<'a> {
    SharePayload {
        item_id: item_id(),
        name_ct: name,
        content_hash_ct: hash,
    }
}

/// One numbered identity: its sub-root, its seeds, and what it publishes.
fn identity_case(share_id_root: &[u8; 32], index: u32) -> Value {
    let seeds = share_seeds_from_root(share_id_root, index).expect("index >= 1");
    let id = identity(&seeds, index);
    let bytes = id.to_bytes();
    let mut case = json!({
        "index": index,
        "label": format!("{INFO_SHARE_ID_PREFIX}{index}"),
        "r_hex": hex::encode(sub_root_independently(share_id_root, index)),
        "kem_seed_hex": hex::encode(*seeds.kem),
        "auth_secret_hex": hex::encode(*seeds.auth),
        "sig_seed_hex": hex::encode(*seeds.sig),
        "derivation_index": id.derivation_index(),
        "key_epoch": id.key_epoch(),
        "root_hex": hex::encode(id.root()),
        "address_hex": hex::encode(id.address().as_bytes()),
        "address_display": id.address().display(),
        "identity_len": bytes.len(),
        "identity_sha256": sha256_hex(&bytes),
    });
    if index == RECIPIENT_INDEX {
        case["identity_hex"] = json!(hex::encode(bytes));
    }
    case
}

/// Build the whole fixture from the shipped entry points.
fn build() -> Value {
    let account = ncf3_account(&ncf3());
    let code_bytes: [u8; 20] =
        hex::decode(account["code_bytes_hex"].as_str().unwrap()).unwrap()[..]
            .try_into()
            .unwrap();
    let keys = kdf::derive_from_bytes(&code_bytes).expect("derivation");
    let zero = keys.share_seeds_for(0);
    let id0 = identity(&zero, 0);

    let sender_root = sender_share_id_root();
    let sender_seeds = share_seeds_from_root(&sender_root, SENDER_INDEX).expect("index >= 1");
    let sender = identity(&sender_seeds, SENDER_INDEX);
    let recipient = identity(&keys.share_seeds_for(RECIPIENT_INDEX), RECIPIENT_INDEX);
    let (name, hash) = (name_ct(), content_hash_ct());
    let row = payload(&name, &hash);
    let envelope = share::wrap_dek_for_as_with_randomness(
        &sender_seeds.auth,
        &sender_seeds.sig,
        SENDER_INDEX,
        &recipient,
        &recipient.address(),
        &dek(),
        &row,
        &EnvelopeRandomness {
            kem_eseed: &eseed(),
            envelope_nonce: &envelope_nonce(),
        },
    )
    .expect("wrap");

    let refusal = |secrets: &ShareSeeds, index: u32, label: &str| {
        let err = share::unwrap_dek_as(
            &secrets.kem,
            &secrets.auth,
            &secrets.sig,
            index,
            &sender,
            &envelope,
            &row,
        )
        .expect_err("must refuse");
        json!({
            "label": label,
            "index": index,
            "kem_seed_hex": hex::encode(*secrets.kem),
            "auth_secret_hex": hex::encode(*secrets.auth),
            "sig_seed_hex": hex::encode(*secrets.sig),
            "expect_error": format!("{err:?}"),
            "refusal_message": err.to_string(),
        })
    };

    json!({
        "format": "NCF-3",
        "section": "5.9",
        "note": "Numbered share identities, an ADDITION to NCF-3 kept out of ncf3.json so that file \
                 never moves. shareIdRoot = HKDF-Expand(PRK, \"nmts/v3/share-id-root\", 32); \
                 R(0) = PRK; R(N) = HKDF-Expand(shareIdRoot, \"nmts/v3/share-id/\" || dec(N), 32) \
                 for N >= 1; the three seeds are the §5.1 labels (share-kem, share-auth, share-sig) \
                 under R(N); identity(N) is the §5.1 bundle with derivation_index = N and \
                 key_epoch = 0. Every HKDF-Expand takes its key as a PRK directly, with no second \
                 Extract.",
        "share_id_root_info": String::from_utf8_lossy(INFO_SHARE_ID_ROOT),
        "share_id_prefix": INFO_SHARE_ID_PREFIX,

        "account": {
            "label": ACCOUNT_LABEL,
            "note": "The ncf3.json `kdf` entry with this label. Its master_hex is the input of the \
                     independent check of share_id_root.",
            "code_bytes_hex": hex::encode(code_bytes),
            "code_display": account["code_display"],
            "share_id_root_hex": hex::encode(*keys.share_id_root),
        },
        "identity_zero": {
            "note": "Identity 0 through the numbered path. Its seeds must equal ncf3.json's \
                     kdf[label].share_kem_seed_hex / share_auth_secret_hex / share_sig_seed_hex, \
                     and the bundle builder at index 0 must reproduce every identity in ncf3.json's \
                     `address` group byte for byte. Both are read from ncf3.json, not re-derived.",
            "kem_seed_hex": hex::encode(*zero.kem),
            "auth_secret_hex": hex::encode(*zero.auth),
            "sig_seed_hex": hex::encode(*zero.sig),
            "derivation_index": 0,
            "root_hex": hex::encode(id0.root()),
            "address_hex": hex::encode(id0.address().as_bytes()),
            "address_display": id0.address().display(),
            "identity_len": SHARE_PUBLIC_LEN,
            "identity_sha256": sha256_hex(&id0.to_bytes()),
        },
        "identities": NUMBERS
            .iter()
            .map(|&n| identity_case(&keys.share_id_root, n))
            .collect::<Vec<_>>(),
        "index_zero": {
            "index": 0,
            "note": "The sub-root function refuses 0: identity 0 is R(0) = PRK, and a second road \
                     to it would be a second value for one published address.",
            "refusal": format!("{:?}", KdfError::ShareIdIndexZero),
            "refusal_message": KdfError::ShareIdIndexZero.to_string(),
        },

        "share": {
            "label": "wrap_to_identity_1",
            "note": "A DEK wrapped to the account's identity 1, sent AS identity 3 of a second \
                     account whose shareIdRoot is the fixed bytes below. The envelope's \
                     sender_address is the sender's identity-3 address; the wrapping key binds the \
                     recipient's identity-1 ROOT, whose first four bytes are the number. Both random \
                     inputs are fixed; production draws both fresh.",
            "sender_share_id_root_hex": hex::encode(sender_root),
            "sender_index": SENDER_INDEX,
            "sender_kem_seed_hex": hex::encode(*sender_seeds.kem),
            "sender_auth_secret_hex": hex::encode(*sender_seeds.auth),
            "sender_sig_seed_hex": hex::encode(*sender_seeds.sig),
            "sender_address_hex": hex::encode(sender.address().as_bytes()),
            "sender_identity_sha256": sha256_hex(&sender.to_bytes()),
            "recipient_index": RECIPIENT_INDEX,
            "recipient_address_hex": hex::encode(recipient.address().as_bytes()),
            "recipient_identity_sha256": sha256_hex(&recipient.to_bytes()),
            "item_id_ascii": String::from_utf8(item_id().to_vec()).unwrap(),
            "name_share_ct_hex": hex::encode(name),
            "content_hash_share_ct_hex": hex::encode(hash),
            "payload_commitment_hex": hex::encode(row.commitment().unwrap()),
            "eseed_hex": hex::encode(eseed()),
            "envelope_nonce_hex": hex::encode(envelope_nonce()),
            "dek_hex": hex::encode(dek()),
            "envelope_hex": hex::encode(&envelope),
            "envelope_len": envelope.len(),
        },
        "share_negative": [
            refusal(&zero, 0, "opened_as_identity_0"),
            refusal(&keys.share_seeds_for(2), 2, "opened_as_identity_2"),
        ],
    })
}

/// Write the fixture. Ignored: it is the regenerator, not a judgement.
#[test]
#[ignore]
fn gen_identity_fixture() {
    let path = fixture_path();
    std::fs::write(&path, format!("{:#}\n", build())).expect("fixture is writable");
    println!("wrote {}", path.display());
}

/// The committed file is exactly what the code produces today.
#[test]
fn identity_fixture_reproducible() {
    let committed = std::fs::read_to_string(fixture_path()).expect("fixture is readable");
    assert_eq!(
        committed,
        format!("{:#}\n", build()),
        "the committed identity fixture no longer matches what the crate produces — a published \
         public code would move. Find the change; do not regenerate past it."
    );
}

/// Every value in the fixture, re-derived through the shipped entry points and an independent
/// HKDF, and identity 0 checked against the frozen artifact.
///
/// ⚠ Deliberately NOT a re-run of `build()`: this walks the committed JSON and asks for each answer.
#[test]
fn identity_fixture_holds() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).expect("readable"))
            .expect("fixture parses");
    let frozen = ncf3();
    let pinned = ncf3_account(&frozen);

    // ── the account and its parent ────────────────────────────────────────────────────────
    let a = &doc["account"];
    assert_eq!(a["label"], ACCOUNT_LABEL);
    assert_eq!(a["code_bytes_hex"], pinned["code_bytes_hex"]);
    let code: [u8; 20] = hex::decode(a["code_bytes_hex"].as_str().unwrap()).unwrap()[..]
        .try_into()
        .unwrap();
    let keys = kdf::derive_from_bytes(&code).expect("derivation");
    let root = hex32(&a["share_id_root_hex"]);
    assert_eq!(*keys.share_id_root, root);
    // Independently: Expand(Extract("", master), "nmts/v3/share-id-root"), master from ncf3.json.
    let master = hex32(&pinned["master_hex"]);
    let mut independent = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b""), &master)
        .expand(b"nmts/v3/share-id-root", &mut independent)
        .expect("expand");
    assert_eq!(independent, root);

    // ── identity 0 against the frozen artifact ────────────────────────────────────────────
    let z = &doc["identity_zero"];
    let zero = keys.share_seeds_for(0);
    for (field, ours, frozen_field) in [
        ("kem_seed_hex", &*zero.kem, "share_kem_seed_hex"),
        ("auth_secret_hex", &*zero.auth, "share_auth_secret_hex"),
        ("sig_seed_hex", &*zero.sig, "share_sig_seed_hex"),
    ] {
        assert_eq!(
            hex::encode(ours),
            pinned[frozen_field].as_str().unwrap(),
            "{field} vs ncf3.json"
        );
        assert_eq!(
            z[field], pinned[frozen_field],
            "{field} in the fixture vs ncf3.json"
        );
    }
    let id0 = identity(&zero, 0);
    assert_eq!(
        hex::encode(id0.address().as_bytes()),
        z["address_hex"].as_str().unwrap()
    );
    assert_eq!(
        sha256_hex(&id0.to_bytes()),
        z["identity_sha256"].as_str().unwrap()
    );
    assert_eq!(hex::encode(id0.root()), z["root_hex"].as_str().unwrap());
    assert_eq!(
        id0.to_bytes(),
        share::public_key(&zero.kem, &zero.auth, &zero.sig).to_bytes()
    );
    assert_eq!(
        share::address_at(&zero.sig, 0),
        share::address_for(&zero.sig)
    );

    let mut judged = 0usize;
    for v in frozen["address"]
        .as_array()
        .expect("ncf3.json address group")
    {
        let id = share::public_key_at(
            &hex32(&v["kem_seed_hex"]),
            &hex32(&v["auth_secret_hex"]),
            &hex32(&v["sig_seed_hex"]),
            0,
        );
        let label = v["label"].as_str().unwrap();
        assert_eq!(
            sha256_hex(&id.to_bytes()),
            v["identity_sha256"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(
            hex::encode(id.root()),
            v["root_hex"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(
            hex::encode(id.address().as_bytes()),
            v["address_hex"].as_str().unwrap()
        );
        assert_eq!(
            id.address().display(),
            v["address_display"].as_str().unwrap()
        );
        if let Some(full) = v["identity_hex"].as_str() {
            assert_eq!(hex::encode(id.to_bytes()), full, "{label}: full bundle");
        }
        judged += 1;
    }
    assert!(judged >= 3, "only {judged} frozen identities compared");

    // ── the numbered identities ───────────────────────────────────────────────────────────
    judged = 0;
    let mut full_bundles = 0usize;
    for v in doc["identities"].as_array().expect("identities") {
        let n = u32::try_from(v["index"].as_u64().unwrap()).unwrap();
        assert!(n >= 1);
        assert_eq!(
            v["label"].as_str().unwrap(),
            format!("nmts/v3/share-id/{n}")
        );
        let r = sub_root_independently(&root, n);
        assert_eq!(hex::encode(r), v["r_hex"].as_str().unwrap(), "R({n})");
        let [kem, auth, sig] = seeds_independently(&r);
        let seeds = share_seeds_from_root(&root, n).expect("index >= 1");
        let via_keys = keys.share_seeds_for(n);
        for (field, independent, ours, ours_too) in [
            ("kem_seed_hex", kem, *seeds.kem, *via_keys.kem),
            ("auth_secret_hex", auth, *seeds.auth, *via_keys.auth),
            ("sig_seed_hex", sig, *seeds.sig, *via_keys.sig),
        ] {
            assert_eq!(
                hex::encode(independent),
                v[field].as_str().unwrap(),
                "{field}({n})"
            );
            assert_eq!(ours, independent, "{field}({n}) from the root");
            assert_eq!(ours_too, independent, "{field}({n}) from the derived keys");
        }
        let id = identity(&seeds, n);
        assert_eq!(id.derivation_index(), n);
        assert_eq!(id.key_epoch(), 0);
        assert_eq!(u64::from(n), v["derivation_index"].as_u64().unwrap());
        assert_eq!(hex::encode(id.root()), v["root_hex"].as_str().unwrap());
        assert_eq!(
            &id.root()[..4],
            &n.to_be_bytes(),
            "the number opens the root"
        );
        assert_eq!(
            hex::encode(id.address().as_bytes()),
            v["address_hex"].as_str().unwrap()
        );
        assert_eq!(
            id.address().display(),
            v["address_display"].as_str().unwrap()
        );
        assert_eq!(share::address_at(&seeds.sig, n), id.address());
        assert_eq!(
            sha256_hex(&id.to_bytes()),
            v["identity_sha256"].as_str().unwrap()
        );
        assert_ne!(
            id.address(),
            id0.address(),
            "identity {n} is not identity 0"
        );
        let parsed = SharePublicKey::from_bytes(&id.to_bytes()).expect("a numbered bundle parses");
        assert_eq!(parsed.address(), id.address());
        if let Some(full) = v["identity_hex"].as_str() {
            assert_eq!(hex::encode(id.to_bytes()), full);
            assert_eq!(full.len(), 2 * SHARE_PUBLIC_LEN);
            full_bundles += 1;
        }
        judged += 1;
    }
    assert_eq!(
        judged,
        NUMBERS.len(),
        "the pinned numbers, no more and no fewer"
    );
    assert_eq!(
        full_bundles, 1,
        "identity 1's bundle is pinned in full, once"
    );

    // ── the refusal of 0 ──────────────────────────────────────────────────────────────────
    let refusal = share_seeds_from_root(&root, 0).expect_err("0 is refused");
    assert_eq!(refusal, KdfError::ShareIdIndexZero);
    assert_eq!(
        refusal.to_string(),
        doc["index_zero"]["refusal_message"].as_str().unwrap()
    );

    // ── the share ─────────────────────────────────────────────────────────────────────────
    let s = &doc["share"];
    let sender_n = u32::try_from(s["sender_index"].as_u64().unwrap()).unwrap();
    let recipient_n = u32::try_from(s["recipient_index"].as_u64().unwrap()).unwrap();
    assert_ne!(sender_n, recipient_n);
    let sender_seeds = share_seeds_from_root(&hex32(&s["sender_share_id_root_hex"]), sender_n)
        .expect("index >= 1");
    assert_eq!(
        hex::encode(*sender_seeds.sig),
        s["sender_sig_seed_hex"].as_str().unwrap()
    );
    let sender = identity(&sender_seeds, sender_n);
    assert_eq!(
        sha256_hex(&sender.to_bytes()),
        s["sender_identity_sha256"].as_str().unwrap()
    );
    let recipient_seeds = keys.share_seeds_for(recipient_n);
    let recipient = identity(&recipient_seeds, recipient_n);
    assert_eq!(
        hex::encode(recipient.address().as_bytes()),
        s["recipient_address_hex"].as_str().unwrap()
    );
    let name = hex::decode(s["name_share_ct_hex"].as_str().unwrap()).unwrap();
    let hash = hex::decode(s["content_hash_share_ct_hex"].as_str().unwrap()).unwrap();
    let row = SharePayload {
        item_id: s["item_id_ascii"].as_str().unwrap().as_bytes(),
        name_ct: &name,
        content_hash_ct: &hash,
    };
    assert_eq!(
        hex::encode(row.commitment().unwrap()),
        s["payload_commitment_hex"].as_str().unwrap()
    );
    let dek = hex32(&s["dek_hex"]);
    let eseed: [u8; KEM_RANDOMNESS_LEN] =
        hex::decode(s["eseed_hex"].as_str().unwrap()).unwrap()[..]
            .try_into()
            .unwrap();
    let nonce: [u8; ENVELOPE_NONCE_LEN] = hex::decode(s["envelope_nonce_hex"].as_str().unwrap())
        .unwrap()[..]
        .try_into()
        .unwrap();
    let envelope = share::wrap_dek_for_as_with_randomness(
        &sender_seeds.auth,
        &sender_seeds.sig,
        sender_n,
        &recipient,
        &recipient.address(),
        &dek,
        &row,
        &EnvelopeRandomness {
            kem_eseed: &eseed,
            envelope_nonce: &nonce,
        },
    )
    .expect("wrap");
    assert_eq!(hex::encode(&envelope), s["envelope_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(share::claimed_sender(&envelope).unwrap().as_bytes()),
        s["sender_address_hex"].as_str().unwrap(),
        "the envelope names the number the sender sent as"
    );
    let opened = share::unwrap_dek_as(
        &recipient_seeds.kem,
        &recipient_seeds.auth,
        &recipient_seeds.sig,
        recipient_n,
        &sender,
        &envelope,
        &row,
    )
    .expect("identity 1 opens it");
    assert_eq!(*opened, dek);

    judged = 0;
    for v in doc["share_negative"].as_array().expect("share_negative") {
        let n = u32::try_from(v["index"].as_u64().unwrap()).unwrap();
        let (kem, auth, sig) = (
            hex32(&v["kem_seed_hex"]),
            hex32(&v["auth_secret_hex"]),
            hex32(&v["sig_seed_hex"]),
        );
        assert_eq!(
            *keys.share_seeds_for(n).sig,
            sig,
            "the secrets are identity {n}'s own"
        );
        let err = share::unwrap_dek_as(&kem, &auth, &sig, n, &sender, &envelope, &row)
            .expect_err("a different number does not open it");
        assert_eq!(err, ShareError::Auth, "refused like any other refusal");
        assert_eq!(err.to_string(), v["refusal_message"].as_str().unwrap());
        judged += 1;
    }
    assert_eq!(judged, 2, "identity 0 and identity 2");
    // The identity-0 door is refused the same way.
    let err = share::unwrap_dek(&zero.kem, &zero.auth, &zero.sig, &sender, &envelope, &row);
    assert_eq!(err.unwrap_err(), ShareError::Auth);
}
