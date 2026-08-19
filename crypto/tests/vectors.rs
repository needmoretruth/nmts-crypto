//! NCF-3 conformance vectors (docs/CRYPTO-FORMAT-NCF3.md §7).
//!
//! This file both GENERATES and VERIFIES `tests/vectors/ncf3.json` — the canonical
//! conformance artifact shared with the standalone recovery tool. Because generation and
//! verification use the deterministic (caller-nonce) constructors, the whole file is gated
//! on the `vectors` feature and does nothing without it.
//!
//! * Regenerate (writes the JSON):
//!   `cargo test --features vectors gen_vectors -- --ignored --nocapture`
//! * Verify (default; reads the committed JSON):
//!   `cargo test --features vectors`
#![cfg(feature = "vectors")]

use nmts_crypto::codes::{AccountCode, VoucherCode};
use nmts_crypto::framing::{
    forge_stream_with_final_flag, verify_part_set, FramingError, Header, StreamDecryptor,
    StreamEncryptor,
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, TAG_LEN,
};
use nmts_crypto::{b64, kdf, manifest, share, wrap};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ----- Fixed inputs (deterministic; documented in the JSON) --------------------------

/// Fixed file DEK for framing/negative vectors: bytes 0x00..0x1F.
fn dek_a() -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = i as u8;
    }
    d
}

/// Fixed stream nonce prefix: bytes 0x20..0x2F.
fn nonce_prefix_a() -> [u8; 16] {
    let mut n = [0u8; 16];
    for (i, b) in n.iter_mut().enumerate() {
        *b = 0x20 + i as u8;
    }
    n
}

/// Fixed envelope key: bytes 0x40..0x5F.
fn env_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    k
}

/// Fixed envelope nonce: bytes 0x60..0x77.
fn env_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    for (i, b) in n.iter_mut().enumerate() {
        *b = 0x60 + i as u8;
    }
    n
}

/// Deterministic plaintext used by every framing vector: `byte[i] = i mod 256`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// A run of `N` bytes starting at `base`, wrapping at 256. Every fixed share input below is one
/// of these, so the JSON says what it is and a foreign implementation can rebuild it by hand.
fn ramp<const N: usize>(base: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = base.wrapping_add(i as u8);
    }
    out
}

/// Nonce prefix for part `index` of a multi-part vector.
///
/// ⚠ Distinct per part on purpose: the parts of one file share a DEK, so two parts drawing the
/// same prefix would repeat chunk nonces under one key — the failure XChaCha20-Poly1305 does not
/// survive. Production draws a fresh random prefix per part; this is its deterministic stand-in.
fn part_nonce_prefix(index: u32) -> [u8; 16] {
    ramp(0x40u8.wrapping_add((index as u8).wrapping_mul(16)))
}

// ----- Fixed share inputs (deterministic; documented in the JSON) --------------------

/// Sender's X-Wing seed: bytes 0x10..0x2F.
fn sender_kem_seed() -> [u8; 32] {
    ramp(0x10)
}
/// Sender's X25519 sender-authentication scalar: bytes 0x30..0x4F.
fn sender_auth_secret() -> [u8; 32] {
    ramp(0x30)
}
/// Recipient's X-Wing seed: bytes 0x50..0x6F.
fn recipient_kem_seed() -> [u8; 32] {
    ramp(0x50)
}
/// Recipient's X25519 sender-authentication scalar: bytes 0x70..0x8F.
fn recipient_auth_secret() -> [u8; 32] {
    ramp(0x70)
}
/// A third party's X-Wing seed: bytes 0x90..0xAF.
fn third_party_kem_seed() -> [u8; 32] {
    ramp(0x90)
}
/// A third party's X25519 sender-authentication scalar: bytes 0xB0..0xCF.
fn third_party_auth_secret() -> [u8; 32] {
    ramp(0xB0)
}
/// Sender's ML-DSA-44 signing seed: bytes 0x02..0x21. Its verification key IS the sender's
/// identity root, so this value alone decides the sender's address (NCF-3 §5.2a).
fn sender_sig_seed() -> [u8; 32] {
    ramp(0x02)
}
/// Recipient's ML-DSA-44 signing seed: bytes 0x04..0x23.
fn recipient_sig_seed() -> [u8; 32] {
    ramp(0x04)
}
/// A third party's ML-DSA-44 signing seed: bytes 0x06..0x25.
fn third_party_sig_seed() -> [u8; 32] {
    ramp(0x06)
}
/// Fixed X-Wing encapsulation randomness (`eseed`): bytes 0xD0.. wrapping at 256.
fn share_eseed() -> [u8; share::KEM_RANDOMNESS_LEN] {
    ramp(0xD0)
}
/// Fixed nonce for the sealed DEK at the tail of a share envelope: bytes 0x1A..0x31.
///
/// An envelope has TWO random inputs, not one; pinning only `eseed` would leave these last
/// 104 bytes unreproducible.
fn share_envelope_nonce() -> [u8; wrap::ENVELOPE_NONCE_LEN] {
    ramp(0x1A)
}
/// The DEK a share vector carries: bytes 0xE0..0xFF.
fn shared_dek() -> [u8; 32] {
    ramp(0xE0)
}

/// The row a share vector's envelope belongs beside (NCF-3 §5.3, defect A6).
///
/// The two ciphertexts are stand-ins rather than real sealed values: the commitment is over
/// opaque bytes, so an implementation can reproduce these vectors without first implementing
/// name sealing. Their LENGTHS differ on purpose — that is what the length prefixes exist for.
fn share_item_id() -> &'static [u8] {
    b"6a0f2b1c-1111-4222-8333-444455556666"
}
fn share_name_ct() -> [u8; 61] {
    ramp(0x40)
}
fn share_content_hash_ct() -> [u8; 104] {
    ramp(0x80)
}

/// The share identity for a (kem seed, auth secret, signing seed) triple.
fn identity(kem: &[u8; 32], auth: &[u8; 32], sig: &[u8; 32]) -> share::SharePublicKey {
    share::public_key(kem, auth, sig)
}

// ----- X-Wing published draft vector 0 -----------------------------------------------
//
// draft-connolly-cfrg-xwing-kem, `spec/test-vectors.json`, first entry.
//
// ⚠ These are transcribed from UPSTREAM and are the anchor of the whole `xwing` group. Without
// them the vector would be circular: the generator would write whatever our KEM produced and the
// verifier would compare our KEM against that, so a drift would rewrite the fixture and still
// pass. `pk` and `ct` are pinned by SHA-256 rather than in full — 4.7 KB of hex in the source
// buys nothing over a digest when the fault being caught is accidental drift, and the full bytes
// are committed in the JSON anyway.

/// Draft `seed` (32 bytes) — the X-Wing decapsulation-key seed.
const XWING_SEED: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
/// Draft `eseed` (64 bytes) — the encapsulation randomness.
const XWING_ESEED: &str = "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
                           35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2";
/// Draft `ss` (32 bytes) — the shared secret. Not directly observable through our API (it is HKDF
/// input, never output), so it is carried for reference and checked transitively.
const XWING_SS: &str = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";
/// SHA-256 of the draft's `pk` (1216 bytes).
const XWING_PK_SHA256: &str = "2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb";
/// SHA-256 of the draft's `ct` (1120 bytes).
const XWING_CT_SHA256: &str = "17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33";

// ----- NIST ACVP known-answer vectors for ML-DSA-44 (§7.6) ---------------------------
//
// From the ACVP `ML-DSA keyGen` sample set (`vsId 42`, group `ML-DSA-44`, test cases 1–3), the
// same set the `ml-dsa` crate's own `tests/key-gen.rs` runs and which upstream excludes from the
// published `.crate` for size. They are the anchor for the operation this format leans on hardest:
// a 32-byte seed expanded into a verification key, which is what makes a share address
// reproducible from an account code alone.
//
// ⚠ The seeds are transcribed in full and the verification keys as SHA-256, for the same reason
// as X-Wing above: the generator derives each key from the seed, refuses to write the file unless
// the digest matches NIST's, and the full key bytes go into the JSON. So a drift in our
// implementation cannot rewrite its own fixture — it fails at the digest.
const ACVP_ML_DSA_44_KEYGEN: [(u32, &str, &str); 3] = [
    (
        1,
        "93ef2e6ef1fb08999d142abe0295482370d3f43bdb254a78e2b0d5168eca065f",
        "6995b20ecd5cde41719035028a712ccf35b1adf53b913030423d9d6fa188d673",
    ),
    (
        2,
        "d6a5d2325b94ca1b993a0151e24ab95b396f415831dc14a08404820ae58a2ad1",
        "51bced8954e17da402e93fc5275f723aed1b9101bdf4fac5afc2b5c227d9e674",
    ),
    (
        3,
        "8a5e79b82dc81553bbe821ee367f0adfa54f59a3e8a71ca626f873f638636dd7",
        "190ba0b968c4fc62435a5269c72a81bfdcfa1531f95abed1c03be42733c9620d",
    ),
];

/// The two messages the deterministic signature vectors sign, and the context each uses.
///
/// One with the empty context (FIPS 204's default, and what a bare `Signer` call produces) and one
/// with the identity-bundle context this format actually uses, because a context is folded into
/// the message representative — pinning only the empty one would leave the value we ship unpinned.
const ACVP_SIG_MESSAGES: [(&str, &[u8], &[u8]); 2] = [
    ("empty_context", b"NMTS ML-DSA-44 deterministic signing vector", b""),
    (
        "identity_bundle_context",
        b"NMTS ML-DSA-44 deterministic signing vector",
        share::SIG_CTX_IDENTITY_BUNDLE,
    ),
];

/// The ML-DSA-44 verification key for a 32-byte seed, and a deterministic signature under it.
///
/// ⚠ Every call here goes through `fips204` — the INDEPENDENT implementation — not through
/// `ml-dsa`. That is the whole point: it is what the generator and the verifier compare our bytes
/// against, so an ml-dsa drift shows up as a disagreement rather than as a quietly rewritten
/// fixture. `fips204` is a dev-dependency and ships in nothing.
fn fips204_key_and_signature(seed: &[u8; 32], message: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use fips204::traits::{KeyGen as _, SerDes as _, Signer as _};
    let (vk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(seed);
    // FIPS 204's deterministic variant is exactly `rnd = 0^32`; this entry point takes that value
    // explicitly, where `ml-dsa` spells the same thing `sign_deterministic`.
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], message, ctx)
        .expect("deterministic signature");
    (vk.into_bytes().to_vec(), sig.to_vec())
}

/// Our own ML-DSA-44 verification key and deterministic signature, through the shipping crate.
fn our_key_and_signature(seed: &[u8; 32], message: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let signing_key =
        ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&ml_dsa::Seed::from(*seed));
    let vk = signing_key.verifying_key().encode().to_vec();
    let sig = signing_key
        .sign_deterministic(message, ctx)
        .expect("context is at most 255 bytes")
        .encode()
        .to_vec();
    (vk, sig)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("ncf3.json")
}

// ----- Framing helpers ---------------------------------------------------------------

/// Encrypts a full stream deterministically at the given chunk size (vectors only).
fn encrypt_fixed(dek: &[u8; 32], nonce_prefix: [u8; 16], log2: u8, plaintext: &[u8]) -> Vec<u8> {
    let mut enc = StreamEncryptor::with_fixed(dek, plaintext.len() as u64, nonce_prefix, log2);
    let mut stream = Vec::new();
    stream.extend_from_slice(enc.header());
    stream.extend_from_slice(&enc.push(plaintext).unwrap());
    stream.extend_from_slice(&enc.finish().unwrap());
    stream
}

/// The five positive framing sizes (label, plaintext_len).
fn framing_sizes() -> Vec<(&'static str, usize)> {
    let mib4 = 4 * 1024 * 1024;
    vec![
        ("empty_0B", 0),
        ("one_byte", 1),
        ("exact_4MiB", mib4),
        ("4MiB_plus_1", mib4 + 1),
        ("three_chunk_9MiB", 9 * 1024 * 1024),
    ]
}

// =====================================================================================
// GENERATION
// =====================================================================================

#[test]
#[ignore = "run explicitly to (re)generate tests/vectors/ncf3.json"]
fn gen_vectors() {
    let mut root = serde_json::Map::new();
    root.insert("format".into(), json!("NCF-3"));
    root.insert(
        "note".into(),
        json!(
            "Conformance vectors for the NCF-3 format (see docs/CRYPTO-FORMAT-NCF3.md). \
             Framing plaintext is byte[i] = i mod 256. All hex is lowercase. Deterministic \
             DEK/nonce values are vector-only; production never accepts caller nonces."
        ),
    );

    // --- KDF vectors ------------------------------------------------------------------
    root.insert("kdf".into(), Value::Array(gen_kdf_vectors()));

    // --- Voucher encoding vector ------------------------------------------------------
    root.insert("voucher".into(), Value::Array(gen_voucher_vectors()));

    // --- Envelope vectors -------------------------------------------------------------
    root.insert("envelope".into(), Value::Array(gen_envelope_vectors()));

    // --- Negative envelope vectors (§7.2) ---------------------------------------------
    root.insert(
        "envelope_negative".into(),
        Value::Array(gen_envelope_negative()),
    );

    // --- Framing digests --------------------------------------------------------------
    root.insert("framing".into(), Value::Array(gen_framing_vectors()));

    // --- Multi-part header sets (§7.3) ------------------------------------------------
    root.insert("framing_parts".into(), Value::Array(gen_part_vectors()));

    // --- Negative framing vectors -----------------------------------------------------
    root.insert(
        "framing_negative".into(),
        Value::Array(gen_negative_vectors()),
    );

    // --- X-Wing conformance (§7.4, first half) ----------------------------------------
    root.insert("xwing".into(), Value::Array(gen_xwing_vectors()));

    // --- Private sharing (§7.4) -------------------------------------------------------
    root.insert("share".into(), Value::Array(gen_share_vectors()));

    // --- Negative share vectors -------------------------------------------------------
    root.insert("share_negative".into(), Value::Array(gen_share_negative()));

    // --- Share addresses (§7.5) -------------------------------------------------------
    root.insert("address".into(), Value::Array(gen_address_vectors()));

    // --- ML-DSA-44 conformance (§7.6) -------------------------------------------------
    root.insert("mldsa".into(), Value::Array(gen_mldsa_vectors()));

    let json = serde_json::to_string_pretty(&Value::Object(root)).unwrap();
    let path = vectors_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, json + "\n").unwrap();
    eprintln!("wrote {}", path.display());
}

/// The three KDF codes: all-zero, a fixed pattern, and a check-symbol edge case.
fn kdf_code_bytes() -> Vec<(&'static str, [u8; 20])> {
    // all-zero (check symbol '0')
    let zero = [0u8; 20];

    // fixed pattern
    let mut pat = [0u8; 20];
    for (i, b) in pat.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(3);
    }

    // check-symbol edge case: choose the last byte so the Crockford check value is 36 ('U').
    let mut edge = [0x11u8; 20];
    for last in 0u16..=255 {
        edge[19] = last as u8;
        let mut acc: u32 = 0;
        for &b in &edge {
            acc = (acc * 256 + b as u32) % 37;
        }
        if acc == 36 {
            break;
        }
    }

    vec![
        ("all_zero", zero),
        ("fixed_pattern", pat),
        ("extended_check_symbol_U", edge),
    ]
}

fn gen_kdf_vectors() -> Vec<Value> {
    kdf_code_bytes()
        .into_iter()
        .map(|(label, bytes)| {
            let code = AccountCode::from_bytes(bytes);
            let keys = kdf::derive_from_bytes(&bytes).unwrap();
            // Recompute master separately for the vector (derive() does not expose it).
            let master = derive_master(&bytes);
            json!({
                "label": label,
                "note": "Every output of the NCF-3 account-code chain (§1). `wallet_seed_hex` is \
                         wallet 0 under its historical key name — the JS conformance harnesses \
                         read that exact spelling — and `wallet_seed_1_hex` / `wallet_seed_10_hex` \
                         cover the decimal-label rule (wallet 10 is not wallet 1 with a zero). \
                         `recovery_patch_name` is not a key: it is the public name the recovery \
                         manifest is stored under inside a quilt (§2.3), pinned here because the \
                         browser and the standalone recovery tool must compute the same one or a \
                         recovery finds nothing.",
                "code_display": code.display(),
                "code_canonical": code.canonical(),
                "code_bytes_hex": hex::encode(bytes),
                "master_hex": hex::encode(master),
                "account_id_hex": hex::encode(keys.account_id),
                "account_id_b64": keys.account_id_b64(),
                "auth_secret_hex": hex::encode(*keys.auth_secret),
                "data_key_hex": hex::encode(*keys.data_key),
                "file_list_key_hex": hex::encode(*keys.file_list_key),
                "share_kem_seed_hex": hex::encode(*keys.share_kem_seed),
                "share_auth_secret_hex": hex::encode(*keys.share_auth_secret),
                "share_sig_seed_hex": hex::encode(*keys.share_sig_seed),
                "wallet_root_hex": hex::encode(*keys.wallet_root),
                "wallet_seed_hex": hex::encode(*keys.wallet_seed_for(0)),
                "wallet_seed_1_hex": hex::encode(*keys.wallet_seed_for(1)),
                "wallet_seed_10_hex": hex::encode(*keys.wallet_seed_for(10)),
                "recovery_patch_name": manifest::recovery_patch_name(&keys.data_key),
            })
        })
        .collect()
}

/// Recomputes just the Argon2id master for the vector file (mirrors kdf.rs constants).
fn derive_master(code_bytes: &[u8; 20]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(
        kdf::ARGON2_M_COST,
        kdf::ARGON2_T_COST,
        kdf::ARGON2_P_COST,
        Some(kdf::MASTER_LEN),
    )
    .unwrap();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = [0u8; 32];
    argon
        .hash_password_into(code_bytes, kdf::ARGON2_SALT, &mut master)
        .unwrap();
    master
}

fn gen_voucher_vectors() -> Vec<Value> {
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(29).wrapping_add(7);
    }
    let v = VoucherCode::from_bytes(bytes);
    vec![json!({
        "label": "fixed_pattern",
        "code_bytes_hex": hex::encode(bytes),
        "code_display": v.display(),
        "code_canonical": v.canonical(),
        "code_hash_hex": hex::encode(v.code_hash()),
    })]
}

fn gen_envelope_vectors() -> Vec<Value> {
    let key = env_key();
    let nonce = env_nonce();

    // dek-wrap: wrap a fixed 32-byte DEK.
    let dek = dek_a();
    let dek_env = wrap::seal_with_nonce(&key, &nonce, wrap::AAD_DEK_WRAP, &dek);

    // name: encrypt a UTF-8 name (incl. multi-byte to lock UTF-8 handling).
    let name = "다국어 файл 📁.txt";
    let name_env = wrap::seal_with_nonce(&key, &nonce, wrap::AAD_NAME, name.as_bytes());

    vec![
        json!({
            "label": "dek_wrap",
            "note": "Envelope layout is nonce(24) || commitment(32) || ciphertext+tag. The \
                     commitment binds the envelope to one key, so a single ciphertext cannot be \
                     built to open under two keys into two plaintexts; it is checked FIRST and in \
                     constant time, and `commitment_hex` is the slice at bytes 24..56.",
            "key_hex": hex::encode(key),
            "aad": String::from_utf8(wrap::AAD_DEK_WRAP.to_vec()).unwrap(),
            "nonce_hex": hex::encode(nonce),
            "commitment_hex": hex::encode(wrap::commitment(&key, &nonce, wrap::AAD_DEK_WRAP)),
            "plaintext_hex": hex::encode(dek),
            "envelope_hex": hex::encode(&dek_env),
            "envelope_len": dek_env.len(),
        }),
        json!({
            "label": "name",
            "note": "A UTF-8 file name under the same key but a different AAD, so an envelope of \
                     one kind cannot be opened as another. The multi-byte characters are there to \
                     pin UTF-8 handling rather than a byte count.",
            "key_hex": hex::encode(key),
            "aad": String::from_utf8(wrap::AAD_NAME.to_vec()).unwrap(),
            "nonce_hex": hex::encode(nonce),
            "commitment_hex": hex::encode(wrap::commitment(&key, &nonce, wrap::AAD_NAME)),
            "plaintext_utf8": name,
            "plaintext_hex": hex::encode(name.as_bytes()),
            "envelope_hex": hex::encode(&name_env),
        }),
    ]
}

/// §7.2 negative: an envelope whose key commitment has been altered must not open.
fn gen_envelope_negative() -> Vec<Value> {
    let key = env_key();
    let nonce = env_nonce();
    let dek = dek_a();
    let mut env = wrap::seal_with_nonce(&key, &nonce, wrap::AAD_DEK_WRAP, &dek);
    // Flip a bit inside the commitment field (bytes 24..56).
    env[wrap::ENVELOPE_NONCE_LEN] ^= 0x01;

    vec![json!({
        "type": "altered_commitment",
        "description": "one bit flipped in the envelope's key-commitment field",
        "note": "The commitment is verified before the AEAD tag, so this is refused by the \
                 commitment check rather than by Poly1305 — and it returns the same error a bad \
                 tag gives, because an attacker who could tell 'wrong key' from 'tampered bytes' \
                 would learn which half of a guess was right.",
        "key_hex": hex::encode(key),
        "aad": String::from_utf8(wrap::AAD_DEK_WRAP.to_vec()).unwrap(),
        "envelope_hex": hex::encode(&env),
        "expect": "fail",
    })]
}

fn gen_framing_vectors() -> Vec<Value> {
    let dek = dek_a();
    let np = nonce_prefix_a();
    framing_sizes()
        .into_iter()
        .map(|(label, len)| {
            let pt = pattern(len);
            let stream = encrypt_fixed(&dek, np, DEFAULT_CHUNK_SIZE_LOG2, &pt);
            let mut obj = serde_json::Map::new();
            obj.insert("label".into(), json!(label));
            obj.insert("plaintext_len".into(), json!(len));
            obj.insert("dek_hex".into(), json!(hex::encode(dek)));
            obj.insert("nonce_prefix_hex".into(), json!(hex::encode(np)));
            obj.insert("chunk_size_log2".into(), json!(DEFAULT_CHUNK_SIZE_LOG2));
            obj.insert("plaintext_pattern".into(), json!("byte[i]=i%256"));
            obj.insert("stream_len".into(), json!(stream.len()));
            obj.insert("stream_sha256".into(), json!(sha256_hex(&stream)));
            // Include full bytes for the tiny streams (decoder self-test convenience).
            if len <= 1 {
                obj.insert("stream_hex".into(), json!(hex::encode(&stream)));
            }
            Value::Object(obj)
        })
        .collect()
}

/// §7.3 multi-part: a complete 3-part set, each part its own stream under ONE DEK.
///
/// Before NCF-3 nothing in a part's header said which part it was, so the server could serve part
/// 2 where part 1 belonged and every chunk still authenticated. The counters are in the header and
/// the header is in every chunk's AAD, so the set is now checkable — and a MISSING part is
/// invisible to the AEAD (bytes never handed over are never checked), which is why
/// `verify_part_set` has to count them separately.
fn gen_part_vectors() -> Vec<Value> {
    let dek = dek_a();
    let total = 3u32;
    let bodies: [&[u8]; 3] = [b"first part", b"second part", b"third and last part"];

    let parts: Vec<Value> = (0..total)
        .map(|index| {
            let body = bodies[index as usize];
            let stream = encrypt_part(&dek, index, total, body);
            json!({
                "part_index": index,
                "part_total": total,
                "plaintext_utf8": String::from_utf8(body.to_vec()).unwrap(),
                "plaintext_hex": hex::encode(body),
                "nonce_prefix_hex": hex::encode(part_nonce_prefix(index)),
                "header_hex": hex::encode(&stream[..HEADER_LEN]),
                "stream_len": stream.len(),
                "stream_hex": hex::encode(&stream),
            })
        })
        .collect();

    vec![json!({
        "label": "three_part_file",
        "note": "One file split into 3 parts under a single DEK (§7.3). Each part is a complete \
                 stream whose header carries part_index/part_total; the whole header is AAD for \
                 every chunk, so a part decrypted in the wrong position fails to authenticate. \
                 A conforming reader must ALSO count the set — see framing_negative/\
                 swapped_part_index for the tamper case, and note that an omitted part cannot be \
                 caught by the AEAD at all.",
        "dek_hex": hex::encode(dek),
        "chunk_size_log2": DEFAULT_CHUNK_SIZE_LOG2,
        "part_total": total,
        "verify_part_set": "ok",
        "parts": parts,
    })]
}

/// One part of a multi-part file, encrypted deterministically.
fn encrypt_part(dek: &[u8; 32], index: u32, total: u32, body: &[u8]) -> Vec<u8> {
    let mut enc = StreamEncryptor::new_part_with_nonce_prefix(
        dek,
        body.len() as u64,
        index,
        total,
        part_nonce_prefix(index),
        DEFAULT_CHUNK_SIZE_LOG2,
    );
    let mut out = enc.header().to_vec();
    out.extend_from_slice(&enc.push(body).unwrap());
    out.extend_from_slice(&enc.finish().unwrap());
    out
}

/// §7.4 first half: X-Wing's own published draft vectors, exercised through OUR call sites.
///
/// The `x-wing` crate asserts the full published set itself — 3 vectors in its `tests/kats.rs`
/// against `tests/test-vectors.json`, taken from the draft's spec repository — but those run when
/// the DEPENDENCY is tested, never when NMTS is. Re-checking one of them here is what catches a
/// vendored or semver-compatible x-wing whose behaviour moved, and it does so through the exact
/// two calls `share.rs` makes: seed → encapsulation key, and (key, eseed) → ciphertext.
///
/// Only the first vector is committed. Duplicating all three would restate upstream's file
/// without testing anything more of ours; the value here is the call path, not the count.
fn gen_xwing_vectors() -> Vec<Value> {
    let seed: [u8; 32] = hex::decode(XWING_SEED).unwrap().try_into().unwrap();
    let eseed: [u8; share::KEM_RANDOMNESS_LEN] =
        hex::decode(XWING_ESEED).unwrap().try_into().unwrap();

    // The draft's `pk` is the X-Wing key alone. Since §5.2a an NMTS identity carries it in the
    // middle of the bundle, after the version byte, the root and the epoch, so the draft value is
    // the 1216-byte window ending 32 bytes before the signature.
    let auth = ramp::<32>(0x01);
    let sig = ramp::<32>(0x03);
    let id = identity(&seed, &auth, &sig);
    let kem_at =
        share::SHARE_SIGNED_LEN - share::SHARE_AUTH_PUBLIC_LEN - share::SHARE_KEM_PUBLIC_LEN;
    let identity_bytes = id.to_bytes();
    let kem_pk = &identity_bytes[kem_at..kem_at + share::SHARE_KEM_PUBLIC_LEN];
    assert_eq!(
        sha256_hex(kem_pk),
        XWING_PK_SHA256,
        "X-Wing key generation no longer matches the published draft vector — refusing to write a \
         fixture that would make the drift look correct"
    );

    // The ciphertext the draft expects, produced by wrapping to this key with the draft's eseed.
    let name_ct = share_name_ct();
    let hash_ct = share_content_hash_ct();
    let payload = share::SharePayload {
        item_id: share_item_id(),
        name_ct: &name_ct,
        content_hash_ct: &hash_ct,
    };
    let envelope = share::wrap_dek_for_with_randomness(
        &sender_kem_seed(),
        &sender_auth_secret(),
        &id,
        &id.address(),
        &shared_dek(),
        &payload,
        &share::EnvelopeRandomness {
            kem_eseed: &eseed,
            envelope_nonce: &share_envelope_nonce(),
        },
    )
    .unwrap();
    let ct =
        &envelope[share::SHARE_ADDRESS_LEN..share::SHARE_ADDRESS_LEN + share::KEM_CIPHERTEXT_LEN];
    assert_eq!(
        sha256_hex(ct),
        XWING_CT_SHA256,
        "X-Wing encapsulation no longer matches the published draft vector — refusing to write a \
         fixture that would make the drift look correct"
    );

    vec![json!({
        "label": "draft_vector_0",
        "note": "X-Wing published draft vector 0 (draft-connolly-cfrg-xwing-kem, \
                 spec/test-vectors.json), re-derived through nmts_crypto::share. `pk_hex` must \
                 equal the draft's `pk`, and `ct_hex` the draft's `ct` for that `eseed`. The \
                 draft's shared secret is not directly observable here — it is HKDF input, never \
                 output — so it is pinned as `ss_hex` for reference and verified transitively: a \
                 different ss gives a different wrapping key and the envelope stops opening.",
        "source": "https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/main/spec/test-vectors.json",
        "also_asserted_in": "x-wing crate, tests/kats.rs (all 3 vectors, upstream test run only)",
        "seed_hex": XWING_SEED,
        "eseed_hex": XWING_ESEED,
        "ss_hex": XWING_SS,
        "pk_hex": hex::encode(kem_pk),
        "pk_sha256": XWING_PK_SHA256,
        "pk_len": kem_pk.len(),
        "ct_hex": hex::encode(ct),
        "ct_sha256": XWING_CT_SHA256,
        "ct_len": ct.len(),
    })]
}

/// §7.4: a full wrap/unwrap from fixed seeds with fixed encapsulation randomness.
fn gen_share_vectors() -> Vec<Value> {
    let sender = identity(&sender_kem_seed(), &sender_auth_secret(), &sender_sig_seed());
    let recipient = identity(
        &recipient_kem_seed(),
        &recipient_auth_secret(),
        &recipient_sig_seed(),
    );
    let dek = shared_dek();

    let name_ct = share_name_ct();
    let hash_ct = share_content_hash_ct();
    let payload = share::SharePayload {
        item_id: share_item_id(),
        name_ct: &name_ct,
        content_hash_ct: &hash_ct,
    };
    let envelope = share::wrap_dek_for_with_randomness(
        &sender_auth_secret(),
        &sender_sig_seed(),
        &recipient,
        &recipient.address(),
        &dek,
        &payload,
        &share::EnvelopeRandomness {
            kem_eseed: &share_eseed(),
            envelope_nonce: &share_envelope_nonce(),
        },
    )
    .unwrap();

    vec![json!({
        "label": "wrap_dek_for_recipient",
        "note": "A DEK wrapped from the sender identity to the recipient identity (§5). \
                 Envelope layout is sender_address(16) || ct_kem(1120) || sealed_dek(104) = 1240. \
                 Both random inputs are fixed here so the bytes are reproducible; production draws \
                 both fresh, so two real envelopes to one recipient never repeat. Identities are \
                 pinned by digest because they are reproducible from the seeds — the recipient's \
                 full bytes are in the `address` group for an implementation that wants to check \
                 the fingerprint step without first implementing X-Wing key generation. \
                 ⚠ The wrapping key binds the recipient's ROOT, not the whole bundle (§5.3, \
                 revised 2026-08-02), which is why `recipient_root_hex` is pinned here as well: \
                 an implementation that hashed the full identity into the HKDF info fails on a \
                 value it can see rather than on 1240 opaque bytes.",
        "sender_kem_seed_hex": hex::encode(sender_kem_seed()),
        "sender_auth_secret_hex": hex::encode(sender_auth_secret()),
        "sender_sig_seed_hex": hex::encode(sender_sig_seed()),
        "sender_identity_sha256": sha256_hex(&sender.to_bytes()),
        "sender_address_hex": hex::encode(sender.address().as_bytes()),
        "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
        "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
        "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
        "recipient_identity_sha256": sha256_hex(&recipient.to_bytes()),
        "recipient_root_hex": hex::encode(recipient.root()),
        "recipient_root_len": share::SHARE_ROOT_LEN,
        "recipient_address_hex": hex::encode(recipient.address().as_bytes()),
        "identity_len": share::SHARE_PUBLIC_LEN,
        "item_id_ascii": String::from_utf8(share_item_id().to_vec()).unwrap(),
        "name_share_ct_hex": hex::encode(name_ct),
        "content_hash_share_ct_hex": hex::encode(hash_ct),
        "payload_commitment_hex": hex::encode(payload.commitment().unwrap()),
        "payload_note": "The three columns stored beside the envelope are hashed into the \
                         wrapping key's HKDF info (§5.3, defect A6), so these bytes are part of \
                         the input, not decoration: change any of them and the envelope below \
                         stops opening. commitment = SHA-256(\"nmts/v3/share-payload\" || \
                         u32be(len)||item_id || u32be(len)||name_ct || u32be(len)||hash_ct). The \
                         two ciphertexts are opaque stand-ins with deliberately different \
                         lengths — the length prefixes are what stop two different rows hashing \
                         alike.",
        "eseed_hex": hex::encode(share_eseed()),
        "envelope_nonce_hex": hex::encode(share_envelope_nonce()),
        "dek_hex": hex::encode(dek),
        "aad": String::from_utf8(share::AAD_SHARE_WRAP.to_vec()).unwrap(),
        "envelope_hex": hex::encode(&envelope),
        "envelope_len": envelope.len(),
    })]
}

/// §7.4 negatives: the seven ways a share must refuse.
///
/// Five are about the ENVELOPE and two, since 2026-08-02, about the IDENTITY itself — a bundle
/// whose self-signature was altered, and a genuine bundle fetched by an address its root does not
/// hash to. The `stage` field says which, because they are refused at different moments and a
/// reader that ran them all through the envelope path would be testing the wrong thing.
fn gen_share_negative() -> Vec<Value> {
    let sender = identity(&sender_kem_seed(), &sender_auth_secret(), &sender_sig_seed());
    let recipient = identity(
        &recipient_kem_seed(),
        &recipient_auth_secret(),
        &recipient_sig_seed(),
    );
    let third = identity(
        &third_party_kem_seed(),
        &third_party_auth_secret(),
        &third_party_sig_seed(),
    );
    let dek = shared_dek();

    let name_ct = share_name_ct();
    let hash_ct = share_content_hash_ct();
    let payload = share::SharePayload {
        item_id: share_item_id(),
        name_ct: &name_ct,
        content_hash_ct: &hash_ct,
    };
    let envelope = share::wrap_dek_for_with_randomness(
        &sender_auth_secret(),
        &sender_sig_seed(),
        &recipient,
        &recipient.address(),
        &dek,
        &payload,
        &share::EnvelopeRandomness {
            kem_eseed: &share_eseed(),
            envelope_nonce: &share_envelope_nonce(),
        },
    )
    .unwrap();

    // Restamped: the claimed sender address rewritten to the third party's, so it passes the
    // fingerprint check against the third party's identity and must still fail to open.
    let mut restamped = envelope.clone();
    restamped[..share::SHARE_ADDRESS_LEN].copy_from_slice(third.address().as_bytes());

    // The A6 cases: the envelope is Alice's, untouched, and only the row beside it is rewritten.
    // A colluding co-recipient can produce all three — they hold the DEK, so they can seal any
    // name or digest under it. The envelope must stop opening anyway.
    let mut swapped_name = name_ct;
    swapped_name[0] ^= 0x01;
    let mut swapped_hash = hash_ct;
    swapped_hash[103] ^= 0x80;
    let other_item_id = b"6a0f2b1c-1111-4222-8333-444455556667";

    let row = |item_id: &[u8], name: &[u8], hash: &[u8]| {
        (
            String::from_utf8(item_id.to_vec()).unwrap(),
            hex::encode(name),
            hex::encode(hash),
        )
    };
    let (id_ok, name_ok, hash_ok) = row(share_item_id(), &name_ct, &hash_ct);

    // One flipped bit at the first byte of the self-signature. Deliberately the signature and not
    // a key: flipping a key would also be caught, but this is the case that isolates the
    // signature check from every other check in the parser.
    let mut bad_signature_identity = recipient.to_bytes();
    bad_signature_identity[share::SHARE_SIGNED_LEN] ^= 0x01;

    vec![
        json!({
            "type": "wrong_sender_identity",
            "stage": "envelope",
            "description": "unwrapped with a third party's identity instead of the sender's",
            "note": "Refused at the fingerprint check: the identity supplied does not hash to the \
                     address the envelope claims.",
            "expect_error": "AddressMismatch",
            "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
            "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
            "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
            "sender_identity_kem_seed_hex": hex::encode(third_party_kem_seed()),
            "sender_identity_auth_secret_hex": hex::encode(third_party_auth_secret()),
            "sender_identity_sig_seed_hex": hex::encode(third_party_sig_seed()),
            "item_id_ascii": id_ok,
            "name_share_ct_hex": name_ok,
            "content_hash_share_ct_hex": hash_ok,
            "envelope_hex": hex::encode(&envelope),
            "expect": "fail",
        }),
        json!({
            "type": "restamped_sender_address",
            "stage": "envelope",
            "description": "sender address rewritten to a third party, who is then supplied as the sender",
            "note": "This one PASSES the fingerprint check — the claim and the identity agree — \
                     and must still fail, because the sender address is bound into the HKDF info \
                     and the static-static agreement is with the wrong party. That is what makes \
                     the 16 bytes self-authenticating rather than a label.",
            "expect_error": "Auth",
            "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
            "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
            "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
            "sender_identity_kem_seed_hex": hex::encode(third_party_kem_seed()),
            "sender_identity_auth_secret_hex": hex::encode(third_party_auth_secret()),
            "sender_identity_sig_seed_hex": hex::encode(third_party_sig_seed()),
            "original_sender_address_hex": hex::encode(sender.address().as_bytes()),
            "item_id_ascii": id_ok,
            "name_share_ct_hex": name_ok,
            "content_hash_share_ct_hex": hash_ok,
            "envelope_hex": hex::encode(&restamped),
            "expect": "fail",
        }),
        json!({
            "type": "swapped_name_ct",
            "stage": "envelope",
            "description": "genuine envelope from the genuine sender, stored beside a different sealed name",
            "note": "Defect A6. The envelope, the sender and the recipient are all correct and the \
                     sealed name is one a co-recipient could legitimately produce — they hold the \
                     same DEK. It must still fail, because the row is hashed into the wrapping \
                     key. Before this binding existed the share opened and the recipient saw an \
                     attacker-chosen file attributed to a verified sender.",
            "expect_error": "Auth",
            "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
            "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
            "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
            "sender_identity_kem_seed_hex": hex::encode(sender_kem_seed()),
            "sender_identity_auth_secret_hex": hex::encode(sender_auth_secret()),
            "sender_identity_sig_seed_hex": hex::encode(sender_sig_seed()),
            "item_id_ascii": id_ok,
            "name_share_ct_hex": hex::encode(swapped_name),
            "content_hash_share_ct_hex": hash_ok,
            "envelope_hex": hex::encode(&envelope),
            "expect": "fail",
        }),
        json!({
            "type": "swapped_content_hash_ct",
            "stage": "envelope",
            "description": "genuine envelope, stored beside a different sealed content digest",
            "note": "Defect A6. Swapping the digest is what would otherwise let a substituted body \
                     pass the download check as well, so this is the half that matters most.",
            "expect_error": "Auth",
            "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
            "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
            "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
            "sender_identity_kem_seed_hex": hex::encode(sender_kem_seed()),
            "sender_identity_auth_secret_hex": hex::encode(sender_auth_secret()),
            "sender_identity_sig_seed_hex": hex::encode(sender_sig_seed()),
            "item_id_ascii": id_ok,
            "name_share_ct_hex": name_ok,
            "content_hash_share_ct_hex": hex::encode(swapped_hash),
            "envelope_hex": hex::encode(&envelope),
            "expect": "fail",
        }),
        json!({
            "type": "repointed_item_id",
            "stage": "envelope",
            "description": "genuine envelope and columns, re-pointed at a different item",
            "note": "Defect A6. One character of the item id differs. Catching it here is what \
                     turns 'the digest will not match once you have downloaded it' into 'the share \
                     does not open at all'.",
            "expect_error": "Auth",
            "recipient_kem_seed_hex": hex::encode(recipient_kem_seed()),
            "recipient_auth_secret_hex": hex::encode(recipient_auth_secret()),
            "recipient_sig_seed_hex": hex::encode(recipient_sig_seed()),
            "sender_identity_kem_seed_hex": hex::encode(sender_kem_seed()),
            "sender_identity_auth_secret_hex": hex::encode(sender_auth_secret()),
            "sender_identity_sig_seed_hex": hex::encode(sender_sig_seed()),
            "item_id_ascii": String::from_utf8(other_item_id.to_vec()).unwrap(),
            "name_share_ct_hex": name_ok,
            "content_hash_share_ct_hex": hash_ok,
            "envelope_hex": hex::encode(&envelope),
            "expect": "fail",
        }),
        json!({
            "type": "bad_self_signature",
            "stage": "identity",
            "description": "a genuine identity with one bit flipped inside its self-signature",
            "note": "Refused before any key in the bundle is looked at (§5.2a). The root, both \
                     working keys and the address are all untouched and correct — what is gone is \
                     the bundle's proof that the root authorised those keys, and without it the \
                     keys are unattributed. An implementation that verified the fingerprint and \
                     skipped the signature would pass every other vector in this file and fail \
                     only here, which is exactly why the case exists.",
            "expect_error": "BadSelfSignature",
            "identity_hex": hex::encode(bad_signature_identity),
            "identity_len": share::SHARE_PUBLIC_LEN,
            "flipped_byte_offset": share::SHARE_SIGNED_LEN,
            "expect": "fail",
        }),
        json!({
            "type": "root_mismatched_address",
            "stage": "identity",
            "description": "a genuine, fully verifiable identity fetched by an address its root does not hash to",
            "note": "The bundle PARSES — its signature is real, because it is a real account's \
                     bundle. What fails is the fingerprint: this is the server substituting one \
                     account's identity for another's, which is the A1 attack and the reason the \
                     address check is a separate, mandatory step that `from_bytes` cannot perform \
                     for the caller (it holds no expected address). Refused at \
                     `AddressMismatch`.",
            "expect_error": "AddressMismatch",
            "identity_hex": hex::encode(third.to_bytes()),
            "identity_len": share::SHARE_PUBLIC_LEN,
            "identity_address_hex": hex::encode(third.address().as_bytes()),
            "fetched_by_address_hex": hex::encode(recipient.address().as_bytes()),
            "expect": "fail",
        }),
    ]
}

/// §7.5: identity → address → display form → parsed back.
fn gen_address_vectors() -> Vec<Value> {
    [
        (
            "sender",
            sender_kem_seed(),
            sender_auth_secret(),
            sender_sig_seed(),
        ),
        (
            "recipient",
            recipient_kem_seed(),
            recipient_auth_secret(),
            recipient_sig_seed(),
        ),
        (
            "third_party",
            third_party_kem_seed(),
            third_party_auth_secret(),
            third_party_sig_seed(),
        ),
    ]
    .into_iter()
    .map(|(label, kem, auth, sig)| {
        let id = identity(&kem, &auth, &sig);
        let addr = id.address();
        let mut obj = serde_json::Map::new();
        obj.insert("label".into(), json!(label));
        obj.insert(
            "note".into(),
            json!(
                "address = SHA-256(\"nmts/v3/share-address\" || root)[0..16], where root is the \
                 identity's first 1316 bytes AFTER the version byte — derivation_index(4) || \
                 pk_sig(1312). Since 2026-08-02 it is the ROOT and not the whole bundle (§5.2a), \
                 so `root_hex` is pinned beside the identity: a mismatch is then found at the \
                 root rather than somewhere inside five kilobytes. The display form is Crockford \
                 base32 with a trailing check symbol, grouped 9-9-9 — deliberately unlike an \
                 account code's eight groups of four, because pasting a code where an address \
                 belongs would hand over the login secret. Parsing is case-insensitive and \
                 alias-folding."
            ),
        );
        obj.insert("kem_seed_hex".into(), json!(hex::encode(kem)));
        obj.insert("auth_secret_hex".into(), json!(hex::encode(auth)));
        obj.insert("sig_seed_hex".into(), json!(hex::encode(sig)));
        obj.insert("identity_sha256".into(), json!(sha256_hex(&id.to_bytes())));
        obj.insert("identity_len".into(), json!(share::SHARE_PUBLIC_LEN));
        obj.insert("identity_version".into(), json!(id.identity_version()));
        obj.insert("derivation_index".into(), json!(id.derivation_index()));
        obj.insert("key_epoch".into(), json!(id.key_epoch()));
        obj.insert("root_hex".into(), json!(hex::encode(id.root())));
        obj.insert("root_len".into(), json!(share::SHARE_ROOT_LEN));
        obj.insert(
            "hash_domain".into(),
            json!(String::from_utf8(share::HASH_SHARE_ADDRESS.to_vec()).unwrap()),
        );
        obj.insert("address_hex".into(), json!(hex::encode(addr.as_bytes())));
        obj.insert("address_display".into(), json!(addr.display()));
        // One entry carries the whole identity so the hashing step can be checked on its own,
        // without an implementation of X-Wing key generation standing in the way.
        if label == "recipient" {
            obj.insert("identity_hex".into(), json!(hex::encode(id.to_bytes())));
        }
        Value::Object(obj)
    })
    .collect()
}

/// §7.6: ML-DSA-44 known answers.
///
/// Two kinds, and the JSON says which is which because they are anchored differently:
///
/// * `key_gen` — NIST ACVP inputs and NIST expected outputs. A real known-answer test: the seed
///   and the expected digest are transcribed from the published set, and this generator refuses
///   to write the file if our key generation disagrees.
/// * `sig_gen_deterministic` — the SEED is NIST's, but the message and the context are ours, so
///   NIST publishes no answer for them. These are anchored instead against `fips204`, an
///   independent FIPS 204 implementation carried as a dev-dependency: both are computed here and
///   must agree byte for byte before anything is written. ⚠ Stated plainly rather than filed
///   under "ACVP", because "two implementations agree" and "NIST says so" are different claims.
///   (NIST's own sigGen vectors carry the 2560-byte EXPANDED signing key, which this crate can
///   only import through a deprecated, panicking entry point; that is not something to put on the
///   path of a shipped format.)
fn gen_mldsa_vectors() -> Vec<Value> {
    let mut out = Vec::new();

    for (tc_id, seed_hex, expected_vk_sha256) in ACVP_ML_DSA_44_KEYGEN {
        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let (our_vk, _) = our_key_and_signature(&seed, b"", b"");
        assert_eq!(
            sha256_hex(&our_vk),
            expected_vk_sha256,
            "ML-DSA-44 key generation disagrees with NIST ACVP case {tc_id} — refusing to write \
             a fixture that would enshrine it",
        );
        let (their_vk, _) = fips204_key_and_signature(&seed, b"x", b"");
        assert_eq!(
            hex::encode(&their_vk),
            hex::encode(&our_vk),
            "the two implementations disagree on ACVP case {tc_id}",
        );
        out.push(json!({
            "kind": "key_gen",
            "label": format!("acvp_ml_dsa_44_keygen_{tc_id}"),
            "note": "NIST ACVP ML-DSA-44 keyGen (vsId 42), AFT. seed(32) -> verification key \
                     (1312). This is FIPS 204 Algorithm 6 with the seed as ξ, which is exactly \
                     how an NMTS share identity's root key is produced — the operation runs on \
                     every login.",
            "source": "NIST ACVP ML-DSA keyGen sample set, vsId 42, parameterSet ML-DSA-44",
            "acvp_tc_id": tc_id,
            "seed_hex": seed_hex,
            "verifying_key_hex": hex::encode(&our_vk),
            "verifying_key_len": our_vk.len(),
            "verifying_key_sha256": expected_vk_sha256,
        }));
    }

    // Deterministic signatures, under both the empty context and the one this format ships.
    let (_, seed_hex, _) = ACVP_ML_DSA_44_KEYGEN[0];
    let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    for (label, message, ctx) in ACVP_SIG_MESSAGES {
        let (our_vk, our_sig) = our_key_and_signature(&seed, message, ctx);
        let (their_vk, their_sig) = fips204_key_and_signature(&seed, message, ctx);
        assert_eq!(hex::encode(&their_vk), hex::encode(&our_vk), "{label}: key");
        assert_eq!(
            hex::encode(&their_sig),
            hex::encode(&our_sig),
            "{label}: the two implementations produced different deterministic signatures",
        );
        out.push(json!({
            "kind": "sig_gen_deterministic",
            "label": format!("deterministic_signature_{label}"),
            "note": "FIPS 204 Algorithm 2, deterministic variant (rnd = 32 zero bytes). ⛔ The \
                     hedged variant is never used in NMTS: it would give one account a different \
                     published identity on every device. The seed is NIST ACVP's; the message and \
                     context are ours, so this pair is anchored against a second, independent \
                     implementation (fips204) rather than against a published answer.",
            "anchor": "cross-checked against the independent fips204 implementation at generation and verification time",
            "seed_hex": seed_hex,
            "verifying_key_sha256": sha256_hex(&our_vk),
            "message_utf8": String::from_utf8(message.to_vec()).unwrap(),
            "message_hex": hex::encode(message),
            "context_utf8": String::from_utf8(ctx.to_vec()).unwrap(),
            "context_hex": hex::encode(ctx),
            "signature_hex": hex::encode(&our_sig),
            "signature_len": our_sig.len(),
        }));
    }

    out
}

fn gen_negative_vectors() -> Vec<Value> {
    let dek = dek_a();
    let np = nonce_prefix_a();
    let mut out = Vec::new();

    // flipped_tag: 1-byte stream, flip a bit in the final tag (last byte).
    {
        let mut s = encrypt_fixed(&dek, np, DEFAULT_CHUNK_SIZE_LOG2, &pattern(1));
        let last = s.len() - 1;
        s[last] ^= 0x01;
        out.push(json!({
            "type": "flipped_tag",
            "description": "one bit flipped in the final chunk's Poly1305 tag",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&s),
            "expect": "fail",
        }));
    }

    // truncated_final_chunk: drop the last byte of a single-chunk stream.
    {
        let mut s = encrypt_fixed(&dek, np, DEFAULT_CHUNK_SIZE_LOG2, &pattern(100));
        s.pop();
        out.push(json!({
            "type": "truncated_final_chunk",
            "description": "last byte removed — the stream ends mid-chunk",
            "note": "Refused on the byte count, not the tag: the decoder runs out of input before it has a tag to check. A conforming reader may report either, but it must not accept.",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&s),
            "expect": "fail",
        }));
    }

    // reordered_chunks: 4 tiny chunks (log2=6), swap chunk 0 and chunk 1.
    {
        let log2 = 6u8; // 64-byte chunks
        let mut s = encrypt_fixed(&dek, np, log2, &pattern(200));
        let chunk_ct = (1usize << log2) + TAG_LEN; // 80 bytes
        let c0 = HEADER_LEN;
        let c1 = HEADER_LEN + chunk_ct;
        let (a, b) = s.split_at_mut(c1);
        a[c0..c0 + chunk_ct].swap_with_slice(&mut b[..chunk_ct]);
        out.push(json!({
            "type": "reordered_chunks",
            "description": "chunk 0 and chunk 1 swapped (chunk_size_log2=6)",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&s),
            "expect": "fail",
        }));
    }

    // wrong_is_final: final chunk authenticated with is_final=0x00.
    {
        let log2 = 6u8;
        let s = forge_stream_with_final_flag(&dek, &pattern(200), np, log2, false);
        out.push(json!({
            "type": "wrong_is_final",
            "description": "final chunk sealed with is_final=false",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&s),
            "expect": "fail",
        }));
    }

    // swapped_part_index: part 1's header in front of part 0's body (§7.3). Both are genuine
    // parts of one genuine file under one genuine DEK — only the position is a lie, and before
    // NCF-3 that lie authenticated cleanly because nothing in the header named the part.
    //
    // ⛔ THE TWO BODIES MUST BE THE SAME LENGTH. They were not, once: "first part" is ten bytes
    //    and "second part" is eleven, so the forged stream declared eleven and carried ten. A
    //    reader could refuse it on the byte count and never reach the AAD — and the vector, whose
    //    whole purpose is to prove the AAD binds the part index, would have passed without that
    //    binding existing at all. Equal lengths leave the position as the ONLY lie.
    {
        let total = 3u32;
        let p0 = encrypt_part(&dek, 0, total, b"first part");
        let p1 = encrypt_part(&dek, 1, total, b"secnd part");
        let mut forged = p1[..HEADER_LEN].to_vec();
        forged.extend_from_slice(&p0[HEADER_LEN..]);
        out.push(json!({
            "type": "swapped_part_index",
            "description": "part 1's header placed in front of part 0's body",
            "note": "The whole header is AAD for every chunk, so a part served in the wrong \
                     position no longer authenticates. Compare framing_parts/three_part_file, \
                     where each part opens in its own position.",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&forged),
            "expect": "fail",
        }));
    }

    // plaintext_len_mismatch: corrupt the header's plaintext_len field.
    {
        let mut s = encrypt_fixed(&dek, np, DEFAULT_CHUNK_SIZE_LOG2, &pattern(100));
        // ⛔ NCF-3 header: plaintext_len is at 16..24. Bytes 8..16 are part_index || part_total,
        //    and this line used to write there — an NCF-1 offset left behind by the reframing.
        //    The vector still failed, so nothing noticed: it was rejected as an impossible part
        //    placement (`part_total == 0`) rather than for the reason its own name gives.
        s[16..24].copy_from_slice(&99u64.to_le_bytes());
        out.push(json!({
            "type": "plaintext_len_mismatch",
            "description": "header plaintext_len changed 100 -> 99 (breaks AAD)",
            "note": "The whole 72-byte header is AAD for every chunk, so editing plaintext_len \
                     breaks the first chunk's tag. Its offset is 16..24; bytes 8..16 are \
                     part_index || part_total, and writing there is a DIFFERENT vector.",
            "dek_hex": hex::encode(dek),
            "stream_hex": hex::encode(&s),
            "expect": "fail",
        }));
    }

    out
}

// =====================================================================================
// VERIFICATION (default run)
// =====================================================================================

fn load() -> Value {
    let raw = std::fs::read_to_string(vectors_path())
        .expect("tests/vectors/ncf3.json missing — run gen_vectors first");
    serde_json::from_str(&raw).expect("ncf3.json is valid JSON")
}

fn hexd(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

/// The share row a vector carries, as owned bytes a [`share::SharePayload`] can borrow.
///
/// Read from the JSON rather than rebuilt from the fixture helpers on purpose: a foreign
/// implementation has only the file, so anything the file does not state is not really pinned.
fn payload_bytes(v: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        v["item_id_ascii"].as_str().unwrap().as_bytes().to_vec(),
        hexd(v, "name_share_ct_hex"),
        hexd(v, "content_hash_share_ct_hex"),
    )
}

fn as32(v: &Value, key: &str) -> [u8; 32] {
    hexd(v, key).try_into().unwrap()
}

#[test]
fn verify_kdf() {
    let doc = load();
    for v in doc["kdf"].as_array().unwrap() {
        let code_bytes: [u8; 20] = hexd(v, "code_bytes_hex").try_into().unwrap();

        // The canonical/display code strings must parse back to these exact bytes.
        let parsed = AccountCode::parse(v["code_canonical"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.as_bytes(), &code_bytes, "canonical parse mismatch");
        let parsed_disp = AccountCode::parse(v["code_display"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed_disp.as_bytes(),
            &code_bytes,
            "display parse mismatch"
        );

        // Derivation must reproduce the stored keys.
        let master = derive_master(&code_bytes);
        assert_eq!(
            hex::encode(master),
            v["master_hex"].as_str().unwrap(),
            "master"
        );
        let keys = kdf::derive_from_bytes(&code_bytes).unwrap();
        assert_eq!(
            hex::encode(keys.account_id),
            v["account_id_hex"].as_str().unwrap(),
            "account_id"
        );
        assert_eq!(
            keys.account_id_b64(),
            v["account_id_b64"].as_str().unwrap(),
            "account_id_b64"
        );
        assert_eq!(
            hex::encode(*keys.auth_secret),
            v["auth_secret_hex"].as_str().unwrap(),
            "auth_secret"
        );
        assert_eq!(
            hex::encode(*keys.data_key),
            v["data_key_hex"].as_str().unwrap(),
            "data_key"
        );
        assert_eq!(
            hex::encode(*keys.file_list_key),
            v["file_list_key_hex"].as_str().unwrap(),
            "file_list_key"
        );
        // Not a key — the public name the manifest is stored under inside a quilt. It is pinned
        // in the same group as the key it derives from, because the account code is the only
        // thing a recovery has and this is what turns that code into a place to look.
        assert_eq!(
            manifest::recovery_patch_name(&keys.data_key),
            v["recovery_patch_name"].as_str().unwrap(),
            "recovery_patch_name"
        );
        assert_eq!(
            hex::encode(*keys.share_sig_seed),
            v["share_sig_seed_hex"].as_str().unwrap(),
            "share_sig_seed — this one decides the account's share ADDRESS"
        );
        assert_eq!(
            hex::encode(*keys.share_kem_seed),
            v["share_kem_seed_hex"].as_str().unwrap(),
            "share_kem_seed"
        );
        assert_eq!(
            hex::encode(*keys.share_auth_secret),
            v["share_auth_secret_hex"].as_str().unwrap(),
            "share_auth_secret"
        );
        assert_eq!(
            hex::encode(*keys.wallet_root),
            v["wallet_root_hex"].as_str().unwrap(),
            "wallet_root"
        );
        // `wallet_seed_hex` is wallet 0 under its historical key name — the JS conformance
        // harnesses read that exact spelling, so it stays.
        for (index, key) in [
            (0u32, "wallet_seed_hex"),
            (1, "wallet_seed_1_hex"),
            (10, "wallet_seed_10_hex"),
        ] {
            assert_eq!(
                hex::encode(*keys.wallet_seed_for(index)),
                v[key].as_str().unwrap(),
                "wallet_seed({index})"
            );
        }

        // account_id_b64 must be the base64url of account_id.
        assert_eq!(
            b64::encode(&keys.account_id),
            v["account_id_b64"].as_str().unwrap()
        );
    }
}

#[test]
fn verify_voucher() {
    let doc = load();
    for v in doc["voucher"].as_array().unwrap() {
        let bytes: [u8; 16] = hexd(v, "code_bytes_hex").try_into().unwrap();
        let voucher = VoucherCode::from_bytes(bytes);
        assert_eq!(voucher.canonical(), v["code_canonical"].as_str().unwrap());
        assert_eq!(voucher.display(), v["code_display"].as_str().unwrap());
        assert_eq!(
            hex::encode(voucher.code_hash()),
            v["code_hash_hex"].as_str().unwrap()
        );
        // Parsing the canonical form round-trips to the bytes.
        assert_eq!(
            VoucherCode::parse(v["code_canonical"].as_str().unwrap())
                .unwrap()
                .as_bytes(),
            &bytes
        );
    }
}

#[test]
fn verify_envelope() {
    let doc = load();
    for v in doc["envelope"].as_array().unwrap() {
        let key = as32(v, "key_hex");
        let nonce: [u8; 24] = hexd(v, "nonce_hex").try_into().unwrap();
        let aad = v["aad"].as_str().unwrap().as_bytes();
        let pt = hexd(v, "plaintext_hex");
        let expected = hexd(v, "envelope_hex");

        // Deterministic seal must match byte-for-byte.
        let got = wrap::seal_with_nonce(&key, &nonce, aad, &pt);
        assert_eq!(got, expected, "envelope {}", v["label"]);

        // And open must round-trip.
        let opened = wrap::open(&key, aad, &expected).unwrap();
        assert_eq!(opened, pt, "open roundtrip {}", v["label"]);

        // Wrong AAD must fail.
        assert!(wrap::open(&key, b"nmts/v1/wrong", &expected).is_err());

        // The committed commitment must be the one the envelope carries, at bytes 24..56.
        let commitment = hex::encode(wrap::commitment(&key, &nonce, aad));
        assert_eq!(
            commitment,
            v["commitment_hex"].as_str().unwrap(),
            "commitment {}",
            v["label"]
        );
        assert_eq!(
            hex::encode(
                &expected
                    [wrap::ENVELOPE_NONCE_LEN..wrap::ENVELOPE_NONCE_LEN + wrap::COMMITMENT_LEN]
            ),
            commitment,
            "the envelope must carry the commitment in its documented position",
        );
    }
}

/// §7.2 negative — an altered key commitment must not open.
#[test]
fn verify_envelope_negative() {
    let doc = load();
    for v in doc["envelope_negative"].as_array().unwrap() {
        let key = as32(v, "key_hex");
        let aad = v["aad"].as_str().unwrap().as_bytes();
        let envelope = hexd(v, "envelope_hex");
        assert_eq!(
            wrap::open(&key, aad, &envelope),
            Err(wrap::WrapError::Auth),
            "negative envelope vector {} must fail but opened",
            v["type"]
        );
    }
}

#[test]
fn verify_framing() {
    let doc = load();
    for v in doc["framing"].as_array().unwrap() {
        let dek = as32(v, "dek_hex");
        let np: [u8; 16] = hexd(v, "nonce_prefix_hex").try_into().unwrap();
        let log2 = v["chunk_size_log2"].as_u64().unwrap() as u8;
        let len = v["plaintext_len"].as_u64().unwrap() as usize;
        let pt = pattern(len);

        let stream = encrypt_fixed(&dek, np, log2, &pt);
        assert_eq!(
            stream.len() as u64,
            v["stream_len"].as_u64().unwrap(),
            "stream_len {}",
            v["label"]
        );
        assert_eq!(
            sha256_hex(&stream),
            v["stream_sha256"].as_str().unwrap(),
            "digest {}",
            v["label"]
        );
        if let Some(full) = v.get("stream_hex").and_then(|x| x.as_str()) {
            assert_eq!(hex::encode(&stream), full, "stream_hex {}", v["label"]);
        }

        // Sequential decrypt round-trips.
        let out = StreamDecryptor::decrypt_all(&dek, &stream).unwrap();
        assert_eq!(out, pt, "roundtrip {}", v["label"]);
    }
}

/// The error each negative vector must produce — ⛔ **not merely "some error".**
///
/// WHY THIS TABLE EXISTS (2026-08-19). `verify_negative` used to assert `is_err()` and nothing
/// else, and two vectors were quietly failing for reasons other than the ones their names give:
///
///   * `plaintext_len_mismatch` wrote at header bytes 8..16, which in NCF-3 are
///     `part_index || part_total`, not `plaintext_len` (16..24). It was rejected as an impossible
///     part placement — `part_total == 0` — so nothing about `plaintext_len` was ever exercised.
///   * `swapped_part_index` forged part 1's header onto part 0's body, but the two bodies were ten
///     and eleven bytes, so a reader could refuse it on the byte count and never reach the AAD.
///     The vector exists to prove the AAD BINDS THE PART INDEX; it would have passed with no such
///     binding in the format at all.
///
/// ⛔ A negative vector that fails for the wrong reason is worse than a missing one: it reports a
/// guarantee as tested. Naming the error is what makes the vector mean what it says.
fn expected_error(kind: &str) -> FramingError {
    match kind {
        // The tag no longer matches the ciphertext.
        "flipped_tag" => FramingError::Auth,
        // ⭐ NOT `Auth`. The stream is one byte short of a complete chunk, so the decoder runs out
        //    of input before it ever has a tag to check — the truncation is caught by the byte
        //    count, which is EARLIER and cheaper than the AEAD. Writing `Auth` here (the first
        //    guess) turned this assertion red on its very first run, which is how the difference
        //    got noticed at all. Both are refusals; naming the real one keeps the vector honest
        //    about which mechanism does the work.
        "truncated_final_chunk" => FramingError::Incomplete,
        // Chunk index is in the AAD, so a chunk read in another chunk's place cannot authenticate.
        "reordered_chunks" => FramingError::Auth,
        // `is_final` is in the AAD too.
        "wrong_is_final" => FramingError::Auth,
        // ⭐ THE ONE THIS TABLE WAS WRITTEN FOR: the part index is in the AAD, and with both
        //    bodies the same length that is the ONLY thing left to reject on.
        "swapped_part_index" => FramingError::Auth,
        // The whole header is AAD, so editing `plaintext_len` breaks the first chunk's tag.
        "plaintext_len_mismatch" => FramingError::Auth,
        other => panic!(
            "negative vector {other} has no expected error — add it to expected_error() and say \
             WHY that is the error, or the vector goes back to proving nothing in particular"
        ),
    }
}

#[test]
fn verify_negative() {
    let doc = load();
    let mut seen = 0usize;
    for v in doc["framing_negative"].as_array().unwrap() {
        let dek = as32(v, "dek_hex");
        let stream = hexd(v, "stream_hex");
        let kind = v["type"].as_str().unwrap();
        let result = StreamDecryptor::decrypt_all(&dek, &stream);
        let err = result.expect_err(&format!("negative vector {kind} must fail but decrypted"));
        assert_eq!(
            err,
            expected_error(kind),
            "negative vector {kind} failed, but for the wrong reason — it is named after a \
             guarantee it is not exercising"
        );
        seen += 1;
    }
    // ⛔ A filter that matches nothing also prints "ok". Count what actually ran.
    assert!(seen >= 6, "only {seen} negative vectors ran — the set shrank or the parse broke");
}

/// §7.3 — a multi-part set that verifies, part by part and as a set.
#[test]
fn verify_framing_parts() {
    let doc = load();
    for v in doc["framing_parts"].as_array().unwrap() {
        let dek = as32(v, "dek_hex");
        let total = v["part_total"].as_u64().unwrap() as u32;
        let mut headers = Vec::new();

        for p in v["parts"].as_array().unwrap() {
            let index = p["part_index"].as_u64().unwrap() as u32;
            let body = hexd(p, "plaintext_hex");
            let stream = hexd(p, "stream_hex");

            // The committed bytes must be reproducible from the documented inputs.
            assert_eq!(
                hex::encode(encrypt_part(&dek, index, total, &body)),
                hex::encode(&stream),
                "part {index} is not reproducible"
            );
            assert_eq!(stream.len() as u64, p["stream_len"].as_u64().unwrap());
            assert_eq!(
                hex::encode(&stream[..HEADER_LEN]),
                p["header_hex"].as_str().unwrap(),
                "part {index} header"
            );

            let header = Header::parse(&stream).unwrap();
            assert_eq!(
                (header.part_index, header.part_total),
                (index, total),
                "part {index} must say which part it is"
            );
            assert_eq!(
                StreamDecryptor::decrypt_all(&dek, &stream).unwrap(),
                body,
                "part {index} must open in its own position"
            );
            headers.push(header);
        }

        // The set as a whole. A missing part is invisible to the AEAD — bytes never handed over
        // are never checked — so counting them is a separate, mandatory step for any reader.
        assert!(
            verify_part_set(&headers).is_ok(),
            "the complete set must verify"
        );
        assert!(
            verify_part_set(&headers[..headers.len() - 1]).is_err(),
            "an incomplete set must be refused, or a truncated file reads as a whole one"
        );
    }
}

/// §7.4 first half — the X-Wing published draft vector, through our own call sites.
#[test]
fn verify_xwing() {
    let doc = load();
    for v in doc["xwing"].as_array().unwrap() {
        // The committed inputs must be the upstream ones. Checking our engine only against the
        // fixture would be circular — a drift would have rewritten the fixture — so the anchor is
        // the constant transcribed from the draft, and the fixture is checked against it too.
        assert_eq!(v["seed_hex"].as_str().unwrap(), XWING_SEED, "draft seed");
        assert_eq!(v["eseed_hex"].as_str().unwrap(), XWING_ESEED, "draft eseed");
        assert_eq!(v["ss_hex"].as_str().unwrap(), XWING_SS, "draft ss");
        assert_eq!(
            sha256_hex(&hexd(v, "pk_hex")),
            XWING_PK_SHA256,
            "the committed pk is not the draft's pk"
        );
        assert_eq!(
            sha256_hex(&hexd(v, "ct_hex")),
            XWING_CT_SHA256,
            "the committed ct is not the draft's ct"
        );

        let seed: [u8; 32] = hexd(v, "seed_hex").try_into().unwrap();
        let eseed: [u8; share::KEM_RANDOMNESS_LEN] = hexd(v, "eseed_hex").try_into().unwrap();

        // seed → encapsulation key must match the draft's `pk`.
        let auth = ramp::<32>(0x01);
        let sig = ramp::<32>(0x03);
        let id = identity(&seed, &auth, &sig);
        // ⚠ The KEM key no longer starts at byte 0 — since §5.2a the bundle opens with the
        // version byte and the root. Slice it out by the offsets the format states.
        let kem_at = share::SHARE_SIGNED_LEN - share::SHARE_AUTH_PUBLIC_LEN
            - share::SHARE_KEM_PUBLIC_LEN;
        assert_eq!(
            hex::encode(
                &id.to_bytes()[kem_at..kem_at + share::SHARE_KEM_PUBLIC_LEN]
            ),
            v["pk_hex"].as_str().unwrap(),
            "X-Wing key generation drifted from the published draft vector"
        );

        // (pk, eseed) → ciphertext must match the draft's `ct`.
        let name_ct = share_name_ct();
        let hash_ct = share_content_hash_ct();
        let payload = share::SharePayload {
            item_id: share_item_id(),
            name_ct: &name_ct,
            content_hash_ct: &hash_ct,
        };
        let envelope = share::wrap_dek_for_with_randomness(
            &sender_auth_secret(),
            &sender_sig_seed(),
            &id,
            &id.address(),
            &shared_dek(),
            &payload,
            &share::EnvelopeRandomness {
                kem_eseed: &eseed,
                envelope_nonce: &share_envelope_nonce(),
            },
        )
        .unwrap();
        let ct = &envelope
            [share::SHARE_ADDRESS_LEN..share::SHARE_ADDRESS_LEN + share::KEM_CIPHERTEXT_LEN];
        assert_eq!(
            hex::encode(ct),
            v["ct_hex"].as_str().unwrap(),
            "X-Wing encapsulation drifted from the published draft vector"
        );

        // And the shared secret it produced is the draft's, proved by the envelope opening: a
        // different ss gives a different wrapping key and nothing comes back.
        assert_eq!(
            *share::unwrap_dek(
                &seed,
                &auth,
                &sig,
                &identity(&sender_kem_seed(), &sender_auth_secret(), &sender_sig_seed()),
                &envelope,
                &payload
            )
            .unwrap(),
            shared_dek(),
        );
    }
}

/// §7.4 — the committed share envelope must be reproducible, and must open to the pinned DEK.
#[test]
fn verify_share() {
    let doc = load();
    for v in doc["share"].as_array().unwrap() {
        let sender_kem = as32(v, "sender_kem_seed_hex");
        let sender_auth = as32(v, "sender_auth_secret_hex");
        let sender_sig = as32(v, "sender_sig_seed_hex");
        let recipient_kem = as32(v, "recipient_kem_seed_hex");
        let recipient_auth = as32(v, "recipient_auth_secret_hex");
        let recipient_sig = as32(v, "recipient_sig_seed_hex");
        let eseed: [u8; share::KEM_RANDOMNESS_LEN] = hexd(v, "eseed_hex").try_into().unwrap();
        let nonce: [u8; wrap::ENVELOPE_NONCE_LEN] =
            hexd(v, "envelope_nonce_hex").try_into().unwrap();
        let dek = as32(v, "dek_hex");
        let expected = hexd(v, "envelope_hex");
        let (item_id, name_ct, hash_ct) = payload_bytes(v);
        let payload = share::SharePayload {
            item_id: &item_id,
            name_ct: &name_ct,
            content_hash_ct: &hash_ct,
        };
        assert_eq!(
            hex::encode(payload.commitment().unwrap()),
            v["payload_commitment_hex"].as_str().unwrap(),
            "payload commitment"
        );

        let sender = identity(&sender_kem, &sender_auth, &sender_sig);
        let recipient = identity(&recipient_kem, &recipient_auth, &recipient_sig);

        // The recipient ROOT the wrapping key is bound to (§5.3). Pinned separately so an
        // implementation that put the whole bundle in the HKDF info fails here rather than on
        // 1240 opaque bytes.
        assert_eq!(
            hex::encode(recipient.root()),
            v["recipient_root_hex"].as_str().unwrap(),
            "recipient root"
        );
        assert_eq!(
            recipient.root().len() as u64,
            v["recipient_root_len"].as_u64().unwrap()
        );

        // Identities and their addresses.
        assert_eq!(
            sha256_hex(&sender.to_bytes()),
            v["sender_identity_sha256"].as_str().unwrap(),
            "sender identity"
        );
        assert_eq!(
            sha256_hex(&recipient.to_bytes()),
            v["recipient_identity_sha256"].as_str().unwrap(),
            "recipient identity"
        );
        assert_eq!(
            hex::encode(sender.address().as_bytes()),
            v["sender_address_hex"].as_str().unwrap(),
            "sender address"
        );
        assert_eq!(
            hex::encode(recipient.address().as_bytes()),
            v["recipient_address_hex"].as_str().unwrap(),
            "recipient address"
        );

        // The envelope must be byte-exact from the documented inputs.
        let got = share::wrap_dek_for_with_randomness(
            &sender_auth,
            &sender_sig,
            &recipient,
            &recipient.address(),
            &dek,
            &payload,
            &share::EnvelopeRandomness {
                kem_eseed: &eseed,
                envelope_nonce: &nonce,
            },
        )
        .unwrap();
        assert_eq!(hex::encode(&got), hex::encode(&expected), "envelope bytes");
        assert_eq!(expected.len() as u64, v["envelope_len"].as_u64().unwrap());
        assert_eq!(expected.len(), share::SHARE_ENVELOPE_LEN);

        // The claimed sender is readable without opening, and equals the real sender.
        assert_eq!(
            share::claimed_sender(&expected).unwrap(),
            sender.address(),
            "an envelope must name the account that produced it"
        );

        // And it opens, for the recipient, to the pinned DEK.
        assert_eq!(
            *share::unwrap_dek(
                &recipient_kem,
                &recipient_auth,
                &recipient_sig,
                &sender,
                &expected,
                &payload
            )
            .unwrap(),
            dek,
            "committed envelope must open to the committed DEK"
        );
    }
}

/// §7.4 negatives — every way a share must refuse, and the REASON each is refused for.
///
/// The reason matters as much as the refusal: these cases are stopped by four different
/// mechanisms — the version check, the self-signature, the address fingerprint, and the wrapping
/// key — and a change that collapsed any two of them would mean a check had quietly stopped
/// running while the suite stayed green.
#[test]
fn verify_share_negative() {
    let doc = load();
    let mut seen_identity_stage = 0usize;
    for v in doc["share_negative"].as_array().unwrap() {
        let expected = match v["expect_error"].as_str().unwrap() {
            "AddressMismatch" => share::ShareError::AddressMismatch,
            "Auth" => share::ShareError::Auth,
            "BadSelfSignature" => share::ShareError::BadSelfSignature,
            other => panic!("unknown expect_error {other} in vector {}", v["type"]),
        };

        // Two of the seven are refused before an envelope is ever reached: the identity itself is
        // not usable. Running them through the envelope path would test the wrong mechanism.
        if v["stage"].as_str().unwrap() == "identity" {
            seen_identity_stage += 1;
            let identity_bytes = hexd(v, "identity_hex");
            assert_eq!(
                identity_bytes.len() as u64,
                v["identity_len"].as_u64().unwrap()
            );
            let parsed = share::SharePublicKey::from_bytes(&identity_bytes);
            match expected {
                share::ShareError::AddressMismatch => {
                    // This bundle is genuine and must PARSE — the failure is that it does not
                    // belong to the address it was fetched by.
                    let pk = parsed.unwrap_or_else(|e| {
                        panic!("vector {} must parse, got {e:?}", v["type"])
                    });
                    assert_eq!(
                        hex::encode(pk.address().as_bytes()),
                        v["identity_address_hex"].as_str().unwrap(),
                        "the bundle's own address"
                    );
                    let fetched_by: [u8; share::SHARE_ADDRESS_LEN] =
                        hexd(v, "fetched_by_address_hex").try_into().unwrap();
                    assert_eq!(
                        share::verify_address(&pk, &share::ShareAddress(fetched_by)).unwrap_err(),
                        share::ShareError::AddressMismatch,
                        "negative share vector {}",
                        v["type"]
                    );
                }
                other => {
                    assert_eq!(
                        parsed.err().unwrap_or_else(|| panic!(
                            "vector {} must not parse",
                            v["type"]
                        )),
                        other,
                        "negative share vector {}",
                        v["type"]
                    );
                }
            }
            continue;
        }

        let recipient_kem = as32(v, "recipient_kem_seed_hex");
        let recipient_auth = as32(v, "recipient_auth_secret_hex");
        let recipient_sig = as32(v, "recipient_sig_seed_hex");
        let claimed_kem = as32(v, "sender_identity_kem_seed_hex");
        let claimed_auth = as32(v, "sender_identity_auth_secret_hex");
        let claimed_sig = as32(v, "sender_identity_sig_seed_hex");
        let envelope = hexd(v, "envelope_hex");

        let (item_id, name_ct, hash_ct) = payload_bytes(v);
        let payload = share::SharePayload {
            item_id: &item_id,
            name_ct: &name_ct,
            content_hash_ct: &hash_ct,
        };

        let supplied_sender = identity(&claimed_kem, &claimed_auth, &claimed_sig);
        let err = share::unwrap_dek(
            &recipient_kem,
            &recipient_auth,
            &recipient_sig,
            &supplied_sender,
            &envelope,
            &payload,
        )
        .expect_err(&format!(
            "negative share vector {} must fail but opened",
            v["type"]
        ));
        assert_eq!(err, expected, "negative share vector {}", v["type"]);
    }
    assert_eq!(
        seen_identity_stage, 2,
        "both identity-stage negatives must be present — losing one would drop the only check on \
         the self-signature or on the fingerprint"
    );
}

/// §7.6 — ML-DSA-44 against NIST's published answers and against a second implementation.
///
/// This is the group that keeps "we implement FIPS 204" from being our own word for it. It runs
/// the two operations the format depends on — a seed expanded into a verification key, and a
/// deterministic signature — and compares each against something that is not us.
#[test]
fn verify_mldsa() {
    let doc = load();
    let group = doc["mldsa"].as_array().unwrap();
    let mut key_gen = 0usize;
    let mut sig_gen = 0usize;

    for v in group {
        let seed: [u8; 32] = hexd(v, "seed_hex").try_into().unwrap();
        match v["kind"].as_str().unwrap() {
            "key_gen" => {
                key_gen += 1;
                // The committed seed must be one of NIST's, or the fixture could be anything.
                let tc_id = v["acvp_tc_id"].as_u64().unwrap() as u32;
                let (_, want_seed, want_vk_sha256) = ACVP_ML_DSA_44_KEYGEN
                    .into_iter()
                    .find(|(id, _, _)| *id == tc_id)
                    .unwrap_or_else(|| panic!("vector claims an ACVP case {tc_id} we do not pin"));
                assert_eq!(v["seed_hex"].as_str().unwrap(), want_seed, "ACVP seed {tc_id}");
                assert_eq!(
                    v["verifying_key_sha256"].as_str().unwrap(),
                    want_vk_sha256,
                    "the committed digest is not NIST's for ACVP case {tc_id}"
                );

                let committed = hexd(v, "verifying_key_hex");
                assert_eq!(sha256_hex(&committed), want_vk_sha256, "committed key bytes");
                assert_eq!(
                    committed.len() as u64,
                    v["verifying_key_len"].as_u64().unwrap()
                );
                assert_eq!(committed.len(), share::SHARE_SIG_PUBLIC_LEN);

                let (ours, _) = our_key_and_signature(&seed, b"", b"");
                assert_eq!(
                    hex::encode(&ours),
                    hex::encode(&committed),
                    "our key generation drifted from NIST ACVP case {tc_id}"
                );
            }
            "sig_gen_deterministic" => {
                sig_gen += 1;
                let message = hexd(v, "message_hex");
                let ctx = hexd(v, "context_hex");
                let committed = hexd(v, "signature_hex");
                assert_eq!(
                    committed.len() as u64,
                    v["signature_len"].as_u64().unwrap()
                );
                assert_eq!(committed.len(), share::SHARE_SELF_SIG_LEN);

                let (our_vk, our_sig) = our_key_and_signature(&seed, &message, &ctx);
                assert_eq!(
                    hex::encode(&our_sig),
                    hex::encode(&committed),
                    "deterministic signature drift for {}",
                    v["label"]
                );
                assert_eq!(
                    sha256_hex(&our_vk),
                    v["verifying_key_sha256"].as_str().unwrap()
                );

                // The anchor: an independent implementation must produce the identical bytes.
                // Without this the vector would only say "we still agree with ourselves".
                let (their_vk, their_sig) = fips204_key_and_signature(&seed, &message, &ctx);
                assert_eq!(hex::encode(&their_vk), hex::encode(&our_vk), "cross-check key");
                assert_eq!(
                    hex::encode(&their_sig),
                    hex::encode(&committed),
                    "the independent implementation disagrees with the committed signature"
                );
            }
            other => panic!("unknown mldsa vector kind {other}"),
        }
    }

    assert!(key_gen >= 3, "expected the three NIST key-generation cases, saw {key_gen}");
    assert_eq!(
        sig_gen, 2,
        "both signing contexts must be pinned — the empty one and the identity-bundle one this \
         format actually ships"
    );
}

/// §7.5 — identity → address → display → parsed back.
#[test]
fn verify_address() {
    let doc = load();
    for v in doc["address"].as_array().unwrap() {
        let kem = as32(v, "kem_seed_hex");
        let auth = as32(v, "auth_secret_hex");
        let sig = as32(v, "sig_seed_hex");
        let id = identity(&kem, &auth, &sig);
        let addr = id.address();

        assert_eq!(
            sha256_hex(&id.to_bytes()),
            v["identity_sha256"].as_str().unwrap(),
            "identity {}",
            v["label"]
        );
        // The root is pinned on its own, because it is the value an address can never stop
        // matching — finding a drift here rather than inside five kilobytes is the difference
        // between a diagnosis and a hunt.
        assert_eq!(
            hex::encode(id.root()),
            v["root_hex"].as_str().unwrap(),
            "root {}",
            v["label"]
        );
        assert_eq!(id.root().len() as u64, v["root_len"].as_u64().unwrap());
        assert_eq!(
            id.identity_version() as u64,
            v["identity_version"].as_u64().unwrap()
        );
        assert_eq!(
            id.derivation_index() as u64,
            v["derivation_index"].as_u64().unwrap(),
            "the reserved derivation index must still be zero"
        );
        assert_eq!(
            id.key_epoch() as u64,
            v["key_epoch"].as_u64().unwrap(),
            "the reserved key epoch must still be zero"
        );
        assert_eq!(
            id.to_bytes().len() as u64,
            v["identity_len"].as_u64().unwrap()
        );
        // Where the full identity is committed, it must be the identity these seeds produce —
        // this is the entry an implementation can use to check the hashing step alone.
        if let Some(full) = v.get("identity_hex").and_then(|x| x.as_str()) {
            assert_eq!(hex::encode(id.to_bytes()), full, "identity bytes");
            assert_eq!(
                share::SharePublicKey::from_bytes(&hex::decode(full).unwrap())
                    .unwrap()
                    .address(),
                addr,
                "the address must be recomputable from the published bytes alone"
            );
        }

        assert_eq!(
            hex::encode(addr.as_bytes()),
            v["address_hex"].as_str().unwrap(),
            "address {}",
            v["label"]
        );
        let shown = v["address_display"].as_str().unwrap();
        assert_eq!(addr.display(), shown, "display {}", v["label"]);

        // Round-trip, and the sloppy input a person actually types.
        assert_eq!(share::ShareAddress::parse(shown).unwrap(), addr);
        assert_eq!(
            share::ShareAddress::parse(&shown.to_lowercase().replace('-', " ")).unwrap(),
            addr,
            "an address read aloud and retyped must resolve"
        );

        // A one-character typo must be refused locally rather than looked up.
        let mut chars: Vec<char> = shown.chars().collect();
        chars[0] = if chars[0] == '7' { '8' } else { '7' };
        let typo: String = chars.into_iter().collect();
        assert!(
            share::ShareAddress::parse(&typo).is_err(),
            "a one-character typo must not parse: {typo}"
        );
    }
}
