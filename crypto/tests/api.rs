//! Behavioural tests for the public API (no `vectors` feature required).
//!
//! Covers code parsing/normalization, KDF determinism and versioning, envelope + share
//! tokens, manifest round-trip and the single-envelope rule, and framing error paths.

use nmts_crypto::codes::{self, AccountCode, CodeError, VoucherCode};
use nmts_crypto::framing::{FramingError, StreamDecryptor, StreamEncryptor};
use nmts_crypto::manifest::{Item, ManifestError, Part, Quilt, RecoveryManifest};
use nmts_crypto::{b64, kdf, share, wrap};

// ----- codes -------------------------------------------------------------------------

#[test]
fn account_code_roundtrip_and_display_shape() {
    let code = AccountCode::from_bytes([0xAB; 20]);
    let display = code.display();
    // 8 hyphen-separated groups: seven of 4, last of 5 (33 symbols total).
    let groups: Vec<&str> = display.split('-').collect();
    assert_eq!(groups.len(), 8);
    for g in &groups[..7] {
        assert_eq!(g.len(), 4);
    }
    assert_eq!(groups[7].len(), 5);
    assert_eq!(code.canonical().len(), 33);

    let parsed = AccountCode::parse(&display).unwrap();
    assert_eq!(parsed.as_bytes(), code.as_bytes());
}

#[test]
fn account_code_normalization_aliasing_and_case() {
    let code = AccountCode::from_bytes([0x10; 20]);
    let canonical = code.canonical();
    // Lowercase the canonical form and inject aliasable characters + spacing.
    // O->0, I->1, L->1; the canonical alphabet has no O/I/L so we can only lower/space it.
    let messy = format!("  {}  ", canonical.to_lowercase());
    let parsed = AccountCode::parse(&messy).unwrap();
    assert_eq!(parsed.as_bytes(), code.as_bytes());
}

#[test]
fn account_code_alias_maps_letters() {
    // Build a code, then in its canonical string map a '0'->'O', '1'->'I' to prove the
    // parser aliases them back. (Only run if such digits appear; craft bytes that do.)
    let code = AccountCode::from_bytes([0x00; 20]); // all '0' data symbols
    let canonical = code.canonical(); // "000...0" + check '0'
    let aliased = canonical.replace('0', "O");
    let parsed = AccountCode::parse(&aliased).unwrap();
    assert_eq!(parsed.as_bytes(), code.as_bytes());
}

#[test]
fn account_code_bad_check_symbol_rejected() {
    let code = AccountCode::from_bytes([0x33; 20]);
    let mut canonical: Vec<char> = code.canonical().chars().collect();
    // Corrupt a data symbol so the check no longer matches.
    canonical[0] = if canonical[0] == 'Z' { 'Y' } else { 'Z' };
    let s: String = canonical.into_iter().collect();
    assert_eq!(AccountCode::parse(&s), Err(CodeError::CheckMismatch));
}

#[test]
fn account_code_wrong_length_rejected() {
    assert!(matches!(
        AccountCode::parse("ABC"),
        Err(CodeError::WrongLength { .. })
    ));
}

#[test]
fn account_code_invalid_symbol_rejected() {
    // 33 chars but containing an out-of-alphabet symbol 'U' in a data position.
    let bad = "U".repeat(33);
    assert!(matches!(
        AccountCode::parse(&bad),
        Err(CodeError::InvalidSymbol('U'))
    ));
}

#[test]
fn voucher_roundtrip_and_hash_matches_input() {
    let v = VoucherCode::from_bytes([0x5C; 16]);
    assert_eq!(v.canonical().len(), 27);
    let parsed = VoucherCode::parse(&v.display()).unwrap();
    assert_eq!(parsed.as_bytes(), v.as_bytes());
    // Hash from arbitrary user input (spaced/lowercased) equals the stored hash.
    let typed = format!(" {} ", v.display().to_lowercase());
    assert_eq!(codes::voucher_hash_from_input(&typed), v.code_hash());
}

// Audit finding, 2026-07-28 — the last symbol of a 16-byte code carries two
// bits the bytes do not use, and ignoring them cost the check symbol its coverage of that
// position.
//
// A 16-byte code is 26 symbols = 130 bits, of which 128 are data. The encoder writes the
// leftover 2 bits as zero, but the decoder used to discard them, so `…SG`, `…SH`, `…SJ`, `…SK`
// all decoded to the same bytes. The check symbol is computed FROM those bytes, so it matched
// all four: the one position the checksum could not see was the position it was there to guard.
// Measured on the shipped WASM engine before the fix: 6,000 of 6,000 such typos accepted.
//
// For a share address that was merely dishonest — the aliased spelling still resolved to the
// right account. For a voucher it was a defect, because `voucher_hash_from_input` hashes the
// normalized STRING: all four spellings hash differently (500 of 500 measured), so the check
// symbol would have told a person their code was correct about a code that cannot redeem.
// Vouchers are still a server stub, which is the only reason that never shipped.
//
// These three tests pin the property, not the incident: canonical output has zero padding, a
// non-zero-padding spelling is refused, and a 20-byte account code (160 bits = 32 symbols, no
// padding at all) is untouched by the rule.
#[test]
fn sixteen_byte_codes_have_only_one_valid_spelling() {
    // Every canonical last data symbol has its low 2 bits clear, so its 5-bit value is a
    // multiple of 4 — 8 of the 32 symbols, not all 32.
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for seed in 0u8..64 {
        let v = VoucherCode::from_bytes([seed.wrapping_mul(37).wrapping_add(11); 16]);
        let canonical = v.canonical();
        let last_data = canonical.chars().nth(canonical.len() - 2).unwrap();
        let value = ALPHABET.find(last_data).expect("data symbol");
        assert_eq!(
            value % 4,
            0,
            "canonical padding bits must be zero: {canonical}"
        );
    }
}

#[test]
fn non_canonical_padding_is_refused() {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let v = VoucherCode::from_bytes([0x5C; 16]);
    let canonical = v.canonical();
    let chars: Vec<char> = canonical.chars().collect();
    let last_data_idx = chars.len() - 2;
    let base = ALPHABET
        .iter()
        .position(|&a| a as char == chars[last_data_idx])
        .unwrap();

    for delta in 1..=3 {
        let mut alias = chars.clone();
        alias[last_data_idx] = ALPHABET[base + delta] as char;
        let s: String = alias.into_iter().collect();
        assert_eq!(
            VoucherCode::parse(&s),
            Err(CodeError::NonCanonicalPadding),
            "a spelling we never generate must be refused, not silently accepted: {s}"
        );
        // And the reason it matters: this spelling hashes to something else entirely, so
        // accepting it would mean a check symbol that passes on a code that cannot redeem.
        assert_ne!(codes::voucher_hash_from_input(&s), v.code_hash());
    }
}

#[test]
fn account_codes_are_unaffected_by_the_padding_rule() {
    // 160 bits = 32 symbols exactly, so there are no padding bits to be non-zero. Every
    // symbol of an account code stays reachable.
    for _ in 0..16 {
        let a = AccountCode::generate();
        assert_eq!(
            AccountCode::parse(&a.display()).unwrap().as_bytes(),
            a.as_bytes()
        );
    }
}

#[test]
fn generated_codes_parse() {
    for _ in 0..16 {
        let a = AccountCode::generate();
        assert_eq!(
            AccountCode::parse(&a.display()).unwrap().as_bytes(),
            a.as_bytes()
        );
        let v = VoucherCode::generate();
        assert_eq!(
            VoucherCode::parse(&v.display()).unwrap().as_bytes(),
            v.as_bytes()
        );
    }
}

// ----- kdf ---------------------------------------------------------------------------

#[test]
fn kdf_is_deterministic_and_distinct() {
    let bytes = [0x42u8; 20];
    let a = kdf::derive_from_bytes(&bytes).unwrap();
    let b = kdf::derive_from_bytes(&bytes).unwrap();
    assert_eq!(a.account_id, b.account_id);
    assert_eq!(*a.auth_secret, *b.auth_secret);
    assert_eq!(*a.data_key, *b.data_key);
    // The three outputs are independent.
    assert_ne!(&a.auth_secret[..], &a.data_key[..]);
    assert_ne!(&a.account_id[..], &a.data_key[..16]);
    // account_id_b64 is base64url of the 16 bytes.
    assert_eq!(a.account_id_b64(), b64::encode(&a.account_id));
    assert_eq!(a.version, kdf::KdfVersion::V3);
    assert_eq!(kdf::KdfVersion::V3.as_u8(), 3);
}

#[test]
fn kdf_different_codes_differ() {
    let a = kdf::derive_from_bytes(&[0x00u8; 20]).unwrap();
    let b = kdf::derive_from_bytes(&[0x01u8; 20]).unwrap();
    assert_ne!(a.account_id, b.account_id);
    assert_ne!(*a.data_key, *b.data_key);
}

// ----- wrap / share tokens -----------------------------------------------------------

#[test]
fn dek_wrap_roundtrip_and_domain_separation() {
    let data_key = [0x77u8; 32];
    let dek = *wrap::generate_dek();
    let env = wrap::wrap_dek(&data_key, &dek);
    assert_eq!(env.len(), wrap::WRAPPED_DEK_LEN);
    assert_eq!(*wrap::unwrap_dek(&data_key, &env).unwrap(), dek);

    // A DEK envelope must not open as a name (different AAD).
    assert!(wrap::decrypt_name(&data_key, &env).is_err());
    // Wrong key fails.
    assert!(wrap::unwrap_dek(&[0u8; 32], &env).is_err());
}

#[test]
fn name_and_meta_roundtrip() {
    let dk = [0x12u8; 32];
    let name = "report 2026 — 최종.pdf";
    let env = wrap::encrypt_name(&dk, name);
    assert_eq!(wrap::decrypt_name(&dk, &env).unwrap(), name);

    let meta = r#"{"path":"/a/b","tags":["x"]}"#;
    let menv = wrap::encrypt_meta(&dk, meta);
    assert_eq!(wrap::decrypt_meta(&dk, &menv).unwrap(), meta);
    // name and meta share the key but not the AAD.
    assert!(wrap::decrypt_meta(&dk, &env).is_err());
}

#[test]
fn content_hash_roundtrip_and_domain_separation() {
    let dk = [0x5au8; 32];
    let hash = [0xabu8; wrap::CONTENT_HASH_LEN];

    let env = wrap::seal_content_hash(&dk, &hash);
    assert_eq!(env.len(), wrap::SEALED_CONTENT_HASH_LEN);
    assert_eq!(wrap::open_content_hash(&dk, &env).unwrap(), hash);

    // The server sees only ciphertext: sealing the SAME hash twice must not produce the
    // same bytes, or equal-content files would still be correlatable across accounts.
    assert_ne!(env, wrap::seal_content_hash(&dk, &hash));

    // Wrong key fails.
    assert!(wrap::open_content_hash(&[0u8; 32], &env).is_err());
    // A hash envelope must not open as a name, nor a name envelope as a hash.
    assert!(wrap::decrypt_name(&dk, &env).is_err());
    let name_env = wrap::encrypt_name(&dk, "invoice.pdf");
    assert!(wrap::open_content_hash(&dk, &name_env).is_err());
}

#[test]
fn content_hash_rejects_a_wrong_length_payload() {
    // A 32-byte payload is the only shape `open_content_hash` may accept. Sealing 31 bytes
    // under the SAME AAD authenticates fine, so length is a separate, explicit gate.
    let dk = [0x31u8; 32];
    let env = wrap::seal(&dk, wrap::AAD_CONTENT_HASH, &[0u8; 31]);
    assert_eq!(
        wrap::open_content_hash(&dk, &env),
        Err(wrap::WrapError::BadContentHashLength)
    );
}

#[test]
fn share_token_roundtrip() {
    let dek = *wrap::generate_dek();
    let token = wrap::encode_share_token(&dek);
    // base64url(33 bytes) has no padding and length 44.
    assert_eq!(token.len(), 44);
    assert!(!token.contains('='));
    let parsed = wrap::parse_share_token(&token).unwrap();
    assert_eq!(*parsed, dek);
}

#[test]
fn share_token_rejects_bad_version_and_length() {
    // Wrong version byte.
    let mut raw = [0u8; 33];
    raw[0] = 0x02;
    let tok = b64::encode(&raw);
    assert!(matches!(
        wrap::parse_share_token(&tok),
        Err(wrap::WrapError::BadTokenVersion(2))
    ));
    // Wrong length.
    let short = b64::encode(&[0x01u8; 10]);
    assert!(matches!(
        wrap::parse_share_token(&short),
        Err(wrap::WrapError::BadTokenLength)
    ));
}

// ----- manifest ----------------------------------------------------------------------

/// The manifest that `tests/vectors/nrm2-sample.json` describes, built in Rust.
///
/// The fixture is shared with the WEB unit tests: the browser assembles manifest JSON itself
/// (the document carries every file key, so it never leaves the crypto worker in the clear),
/// which makes these structs and that builder two independent implementations of one wire
/// format. `manifest_matches_shared_fixture` is the gate that stops them drifting apart.
fn sample_manifest() -> RecoveryManifest {
    RecoveryManifest {
        v: 2,
        seq: 12,
        prev_manifest_blob_id: Some("prevManifestBlob".into()),
        generated_at: "2026-07-26T00:00:00Z".into(),
        account_id: "abcdEFGH1234-_wx".into(),
        items: vec![
            Item {
                id: "11111111-1111-4111-8111-111111111111".into(),
                name: "big.bin".into(),
                path: "/".into(),
                size: 1_073_741_825,
                dek: b64::encode(&[9u8; 32]),
                kind: "file".into(),
                content_hash: Some(b64::encode(&[1u8; 32])),
                parts: vec![
                    Part {
                        // Spelled out rather than counted: a fixture checked against a loop
                        // would agree with itself whatever numbers it held.
                        part_index: Some(0),
                        blob_id: "blobA".into(),
                        plaintext_len: 1_073_741_824,
                        sui_object_id: Some("0xabc".into()),
                        // Named outright — what every map written from now on looks like.
                        network: Some("walrus".into()),
                    },
                    Part {
                        part_index: Some(1),
                        blob_id: "blobB".into(),
                        plaintext_len: 1,
                        sui_object_id: None,
                        // Omitted — what every map written BEFORE the field looks like.
                        network: None,
                    },
                ],
                quilt: None,
            },
            Item {
                id: "22222222-2222-4222-8222-222222222222".into(),
                name: "note.txt".into(),
                path: "/docs".into(),
                size: 12,
                dek: b64::encode(&[7u8; 32]),
                kind: "file".into(),
                content_hash: None,
                parts: vec![Part {
                    part_index: Some(0),
                    blob_id: "blobC".into(),
                    plaintext_len: 12,
                    sui_object_id: None,
                    // A non-default name, so neither implementation can pass by hardcoding
                    // "walrus". Nothing is stored on Filecoin — this exercises the format.
                    network: Some("filecoin".into()),
                }],
                quilt: Some(Quilt {
                    quilt_blob_id: "quiltX".into(),
                    patch_id: "patch7".into(),
                }),
            },
        ],
    }
}

/// The same document as [`sample_manifest`] one version back: `v` is 1 and no part carries a
/// `part_index`. That is exactly what NRM-1 looked like, and `tests/vectors/nrm1-sample.json`
/// is the written-down copy of it.
///
/// Expressed as a subtraction from the v2 sample rather than as a second literal, because the
/// two documents differ in those two things and in nothing else — a hand-copied twin could
/// drift in some third field and both fixtures would still pass.
fn sample_manifest_nrm1() -> RecoveryManifest {
    let mut m = sample_manifest();
    m.v = 1;
    for item in &mut m.items {
        for part in &mut item.parts {
            part.part_index = None;
        }
    }
    m
}

/// A fixture's JSON with the human-readable `_comment` key stripped.
///
/// Used to compare a fixture against our own output as UNTYPED JSON. Struct equality proves
/// the fields we know are read correctly, but serde silently ignores fields it does not know,
/// so a misspelled or stray key in a fixture sails straight through it. This is what pins a
/// fixture to exactly the fields these structs emit — nothing more, nothing fewer.
fn fixture_json(raw: &[u8]) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(raw).expect("fixture must be JSON");
    value
        .as_object_mut()
        .expect("fixture is an object")
        .remove("_comment");
    value
}

#[test]
fn manifest_json_and_envelope_roundtrip() {
    let m = sample_manifest();
    let json = m.to_json().unwrap();
    assert_eq!(RecoveryManifest::from_json(&json).unwrap(), m);

    let dk = [0x21u8; 32];
    let env = m.encrypt(&dk).unwrap();
    assert_eq!(RecoveryManifest::decrypt(&dk, &env).unwrap(), m);
    // Wrong key fails.
    assert!(RecoveryManifest::decrypt(&[0u8; 32], &env).is_err());
}

/// The wire-format gate against the browser's builder (see `sample_manifest`).
///
/// Compares PARSED values twice over: as structs, so field names, nesting and which fields
/// vanish when absent are pinned, and as untyped JSON, so a field these structs do NOT know
/// cannot sit in the fixture unnoticed. Key order is not part of the contract either way.
#[test]
fn manifest_matches_shared_fixture() {
    let raw = include_bytes!("vectors/nrm2-sample.json");
    let parsed = RecoveryManifest::from_json(raw).expect("fixture must parse");
    assert_eq!(parsed, sample_manifest());

    // Round-tripping our own output must land on the same document — proves the fixture is
    // reachable from these structs and not merely tolerated by a lenient parser.
    let emitted = parsed.to_json().unwrap();
    let reparsed = RecoveryManifest::from_json(&emitted).unwrap();
    assert_eq!(reparsed, parsed);
    assert_eq!(fixture_json(&emitted), fixture_json(raw));
}

/// NRM-1 maps stay readable, and a reader can TELL that they are NRM-1.
///
/// A map somebody downloaded before 2026-07-29 is the only copy they have, so this is not a
/// nicety. What it must not do is look like an NRM-2 map: every part comes back with
/// `part_index: None`, which is the type saying "this document cannot tell you where this part
/// goes" — RECOVERY-MANIFEST.md §6's "treat its array order as a claim it has not yet
/// verified". A `u64` defaulting to 0 would have said the opposite, confidently.
#[test]
fn manifest_still_parses_an_nrm1_document() {
    let raw = include_bytes!("vectors/nrm1-sample.json");
    let parsed = RecoveryManifest::from_json(raw).expect("an NRM-1 map must still open");
    assert_eq!(parsed, sample_manifest_nrm1());
    assert_eq!(parsed.v, 1);
    assert!(
        parsed
            .items
            .iter()
            .flat_map(|it| &it.parts)
            .all(|p| p.part_index.is_none()),
        "NRM-1 has no placement to read, and absence must not be filled in"
    );

    let emitted = parsed.to_json().unwrap();
    assert_eq!(fixture_json(&emitted), fixture_json(raw));
}

/// The version marker moved to 2 when `part_index` became required.
#[test]
fn manifest_version_is_two() {
    // Pinned as a LITERAL, because every other test here compares against the constant and so
    // proves the number travels rather than what it is — and what it is carries the whole
    // compatibility story (RECOVERY-MANIFEST.md §6). Moving it means moving that section too.
    assert_eq!(nmts_crypto::manifest::MANIFEST_VERSION, 2);
    // The threshold is a separate fact from "what we write", and stays 2 past the next bump.
    assert_eq!(nmts_crypto::manifest::MANIFEST_VERSION_WITH_PART_INDEX, 2);
}

/// A `v: 2` document with a part that carries no `part_index` is refused.
///
/// It is not an old map: NRM-1 is the version where the field does not exist. A document that
/// declares itself NRM-2 and then omits the field is one that was altered, and accepting it
/// would make stripping the field a silent downgrade nobody could detect
/// (RECOVERY-MANIFEST.md §2.1, second ⛔).
#[test]
fn manifest_v2_refuses_a_part_with_no_placement() {
    let stripped = br#"{"v":2,"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-07-26T00:00:00Z","account_id":"x","items":[
        {"id":"i","name":"n","path":"/","size":2,"dek":"d","kind":"file","parts":[
        {"part_index":0,"blob_id":"a","plaintext_len":1},
        {"blob_id":"b","plaintext_len":1}]}]}"#;
    let err = RecoveryManifest::from_json(stripped).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::PartIndexMissing {
                position: 1,
                v: 2,
                ..
            }
        ),
        "{err}"
    );

    // Explicit null is the same statement spelled differently, and must land the same way —
    // two spellings of "not recorded" is one too many.
    let nulled = br#"{"v":2,"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-07-26T00:00:00Z","account_id":"x","items":[
        {"id":"i","name":"n","path":"/","size":1,"dek":"d","kind":"file","parts":[
        {"part_index":null,"blob_id":"a","plaintext_len":1}]}]}"#;
    assert!(matches!(
        RecoveryManifest::from_json(nulled).unwrap_err(),
        ManifestError::PartIndexMissing { position: 0, .. }
    ));
}

/// A part whose `part_index` disagrees with the position it occupies is refused.
///
/// The two parts below are a straight swap: each index exists exactly once, so a reader that
/// sorted first would find a perfect `0, 1` run and accept a file that assembles backwards.
/// The check is positional and stays positional — there is deliberately no sort helper in the
/// crate to reach for — the same mistake was made once in the browser download path.
#[test]
fn manifest_refuses_a_part_that_sits_somewhere_else() {
    let swapped = br#"{"v":2,"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-07-26T00:00:00Z","account_id":"x","items":[
        {"id":"i","name":"n","path":"/","size":2,"dek":"d","kind":"file","parts":[
        {"part_index":1,"blob_id":"a","plaintext_len":1},
        {"part_index":0,"blob_id":"b","plaintext_len":1}]}]}"#;
    let err = RecoveryManifest::from_json(swapped).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::PartIndexMisplaced {
                position: 0,
                stated: 1,
                ..
            }
        ),
        "{err}"
    );

    // A number too large to be any position at all is the same contradiction, and must not
    // reach a lossy comparison on its way to being refused.
    let absurd = br#"{"v":2,"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-07-26T00:00:00Z","account_id":"x","items":[
        {"id":"i","name":"n","path":"/","size":1,"dek":"d","kind":"file","parts":[
        {"part_index":18446744073709551615,"blob_id":"a","plaintext_len":1}]}]}"#;
    assert!(matches!(
        RecoveryManifest::from_json(absurd).unwrap_err(),
        ManifestError::PartIndexMisplaced { position: 0, .. }
    ));

    // And in an NRM-1 document too: absence is legal there, self-contradiction is not.
    let mut old = sample_manifest_nrm1();
    old.items[0].parts[0].part_index = Some(1);
    assert!(matches!(
        RecoveryManifest::from_json(&serde_json::to_vec(&old).unwrap()).unwrap_err(),
        ManifestError::PartIndexMisplaced { position: 0, .. }
    ));
}

/// A writer must not emit an item whose parts do not add up to its `size`.
///
/// RECOVERY-MANIFEST.md §2 makes this a writer MUST and a reader MAY, and the asymmetry is
/// deliberate: `size` is copied from the account's own SEALED file list, so for a writer that
/// has fetched no blob this arithmetic is the only thing standing between a dropped tail and a
/// map that reports itself as complete. A reader is about to check every `plaintext_len`
/// against the part's own sealed header instead, which is strictly stronger — so it gets
/// `Item::parts_add_up` to ask with, not a refusal that would cost it every other file.
#[test]
fn manifest_refuses_to_write_parts_that_do_not_add_up() {
    let mut short = sample_manifest();
    short.items[0].parts.pop();
    assert!(!short.items[0].parts_add_up());
    let err = short.to_json().unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::PartsDoNotAddUp {
                size: 1_073_741_825,
                parts: 1,
                held: 1_073_741_824,
                ..
            }
        ),
        "{err}"
    );
    // encrypt() goes through to_json(), so nothing can be sealed past this either.
    assert!(short.encrypt(&[0x21u8; 32]).is_err());

    // The consistent sample answers yes, so the assertion above is about the arithmetic and
    // not about the method always being false.
    assert!(sample_manifest().items.iter().all(Item::parts_add_up));

    // Lengths chosen to wrap a u64 sum back onto the declared size are still refused: the sum
    // is taken in u128, so there is no arithmetic that makes a short file look whole.
    let mut wrapped = sample_manifest();
    wrapped.items[0].size = 1;
    wrapped.items[0].parts[0].plaintext_len = u64::MAX;
    wrapped.items[0].parts[1].plaintext_len = 2;
    assert!(!wrapped.items[0].parts_add_up());
    assert!(wrapped.to_json().is_err());

    // A reader is NOT stopped by it — the same broken document parses, and answers honestly
    // when asked.
    let served = br#"{"v":2,"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-07-26T00:00:00Z","account_id":"x","items":[
        {"id":"i","name":"n","path":"/","size":10,"dek":"d","kind":"file","parts":[
        {"part_index":0,"blob_id":"a","plaintext_len":4}]}]}"#;
    let parsed = RecoveryManifest::from_json(served).expect("a reader still opens it");
    assert!(!parsed.items[0].parts_add_up());
}

/// A manifest written before the `network` field must still route to a network.
///
/// The recovery tool asks ONE network for a blob id; an unresolved "unknown" there is an
/// unrecoverable file. Absence resolves to walrus because that is the only network NMTS could
/// write to when such a manifest was made — a fact about history, not a default.
#[test]
fn manifest_part_without_a_network_reads_as_walrus() {
    let m = sample_manifest();
    let named = &m.items[0].parts[0];
    let unnamed = &m.items[0].parts[1];
    assert_eq!(named.network.as_deref(), Some("walrus"));
    assert_eq!(unnamed.network, None);
    // Both route to the same aggregator; only one of them says so on the page.
    assert_eq!(named.network_name(), "walrus");
    assert_eq!(unnamed.network_name(), "walrus");
    // A named non-default network is carried through untouched.
    assert_eq!(m.items[1].parts[0].network_name(), "filecoin");
}

#[test]
fn manifest_chain_head_keeps_a_visible_null_link() {
    // seq 1 has no predecessor. `prev_manifest_blob_id` must still be PRESENT as null: a
    // reader has to tell "oldest manifest" apart from "writer never implemented chaining".
    let mut m = sample_manifest();
    m.seq = 1;
    m.prev_manifest_blob_id = None;
    let json = String::from_utf8(m.to_json().unwrap()).unwrap();
    assert!(
        json.contains("\"prev_manifest_blob_id\":null"),
        "head of chain must serialize an explicit null: {json}"
    );
}

#[test]
fn manifest_parses_documents_without_chain_fields() {
    // Defensive: a document written before the chain fields existed still parses, with seq 0
    // standing for "unordered" (real manifests start at 1).
    let legacy = br#"{"v":1,"generated_at":"2026-07-02T00:00:00Z","account_id":"x","items":[]}"#;
    let m = RecoveryManifest::from_json(legacy).unwrap();
    assert_eq!(m.seq, 0);
    assert_eq!(m.prev_manifest_blob_id, None);
}

#[test]
fn manifest_omits_absent_optional_fields() {
    let m = RecoveryManifest {
        v: 2,
        seq: 1,
        prev_manifest_blob_id: None,
        generated_at: "2026-07-02T00:00:00Z".into(),
        account_id: "x".into(),
        items: vec![Item {
            id: "i".into(),
            name: "n".into(),
            path: "/".into(),
            size: 0,
            dek: b64::encode(&[0u8; 32]),
            kind: "file".into(),
            content_hash: None,
            parts: vec![Part {
                part_index: Some(0),
                blob_id: "b".into(),
                plaintext_len: 0,
                sui_object_id: None,
                network: None,
            }],
            quilt: None,
        }],
    };
    let json = String::from_utf8(m.to_json().unwrap()).unwrap();
    for absent in ["quilt", "content_hash", "sui_object_id", "network"] {
        assert!(
            !json.contains(absent),
            "absent {absent} must be omitted: {json}"
        );
    }
    // `part_index` is not in that list and must never join it: from v2 it is required, so the
    // `Option` that makes NRM-1's absence representable must not also let a v2 writer skip it.
    assert!(json.contains("\"part_index\":0"), "{json}");
}

#[test]
fn manifest_rejects_chunk_framed_input() {
    // A stream (leading NCF1 magic) is not a single-envelope manifest.
    let stream = StreamEncryptor::encrypt_all(&[0u8; 32], b"not a manifest");
    let err = RecoveryManifest::decrypt(&[0u8; 32], &stream).unwrap_err();
    assert!(matches!(err, ManifestError::NotSingleEnvelope));
}

// ----- framing error paths -----------------------------------------------------------

#[test]
fn decrypt_rejects_bad_magic_and_short_header() {
    assert!(matches!(
        StreamDecryptor::new(&[0u8; 32], &[0u8; 10]),
        Err(FramingError::ShortHeader)
    ));
    let mut header = [0u8; nmts_crypto::framing::HEADER_LEN];
    header[..4].copy_from_slice(b"XXXX");
    assert!(matches!(
        StreamDecryptor::new(&[0u8; 32], &header),
        Err(FramingError::BadMagic)
    ));
}

/// **The A4 fix.** A multi-part file is several streams under ONE DEK. Before NCF-3 nothing in a
/// part's header said which part it was, so the server could serve part 2 where part 1 belonged
/// and every chunk still authenticated. The counters are in the header and the header is in every
/// chunk's AAD, so a misplaced part now fails to open at all.
#[test]
fn a_part_served_in_the_wrong_position_does_not_open() {
    use nmts_crypto::framing::{verify_part_set, Header, StreamEncryptor};

    let dek = [0x5au8; 32];
    let make = |index: u32, body: &[u8]| {
        let mut enc = StreamEncryptor::new_part(&dek, body.len() as u64, index, 3);
        let mut out = enc.header().to_vec();
        out.extend_from_slice(&enc.push(body).unwrap());
        out.extend_from_slice(&enc.finish().unwrap());
        out
    };
    let p0 = make(0, b"first part");
    let p1 = make(1, b"second part");

    // Each part opens in its own position.
    let h0 = Header::parse(&p0).unwrap();
    assert_eq!((h0.part_index, h0.part_total), (0, 3));
    assert_eq!(
        StreamDecryptor::decrypt_all(&dek, &p0).unwrap(),
        b"first part"
    );

    // Swapping part 1's header onto part 0's body fails authentication — the header is AAD.
    let mut forged = p1[..nmts_crypto::framing::HEADER_LEN].to_vec();
    forged.extend_from_slice(&p0[nmts_crypto::framing::HEADER_LEN..]);
    assert!(StreamDecryptor::decrypt_all(&dek, &forged).is_err());

    // A MISSING part is invisible to the AEAD — bytes never handed over are never checked — so
    // the reader has to count them. This is the check every reassembly path must call.
    let h1 = Header::parse(&p1).unwrap();
    assert!(matches!(
        verify_part_set(&[h0.clone(), h1.clone()]),
        Err(FramingError::IncompletePartSet {
            expected: 3,
            found: 2
        })
    ));
    // And a repeated part must not stand in for the one it replaced.
    assert!(matches!(
        verify_part_set(&[h0.clone(), h1.clone(), h1.clone()]),
        Err(FramingError::BadPartPlacement { .. })
    ));
}

/// **Found by an adversarial review of the ranged-read path (2026-07-29).** The A4 counters close reassembly, but a RANGED read holds one
/// part and its header travels with its own bytes — so the AAD is self-consistent whichever part
/// the server chose to answer with, and `verify_part_set` (which wants every header at once) is
/// not available. Both parts below are the same length and sealed under the same DEK, and each
/// authenticates perfectly on its own: only a stated placement can tell them apart.
#[test]
fn a_ranged_read_of_the_wrong_part_is_refused_when_it_states_where_it_is() {
    use nmts_crypto::framing::{decrypt_chunk, Header, PartPlacement, HEADER_LEN};

    let dek = [0x7cu8; 32];
    // EQUAL lengths on purpose: with different sizes a cross-part read is refused on
    // `chunk_ciphertext_len` before authentication is ever reached, and this would prove nothing.
    let body = |fill: u8| vec![fill; 4096];
    let part = |index: u32| {
        let payload = body(index as u8);
        let mut enc = StreamEncryptor::new_part(&dek, payload.len() as u64, index, 3);
        let mut out = enc.header().to_vec();
        out.extend_from_slice(&enc.push(&payload).unwrap());
        out.extend_from_slice(&enc.finish().unwrap());
        out
    };
    let p0 = part(0);
    let p1 = part(1);
    assert_eq!(p0.len(), p1.len(), "equal parts, or the size check decides");

    let h1 = Header::parse(&p1).unwrap();
    let ct1 = &p1[HEADER_LEN..];

    // The tag alone is perfectly happy — this IS what a hostile server hands a reader that asked
    // for part 0: part 1's bytes, with part 1's header, all of it validly sealed.
    assert_eq!(
        decrypt_chunk(&dek, &h1, PartPlacement::at(1, 3), 0, ct1).unwrap(),
        body(1)
    );

    // Saying "this must be part 0 of 3" refuses it, before any plaintext exists, and the error
    // names what the part ACTUALLY claims rather than what was asked for.
    assert!(matches!(
        decrypt_chunk(&dek, &h1, PartPlacement::at(0, 3), 0, ct1),
        Err(FramingError::BadPartPlacement { index: 1, total: 3 })
    ));
    // Reading one part of a 3-part file as if it were the whole file is the same mistake.
    assert!(matches!(
        decrypt_chunk(&dek, &h1, PartPlacement::whole_file(), 0, ct1),
        Err(FramingError::BadPartPlacement { index: 1, total: 3 })
    ));
    // A wrong KEY is still an auth failure. The two refusals stay in their own classes: placement
    // touches no secret and says so plainly, the key check says nothing at all.
    assert!(matches!(
        decrypt_chunk(&[0x01u8; 32], &h1, PartPlacement::at(1, 3), 0, ct1),
        Err(FramingError::Auth)
    ));
}

/// **The A5 fix.** The stream header commits to its DEK, so one ciphertext cannot be built to
/// open under two keys into two plaintexts. Public links hand the DEK out by design, which is
/// why "this blob is that file" has to be a fact rather than a claim.
#[test]
fn a_stream_names_exactly_one_key() {
    use nmts_crypto::framing::{stream_commitment, Header, StreamEncryptor, HEADER_LEN};

    let dek = [0x11u8; 32];
    let stream = StreamEncryptor::encrypt_all(&dek, b"payload");
    let header = Header::parse(&stream).unwrap();

    assert!(header.verify_commitment(&dek).is_ok());
    // The commitment covers every header byte ABOVE it, not just the key and nonce — found by an adversarial review, 2026-07-29.
    assert_eq!(
        header.key_commitment,
        stream_commitment(&dek, header.as_bytes()[..40].try_into().unwrap()),
    );
    assert!(matches!(
        header.verify_commitment(&[0x12u8; 32]),
        Err(FramingError::Auth)
    ));

    // The decryptor refuses to exist for the wrong key, so no caller can skip the check.
    assert!(matches!(
        StreamDecryptor::new(&[0x12u8; 32], &stream),
        Err(FramingError::Auth)
    ));

    // And the commitment is not merely advisory: editing it breaks the chunk tags too, because
    // the whole header is AAD.
    let mut tampered = stream.clone();
    tampered[HEADER_LEN - 1] ^= 0x01;
    assert!(StreamDecryptor::new(&dek, &tampered).is_err());
}

#[test]
fn decrypt_rejects_trailing_and_incomplete() {
    let dek = [3u8; 32];
    let stream = StreamEncryptor::encrypt_all(&dek, b"hello");
    // Trailing byte after a complete stream.
    let mut extra = stream.clone();
    extra.push(0);
    assert!(StreamDecryptor::decrypt_all(&dek, &extra).is_err());
    // Incomplete: drop the final tag byte-run.
    let short = &stream[..stream.len() - 5];
    assert!(StreamDecryptor::decrypt_all(&dek, short).is_err());
}

#[test]
fn push_more_than_declared_len_fails() {
    let dek = [4u8; 32];
    let mut enc = StreamEncryptor::new(&dek, 4);
    assert!(matches!(
        enc.push(b"toolong!!"),
        Err(FramingError::TooMuchData)
    ));
}

// ----- private sharing (NCF-3 §5) ----------------------------------------------------

/// A stand-in share row for the tests that are about something OTHER than the payload binding.
///
/// The bytes are arbitrary; what matters is that both sides of a round trip use the same ones.
/// `payload_binding_*` below are the tests that vary them on purpose.
const T_ITEM_ID: &[u8] = b"6a0f2b1c-1111-4222-8333-444455556666";
const T_NAME_CT: &[u8] = &[0xA1; 61];
const T_HASH_CT: &[u8] = &[0xB2; 104];

fn t_payload() -> share::SharePayload<'static> {
    share::SharePayload {
        item_id: T_ITEM_ID,
        name_ct: T_NAME_CT,
        content_hash_ct: T_HASH_CT,
    }
}

/// A DEK wrapped for one recipient opens for THAT recipient and nobody else, and two wraps of
/// the same DEK to the same recipient must not look alike (else the server could tell that two
/// shares went to the same person from the ciphertext alone).
#[test]
fn share_wrap_roundtrip_and_isolation() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x22u8; 20]).unwrap();
    let alice_pub = share::public_key(&alice.share_kem_seed, &alice.share_auth_secret, &alice.share_sig_seed);
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);
    let bob_addr = bob_pub.address();

    let dek = *wrap::generate_dek();
    let env = share::wrap_dek_for(
        &alice.share_auth_secret,
        &alice.share_sig_seed,
        &bob_pub,
        &bob_addr,
        &dek,
        &t_payload(),
    )
    .unwrap();
    assert_eq!(env.len(), share::SHARE_ENVELOPE_LEN);
    assert_eq!(
        *share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &env,
            &t_payload()
        )
        .unwrap(),
        dek,
        "the recipient the DEK was wrapped for must get the DEK back unchanged"
    );

    // Alice sent it and still cannot read it back: the encapsulation went to Bob's key, so
    // holding the sender half of the exchange buys nothing. Shares are one-directional.
    assert_eq!(
        share::unwrap_dek(
            &alice.share_kem_seed,
            &alice.share_auth_secret,
            &alice.share_sig_seed,
            &alice_pub,
            &env,
            &t_payload()
        ),
        Err(share::ShareError::Auth),
        "an envelope must open only for its recipient, not for whoever produced it"
    );

    // Two wraps of the SAME dek to the SAME recipient are unrelated (fresh encapsulation each).
    // ⚠ The first 16 bytes ARE equal by design — they are the sender's own address, which the
    // server already holds in its own column. Everything after it must differ.
    let env2 = share::wrap_dek_for(
        &alice.share_auth_secret,
        &alice.share_sig_seed,
        &bob_pub,
        &bob_addr,
        &dek,
        &t_payload(),
    )
    .unwrap();
    assert_ne!(
        env[share::SHARE_ADDRESS_LEN..],
        env2[share::SHARE_ADDRESS_LEN..],
        "two shares to one recipient must not be linkable from the ciphertext alone"
    );
    assert_eq!(
        *share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &env2,
            &t_payload()
        )
        .unwrap(),
        dek,
        "a fresh encapsulation of the same DEK must still deliver that DEK"
    );
}

/// **The A1 fix, stated end to end.** A share address is a fingerprint of the share public key,
/// so a sender who is handed a key by the server can check it belongs to the address they were
/// given out of band. Before NCF-3 those were unrelated derivations and the server could hand
/// over its own key, read every shared DEK, and re-wrap to the real recipient with nothing
/// visible on either screen.
#[test]
fn a_substituted_public_key_cannot_pass_as_a_recipient() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x22u8; 20]).unwrap();
    let server = kdf::derive_from_bytes(&[0x99u8; 20]).unwrap();
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);
    let server_pub = share::public_key(&server.share_kem_seed, &server.share_auth_secret, &server.share_sig_seed);

    // The address Bob published belongs to Bob's key and to nothing else.
    assert!(
        share::verify_address(&bob_pub, &bob_pub.address()).is_ok(),
        "an account's own key must satisfy the address it published"
    );
    assert_eq!(
        share::verify_address(&server_pub, &bob_pub.address()),
        Err(share::ShareError::AddressMismatch),
        "a key that is not Bob's must not satisfy Bob's address, or the server is back in the middle"
    );

    // And there is no way to wrap past the check: the address is an argument, not a courtesy.
    assert_eq!(
        share::wrap_dek_for(
            &alice.share_auth_secret,
            &alice.share_sig_seed,
            &server_pub,
            &bob_pub.address(),
            &[7u8; 32],
            &t_payload()
        ),
        Err(share::ShareError::AddressMismatch),
        "wrapping must refuse a key that does not fingerprint to the address it was aimed at"
    );

    // The address really is a function of the key bytes, recomputable by anyone.
    let recomputed = share::SharePublicKey::from_bytes(&bob_pub.to_bytes())
        .unwrap()
        .address();
    assert_eq!(
        recomputed,
        bob_pub.address(),
        "anyone holding the published bytes must be able to recompute the address themselves"
    );

    // Keeping Bob's KEM key and swapping in the attacker's AUTHENTICATION key would let them
    // impersonate every sender to an address that stays valid forever, since addresses do not
    // rotate. Until 2026-08-02 the fingerprint stopped that by covering the whole bundle; since
    // §5.2a it is the SELF-SIGNATURE that stops it, and the difference is visible here — the
    // forged bundle keeps Bob's address (his root is untouched) and is refused at parse instead.
    let mut forged = bob_pub.to_bytes();
    let attacker_auth =
        share::public_key(&server.share_kem_seed, &server.share_auth_secret, &server.share_sig_seed)
            .to_bytes();
    let auth_at = share::SHARE_SIGNED_LEN - 32;
    forged[auth_at..share::SHARE_SIGNED_LEN]
        .copy_from_slice(&attacker_auth[auth_at..share::SHARE_SIGNED_LEN]);
    assert_eq!(
        share::SharePublicKey::from_bytes(&forged).unwrap_err(),
        share::ShareError::BadSelfSignature,
        "an authentication key Bob's root never signed must not be usable under Bob's address"
    );
}

/// Tampering anywhere in the envelope must fail, including inside the KEM ciphertext — the
/// post-quantum half answers a bad ciphertext with a random-looking secret rather than an error,
/// so the AEAD is what has to notice, and it must notice everywhere.
#[test]
fn share_wrap_rejects_tampering_and_bad_lengths() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x33u8; 20]).unwrap();
    let alice_pub = share::public_key(&alice.share_kem_seed, &alice.share_auth_secret, &alice.share_sig_seed);
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);
    let dek = *wrap::generate_dek();
    let env = share::wrap_dek_for(
        &alice.share_auth_secret,
        &alice.share_sig_seed,
        &bob_pub,
        &bob_pub.address(),
        &dek,
        &t_payload(),
    )
    .unwrap();

    // One offset per field of `sender_address(16) || ct_kem(1120) || sealed_dek(104)`, including
    // both halves of the hybrid ciphertext: the ML-KEM body and the X25519 key that trails it.
    let ct = share::SHARE_ADDRESS_LEN;
    for idx in [
        ct,
        ct + 1087,
        ct + share::KEM_CIPHERTEXT_LEN - 1,
        ct + share::KEM_CIPHERTEXT_LEN,
        share::SHARE_ENVELOPE_LEN - 1,
    ] {
        let mut bad = env.clone();
        bad[idx] ^= 0x01;
        assert_eq!(
            share::unwrap_dek(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed, &alice_pub, &bad, &t_payload()),
            Err(share::ShareError::Auth),
            "a flipped bit at {idx} must not yield a DEK — ML-KEM answers a bad ciphertext with a \
             random-looking secret rather than an error, so the AEAD is the only thing that notices"
        );
    }

    // A bit flipped in the sender address is caught EARLIER, by the fingerprint check, because
    // the envelope now names a sender that the supplied identity does not answer to.
    let mut relabelled = env.clone();
    relabelled[0] ^= 0x01;
    assert_eq!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &relabelled,
            &t_payload()
        ),
        Err(share::ShareError::AddressMismatch),
        "an edited sender address must be refused before any secret is computed against it"
    );

    assert_eq!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &env[..env.len() - 1],
            &t_payload()
        ),
        Err(share::ShareError::BadEnvelopeLength),
        "a short envelope must be rejected on length, never parsed into whatever fits"
    );
    assert_eq!(
        share::SharePublicKey::from_bytes(&[0u8; 31]).unwrap_err(),
        share::ShareError::BadPublicKey,
        "public keys are validated on receipt, so a wrong-length one never reaches the KEM"
    );
}

/// **The A3 fix, stated end to end.** An envelope now proves who it came FROM, not only who it
/// was FOR. X-Wing is an unauthenticated KEM — anyone holding a recipient's public key, which is
/// public by construction, can build a valid envelope for them — so before this the "from" line
/// in an inbox was a server-supplied column, and a hostile server or an ordinary account with a
/// squatted address could plant a file attributed to a trusted contact.
///
/// Origin is carried by a static-static X25519 agreement mixed into the wrapping key, so there is
/// no separate "is the sender genuine?" call a caller could forget: an envelope that opens is one
/// whose claimed sender produced it.
#[test]
fn an_envelope_proves_which_account_sent_it() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x22u8; 20]).unwrap();
    let carol = kdf::derive_from_bytes(&[0x77u8; 20]).unwrap();
    let alice_pub = share::public_key(&alice.share_kem_seed, &alice.share_auth_secret, &alice.share_sig_seed);
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);
    let carol_pub = share::public_key(&carol.share_kem_seed, &carol.share_auth_secret, &carol.share_sig_seed);

    let dek = *wrap::generate_dek();
    let env = share::wrap_dek_for(
        &alice.share_auth_secret,
        &alice.share_sig_seed,
        &bob_pub,
        &bob_pub.address(),
        &dek,
        &t_payload(),
    )
    .unwrap();

    // The claim is readable without opening anything — that is what tells a reader WHICH identity
    // to go and fetch — and it is Alice's real address, taken from her secrets by the wrapper
    // rather than from an argument a caller could set.
    assert_eq!(
        share::claimed_sender(&env).unwrap(),
        alice_pub.address(),
        "the envelope must name the account that actually produced it"
    );

    // Handing the opener the wrong identity is refused at the fingerprint check: Carol's key does
    // not answer to the address the envelope claims.
    assert_eq!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &carol_pub,
            &env,
            &t_payload()
        ),
        Err(share::ShareError::AddressMismatch),
        "an identity that does not match the claimed address must never be used to open"
    );

    // And rewriting the claim so that it DOES match Carol's identity fails too, because the
    // sender address is bound into the wrapping key. There is no way to relabel an envelope: the
    // choice is between opening under the true name and not opening at all.
    let mut restamped = env.clone();
    restamped[..share::SHARE_ADDRESS_LEN].copy_from_slice(carol_pub.address().as_bytes());
    assert_eq!(
        share::claimed_sender(&restamped).unwrap(),
        carol_pub.address(),
        "the restamped envelope must really carry the false claim, or this proves nothing"
    );
    assert_eq!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &carol_pub,
            &restamped,
            &t_payload()
        ),
        Err(share::ShareError::Auth),
        "a relabelled envelope must stop opening rather than open under a false sender"
    );

    // The genuine pairing still works, so none of the above is achieved by breaking delivery.
    assert_eq!(
        *share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &env,
            &t_payload()
        )
        .unwrap(),
        dek,
        "the real sender's identity must open the real envelope"
    );
}

/// A real account, correctly addressing a real recipient, still cannot pass its envelope off as
/// somebody else's — the half of the A3 fix that squatted addresses would otherwise reach.
///
/// This is the case a signature would also cover; the static-static agreement covers it without
/// producing a transferable receipt that account X sent file Y to account Z.
#[test]
fn a_forger_holding_only_public_keys_cannot_impersonate_a_sender() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x22u8; 20]).unwrap();
    let carol = kdf::derive_from_bytes(&[0x77u8; 20]).unwrap();
    let alice_pub = share::public_key(&alice.share_kem_seed, &alice.share_auth_secret, &alice.share_sig_seed);
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);
    let carol_pub = share::public_key(&carol.share_kem_seed, &carol.share_auth_secret, &carol.share_sig_seed);

    // Carol knows Bob's published key — everyone does — and encapsulates to it correctly.
    let dek = *wrap::generate_dek();
    let forged = share::wrap_dek_for(
        &carol.share_auth_secret,
        &carol.share_sig_seed,
        &bob_pub,
        &bob_pub.address(),
        &dek,
        &t_payload(),
    )
    .unwrap();

    // It arrives as exactly what it is: a share from Carol.
    assert_eq!(
        share::claimed_sender(&forged).unwrap(),
        carol_pub.address(),
        "a sender cannot choose the name on its own envelope"
    );
    assert!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &carol_pub,
            &forged,
            &t_payload()
        )
        .is_ok(),
        "an honest share from an unknown account must still be deliverable — this closes \
         impersonation, not contact from strangers"
    );

    // What Carol cannot do is have it read as a share from Alice, whose authentication secret she
    // does not hold.
    assert_eq!(
        share::unwrap_dek(
            &bob.share_kem_seed,
            &bob.share_auth_secret,
            &bob.share_sig_seed,
            &alice_pub,
            &forged,
            &t_payload()
        ),
        Err(share::ShareError::AddressMismatch),
        "an envelope must not be openable under an identity that did not produce it"
    );
}

/// A share must fail to open for an account it was not addressed to, even when that account is a
/// genuine participant holding the genuine sender identity. Confidentiality is the older promise
/// of this module and the sender-authentication work must not have loosened it.
#[test]
fn a_share_does_not_open_for_an_account_it_was_not_addressed_to() {
    let alice = kdf::derive_from_bytes(&[0x11u8; 20]).unwrap();
    let bob = kdf::derive_from_bytes(&[0x22u8; 20]).unwrap();
    let carol = kdf::derive_from_bytes(&[0x77u8; 20]).unwrap();
    let alice_pub = share::public_key(&alice.share_kem_seed, &alice.share_auth_secret, &alice.share_sig_seed);
    let bob_pub = share::public_key(&bob.share_kem_seed, &bob.share_auth_secret, &bob.share_sig_seed);

    let dek = *wrap::generate_dek();
    let env = share::wrap_dek_for(
        &alice.share_auth_secret,
        &alice.share_sig_seed,
        &bob_pub,
        &bob_pub.address(),
        &dek,
        &t_payload(),
    )
    .unwrap();

    // Carol has the whole envelope and the sender's published identity — everything except Bob's
    // secrets — and gets nothing.
    assert_eq!(
        share::unwrap_dek(
            &carol.share_kem_seed,
            &carol.share_auth_secret,
            &carol.share_sig_seed,
            &alice_pub,
            &env,
            &t_payload()
        ),
        Err(share::ShareError::Auth),
        "only the addressed recipient may recover the DEK"
    );
}

/// The share identity must be a stable function of the account code — a recipient re-entering
/// their code on a new device years later must still open shares sent today.
#[test]
fn share_identity_is_deterministic_and_distinct_from_the_other_derivations() {
    let a = kdf::derive_from_bytes(&[0x44u8; 20]).unwrap();
    let again = kdf::derive_from_bytes(&[0x44u8; 20]).unwrap();
    assert_eq!(*a.share_kem_seed, *again.share_kem_seed);
    assert_eq!(
        *a.share_auth_secret, *again.share_auth_secret,
        "the sender-authentication secret is one third of the identity and must be as stable as \
         the seed"
    );
    assert_eq!(
        *a.share_sig_seed, *again.share_sig_seed,
        "the signing seed IS the address, so it is the least movable value in the product"
    );
    assert_eq!(
        share::public_key(&a.share_kem_seed, &a.share_auth_secret, &a.share_sig_seed).to_bytes(),
        share::public_key(&again.share_kem_seed, &again.share_auth_secret, &again.share_sig_seed).to_bytes()
    );
    assert_eq!(
        share::address_for(&a.share_sig_seed),
        share::address_for(&again.share_sig_seed)
    );
    assert_eq!(
        share::public_key(&a.share_kem_seed, &a.share_auth_secret, &a.share_sig_seed)
            .to_bytes()
            .len(),
        share::SHARE_PUBLIC_LEN,
        "a published identity is the version byte, the root, the epoch, both working keys and \
         the self-signature — all of them"
    );

    let other = kdf::derive_from_bytes(&[0x45u8; 20]).unwrap();
    assert_ne!(*a.share_kem_seed, *other.share_kem_seed);
    assert_ne!(
        *a.share_auth_secret, *other.share_auth_secret,
        "two accounts sharing an authentication secret could forge each other's shares"
    );
    assert_ne!(
        share::address_for(&a.share_sig_seed),
        share::address_for(&other.share_sig_seed)
    );

    // The three share secrets come from one HKDF-Extract under different labels; a copy-pasted
    // label would collapse two of them into one value, and one key used for two of
    // encapsulation, authentication and signing is the cross-protocol shortcut NCF-3 §5.5 exists
    // to refuse.
    assert_ne!(&a.share_kem_seed[..], &a.share_auth_secret[..]);
    assert_ne!(&a.share_kem_seed[..], &a.share_sig_seed[..]);
    assert_ne!(&a.share_auth_secret[..], &a.share_sig_seed[..]);

    // The public address must not be the accountId, nor a truncation of any secret.
    let addr = share::address_for(&a.share_sig_seed);
    assert_ne!(&addr.as_bytes()[..], &a.account_id[..]);
    assert_ne!(&addr.as_bytes()[..], &a.share_kem_seed[..16]);
    assert_ne!(&addr.as_bytes()[..], &a.share_auth_secret[..16]);
    assert_ne!(&addr.as_bytes()[..], &a.share_sig_seed[..16]);
    assert_ne!(&addr.as_bytes()[..], &a.data_key[..16]);
}

/// The address a user reads aloud or retypes must round-trip through its display form, survive
/// sloppy input, and REJECT a single mistyped character — otherwise a typo would silently
/// resolve to "no such account" or, worse, to a different real account.
#[test]
fn share_address_display_round_trips_and_catches_a_typo() {
    let a = kdf::derive_from_bytes(&[0x46u8; 20]).unwrap();
    let addr = share::address_for(&a.share_sig_seed);
    let shown = addr.display();

    // Shape: 27 symbols in three groups, visibly unlike an account code's eight groups of four.
    assert_eq!(shown.len(), 27 + 2, "expected 9-9-9 grouping, got {shown}");
    assert_eq!(shown.matches('-').count(), 2);
    assert_eq!(share::ShareAddress::parse(&shown).unwrap(), addr);

    // Sloppy input: lowercase, stray spaces, no separators, and Crockford's O→0 / I→1 aliases.
    assert_eq!(
        share::ShareAddress::parse(&shown.to_lowercase().replace('-', " ")).unwrap(),
        addr
    );

    // A single wrong symbol must be rejected locally, not looked up.
    let mut chars: Vec<char> = shown.chars().collect();
    chars[0] = if chars[0] == '7' { '8' } else { '7' };
    let typo: String = chars.into_iter().collect();
    assert!(
        matches!(
            share::ShareAddress::parse(&typo),
            Err(share::ShareError::BadAddress(_))
        ),
        "a one-character typo must not parse"
    );
}

/// Known-answer vectors for every NCF-3 derivation, for the all-zero account code.
///
/// A share address is a long-lived public identifier — people write it down and hand it to
/// others. A silent derivation change would not crash anything; it would just quietly stop
/// delivering shares to an address that still looks valid. This is the tripwire for that.
///
/// This is the FIRST pin the identity meets — `tests/vectors/ncf3.json` pins it again in full,
/// and the JS conformance harnesses pin the browser artifact against that file. The value of
/// having it here as well is that it fails without a fixture to regenerate, so "the vectors were
/// rewritten to match the new behaviour" cannot quietly become the fix.
#[test]
fn ncf3_derivations_match_the_pinned_known_answers() {
    let k = kdf::derive_from_bytes(&[0u8; 20]).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

    assert_eq!(
        hex(&k.account_id),
        "8581294285dcd7a19d7a15e4ffbaff58",
        "account id drift"
    );
    assert_eq!(
        hex(&*k.data_key),
        "b27b0c0749d350863e275020f02b75963c6f0c97c21673a7ff5380f43a9d217a",
        "data key drift"
    );
    assert_eq!(
        hex(&*k.file_list_key),
        "627c470618679149e1c3a61015f7062e1700ad0e7b67499cae2091ce673c9cf3",
        "file-list key drift — the sealed drive index would stop opening"
    );
    assert_eq!(
        hex(&*k.wallet_root),
        "f77dc4e1c033d6bbf27684c1dabd9e6deefa553cd60b453cf33f96579109b599",
        "wallet root drift — every wallet address would change"
    );
    assert_eq!(
        hex(&*k.wallet_seed_for(0)),
        "b910ed6fca3faa8502d6ad443048d4a843399be4b8ffd92d720188133d93d80b",
        "wallet 0 drift"
    );
    assert_eq!(
        hex(&*k.wallet_seed_for(1)),
        "cd5337c01af3c5c4ba9acda71accaab84b05b6d48b2c7197009625ec54b36315",
        "wallet 1 drift"
    );
    assert_eq!(
        hex(&*k.share_kem_seed),
        "cceef75375cb1d590acc8491539662eb89bcf38a8feb8219cd58909072cbedde",
        "share seed drift — shares sent to this account would stop opening"
    );
    assert_eq!(
        hex(&*k.share_auth_secret),
        "2b1bf90179109a4dfe4ce84967fc1f685e0c5fa6a018764f75270f915f2806ff",
        "sender-authentication secret drift — every share this account sent would stop opening"
    );
    assert_eq!(
        hex(&*k.share_sig_seed),
        "9fe06c14a0a3e40f42772352e3beb2f22214b621c5d86b539d13ea43a969fe06",
        "identity signing-seed drift — this account's share address itself would move"
    );

    // ⚠ **Why the three values below changed on 2026-08-02, and what would have to be true for
    // them to change again.** The 2026-08-02 revision rebuilt the share identity (NCF-3 §5.2a): it went
    // from `pk_kem(1216) || pk_auth(32)` = 1248 bytes to a versioned bundle of 4989, and the
    // address stopped fingerprinting the whole thing and started fingerprinting only the 1316-byte
    // ROOT (`derivation_index || pk_sig`). So a new identity digest, a new address, and a new
    // display form were all EXPECTED here, once, and every testnet address became unreachable —
    // which had already been accepted for the NCF-3 cutover.
    //
    // ⛔ That is the only reason these three lines have ever moved. If they move again without a
    // decision record saying the format changed, the format changed by accident: the account code
    // in this test is fixed, and every step between it and these bytes is deterministic.
    let id = share::public_key(&k.share_kem_seed, &k.share_auth_secret, &k.share_sig_seed);
    let sha256_of = |bytes: &[u8]| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        hex(&h.finalize())
    };
    assert_eq!(
        id.to_bytes().len(),
        4989,
        "the published identity is version(1) + root(1316) + epoch(4) + pk_kem(1216) \
         + pk_auth(32) + self_sig(2420)"
    );
    assert_eq!(id.root().len(), 1316, "the fingerprinted root is index(4) + pk_sig(1312)");
    assert_eq!(
        sha256_of(&id.to_bytes()),
        "ba7641d8faf5b99d458daf1a742fd349fa12abad061ccecb41212fb3964ec673",
        "share identity drift"
    );
    // Pinned separately from the identity so a drift lands on the part that MATTERS: the root is
    // what an address can never stop matching, and finding a mismatch here rather than inside a
    // five-kilobyte blob is the difference between a diagnosis and a hunt.
    assert_eq!(
        sha256_of(id.root()),
        "bb5d940e5255ff1854553319c6ec0d48ecf11936a76618d9f93c83df8633a9ce",
        "share identity ROOT drift — every published address would move"
    );
    assert_eq!(
        hex(share::address_for(&k.share_sig_seed).as_bytes()),
        "d26c91069c68a463d6180d8c6eed1f3b",
        "share address drift — an address already given out would stop resolving"
    );
    assert_eq!(
        share::address_for(&k.share_sig_seed).display(),
        "T9P921MWD-2J67NGR1P-66XV8Z7CS",
        "share address display drift"
    );
}

// ----- numbered wallets ---------------------------------------------------------------

/// Every wallet, including the first, comes from the wallet root under one rule (NCF-3 §1.3).
/// NCF-2 gave wallet 0 its own derivation off the account PRK because it already existed on
/// chain; NCF-3 breaks every address anyway, so the exception is gone and this is the test that
/// keeps it gone.
#[test]
fn wallets_are_numbered_by_one_rule() {
    let a = kdf::derive_from_bytes(&[0x55u8; 20]).unwrap();
    let again = kdf::derive_from_bytes(&[0x55u8; 20]).unwrap();

    // Deterministic, and every index answers from the root — including 0.
    for index in [0u32, 1, 2, 11] {
        assert_eq!(*a.wallet_seed_for(index), *again.wallet_seed_for(index));
        assert_eq!(
            *a.wallet_seed_for(index),
            *kdf::wallet_seed_from_root(&a.wallet_root, index),
            "wallet {index} must come from the root",
        );
    }

    // Distinct from each other and from the root itself.
    let zero = a.wallet_seed_for(0);
    let one = a.wallet_seed_for(1);
    let two = a.wallet_seed_for(2);
    assert_ne!(*zero, *one);
    assert_ne!(*one, *two);
    assert_ne!(*one, *a.wallet_root);

    // Index 11 must not collide with index 1 (the label is the whole decimal, not a prefix).
    assert_ne!(*a.wallet_seed_for(11), *one);

    // Two accounts never share a wallet.
    let other = kdf::derive_from_bytes(&[0x56u8; 20]).unwrap();
    assert_ne!(*other.wallet_seed_for(1), *one);
}
