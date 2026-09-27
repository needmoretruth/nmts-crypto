//! The forms a recovery list gained after NRM-2, each with its refusals: the own-quilt placement
//! (NRM-3), padding (NRM-4) and Filecoin parts (NRM-5). `docs/RECOVERY-MANIFEST.md` §2.2 · §2.4 · §6.
//!
//! ⛔ ITS OWN FILE BECAUSE `api.rs` HAS A CEILING. `check:size` does not let a file over 700 lines
//!    grow, and NRM-5 did not fit beside the rest, so the NRM-3 and NRM-4 tests moved here with it —
//!    each form's fixture test sits beside its refusals, and the three versions sit together.

use nmts_crypto::manifest::{
    self, FilecoinProblem, ManifestError, Quilt, RecoveryManifest, MANIFEST_VERSION_WITH_FILECOIN,
};

/// A fixture's JSON with the human-readable `_comment` key stripped (the same helper `api.rs` has:
/// serde ignores keys it does not know, so struct equality alone would let a stray key through).
fn fixture_json(raw: &[u8]) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(raw).expect("fixture must be JSON");
    value
        .as_object_mut()
        .expect("fixture is an object")
        .remove("_comment");
    value
}

/// The NRM-4 fixture parses, and the two numbers a padded part carries stay apart.
///
/// ⛔ What would make this test pass while the format was broken: reading `padded_len` as the
///    part's contribution. So it asserts the SUM — the parts still add up to `size` — which is
///    the invariant padding must not cost, and the one that catches an edited `size`.
#[test]
fn manifest_reads_the_padded_nrm4_fixture() {
    let raw = include_bytes!("vectors/nrm4-sample.json");
    let parsed = RecoveryManifest::from_json(raw).expect("the NRM-4 fixture must parse");
    assert_eq!(parsed.v, 4);

    let small = &parsed.items[0];
    assert_eq!(small.size, 12);
    assert_eq!(small.parts[0].plaintext_len, 12);
    assert_eq!(small.parts[0].padded_len, Some(1_048_576));
    assert_eq!(small.parts[0].stream_plaintext_len(), 1_048_576);
    assert!(
        small.parts_add_up(),
        "padding must not disturb the size arithmetic"
    );

    let big = &parsed.items[1];
    // The full part is untouched and answers the same for both numbers; only the tail is padded.
    assert_eq!(big.parts[0].padded_len, None);
    assert_eq!(big.parts[0].stream_plaintext_len(), 1_073_741_824);
    assert_eq!(big.parts[1].padded_len, Some(4_194_304));
    assert!(big.parts_add_up());

    let emitted = parsed.to_json().unwrap();
    assert_eq!(fixture_json(&emitted), fixture_json(raw));
}

/// ⛔ Every padded document a reader would have to guess about is refused, on BOTH paths.
///
/// The write path matters as much as the read path here: this crate is what the browser compiles
/// to WASM, so a refusal on `to_json` is what stops a contradictory list being sealed and handed
/// to somebody as their only copy.
#[test]
fn manifest_refuses_padding_that_contradicts_itself() {
    let doc = |v: u32, part: &str| {
        format!(
            r#"{{"v":{v},"seq":1,"prev_manifest_blob_id":null,
            "generated_at":"2026-08-18T00:00:00Z","account_id":"x","items":[
            {{"id":"i","name":"n","path":"/","size":4,"dek":"d","kind":"file",
              "parts":[{part}]}}]}}"#
        )
        .into_bytes()
    };
    let padded = r#"{"part_index":0,"blob_id":"a","plaintext_len":4,"padded_len":64}"#;

    // 1. The form needs its version. A v3 document using it was altered, not written early.
    assert!(matches!(
        RecoveryManifest::from_json(&doc(3, padded)),
        Err(manifest::ManifestError::PaddingTooOld { .. })
    ));

    // 2. Equal is not padding — it is written as absence, so that two identical lists cannot
    //    differ in their canonical bytes.
    assert!(matches!(
        RecoveryManifest::from_json(&doc(
            4,
            r#"{"part_index":0,"blob_id":"a","plaintext_len":4,"padded_len":4}"#
        )),
        Err(manifest::ManifestError::PaddingNotLarger { .. })
    ));

    // 3. Smaller is a stream that could not have held the part at all.
    assert!(matches!(
        RecoveryManifest::from_json(&doc(
            4,
            r#"{"part_index":0,"blob_id":"a","plaintext_len":4,"padded_len":3}"#
        )),
        Err(manifest::ManifestError::PaddingNotLarger { .. })
    ));

    // 4. The same three refusals on the way OUT, from structs rather than from JSON.
    let mut m = RecoveryManifest::from_json(&doc(4, padded)).expect("the honest form must parse");
    m.v = 3;
    assert!(matches!(
        m.to_json(),
        Err(manifest::ManifestError::PaddingTooOld { .. })
    ));
    m.v = 4;
    m.items[0].parts[0].padded_len = Some(4);
    assert!(matches!(
        m.to_json(),
        Err(manifest::ManifestError::PaddingNotLarger { .. })
    ));
}

/// The NRM-3 fixture parses, and BOTH placements in it resolve to what they say they are.
///
/// Reading only one of the two is the failure worth guarding: a recovery would return the older
/// files and quietly lose the ones from the very upload the list rode along with.
#[test]
fn manifest_reads_both_placements_of_the_nrm3_fixture() {
    let raw = include_bytes!("vectors/nrm3-sample.json");
    let parsed = RecoveryManifest::from_json(raw).expect("the NRM-3 fixture must parse");
    assert_eq!(parsed.v, 3);

    let placements: Vec<_> = parsed
        .items
        .iter()
        .map(|i| i.quilt.as_ref().and_then(Quilt::placement))
        .collect();
    assert_eq!(
        placements[0],
        Some(manifest::Placement::Absolute {
            quilt_blob_id: "quiltX",
            patch_id: "patch7"
        })
    );
    assert_eq!(
        placements[1],
        Some(manifest::Placement::OwnQuilt {
            identifier: "55555555-5555-4555-8555-555555555555"
        })
    );
    // The own-quilt item names no blob, and that absence is the document being honest rather
    // than incomplete: the blob did not exist yet when it was written.
    assert!(parsed.items[1].parts[0].blob_id.is_none());

    let emitted = parsed.to_json().unwrap();
    assert_eq!(fixture_json(&emitted), fixture_json(raw));
}

/// Every way of writing a placement that a reader would have to guess about is refused.
///
/// Each case is a document that could be produced by an editing mistake or by tampering, and in
/// every one of them the plausible guess fetches the wrong bytes. Refusing costs a person an
/// error message; guessing costs them the file and tells them it worked.
#[test]
fn manifest_refuses_every_ambiguous_placement() {
    let doc = |v: u32, parts: &str, quilt: &str| {
        format!(
            r#"{{"v":{v},"seq":1,"prev_manifest_blob_id":null,
            "generated_at":"2026-08-17T00:00:00Z","account_id":"x","items":[
            {{"id":"i","name":"n","path":"/","size":1,"dek":"d","kind":"file",
              "parts":[{parts}],"quilt":{quilt}}}]}}"#
        )
        .into_bytes()
    };
    let one_part = r#"{"part_index":0,"plaintext_len":1}"#;
    let one_part_with_blob = r#"{"part_index":0,"blob_id":"a","plaintext_len":1}"#;

    // Half an absolute placement: a patch id with no quilt to look for it in.
    let err = RecoveryManifest::from_json(&doc(3, one_part_with_blob, r#"{"patch_id":"p"}"#))
        .unwrap_err();
    assert!(
        matches!(err, ManifestError::QuiltFormUnclear { .. }),
        "{err}"
    );

    // Both forms at once — which one is the reader supposed to believe?
    let both = r#"{"quilt_blob_id":"q","patch_id":"p","identifier":"x"}"#;
    let err = RecoveryManifest::from_json(&doc(3, one_part_with_blob, both)).unwrap_err();
    assert!(
        matches!(err, ManifestError::QuiltFormUnclear { .. }),
        "{err}"
    );

    // The v3 form inside a document that calls itself v2: an altered document, not an old one.
    let err = RecoveryManifest::from_json(&doc(2, one_part, r#"{"identifier":"x"}"#)).unwrap_err();
    assert!(
        matches!(err, ManifestError::OwnQuiltTooOld { v: 2, .. }),
        "{err}"
    );

    // Own-quilt AND a blob id: the form means "the blob is not named yet", so naming one is a
    // contradiction, and picking either half would be inventing the answer.
    let err = RecoveryManifest::from_json(&doc(3, one_part_with_blob, r#"{"identifier":"x"}"#))
        .unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::OwnQuiltPartsWrong {
                blob_id_present: true,
                ..
            }
        ),
        "{err}"
    );

    // Own-quilt across two parts: a quilted item is one patch in one blob.
    let two = format!("{one_part},{}", r#"{"part_index":1,"plaintext_len":0}"#);
    let err = RecoveryManifest::from_json(&doc(3, &two, r#"{"identifier":"x"}"#)).unwrap_err();
    assert!(
        matches!(err, ManifestError::OwnQuiltPartsWrong { parts: 2, .. }),
        "{err}"
    );

    // A part with no blob id and no own-quilt placement has no address at all.
    let err = RecoveryManifest::from_json(&doc(3, one_part, "null")).unwrap_err();
    assert!(
        matches!(err, ManifestError::BlobIdMissing { position: 0, .. }),
        "{err}"
    );
}

// ----- NRM-5: Filecoin parts ----------------------------------------------------------------

const CID: &str = "bafkzcibd5adqy3m4o5lm6dnp2wzflzkkmcesjj2ad3r6l3llemvbei4fkusi5zy5";

/// One copy, as JSON, with any field overridden.
fn copy(provider: &str, url: &str) -> String {
    format!(
        r#"{{"provider_id":"{provider}","data_set_id":"301","piece_id":"0","retrieval_url":"{url}"}}"#
    )
}

/// A one-item, one-part document whose part is `part` (JSON), declaring `v`, optionally quilted.
fn doc(v: u32, part: &str, quilt: &str) -> Vec<u8> {
    format!(
        r#"{{"v":{v},"seq":1,"prev_manifest_blob_id":null,
        "generated_at":"2026-09-24T00:00:00Z","account_id":"x","items":[
        {{"id":"i","name":"n","path":"/","size":4,"dek":"d","kind":"file",
          "parts":[{part}],"quilt":{quilt}}}]}}"#
    )
    .into_bytes()
}

/// A Filecoin part that breaks no rule, with its pieces swappable one at a time.
fn filecoin_part(blob: &str, chain: Option<&str>, copies: Option<&str>) -> String {
    let mut p =
        format!(r#"{{"part_index":0,"blob_id":"{blob}","plaintext_len":4,"network":"filecoin""#);
    if let Some(c) = chain {
        p.push_str(&format!(r#","chain":"{c}""#));
    }
    if let Some(c) = copies {
        p.push_str(&format!(r#","copies":[{c}]"#));
    }
    p.push('}');
    p
}

fn good_copies() -> String {
    format!(
        "{},{}",
        copy("7", &format!("https://sp-a.example/piece/{CID}")),
        copy("11", &format!("https://sp-b.example:8443/pdp/piece/{CID}"))
    )
}

fn problem(bytes: &[u8]) -> FilecoinProblem {
    match RecoveryManifest::from_json(bytes) {
        Err(ManifestError::Filecoin { problem, .. }) => problem,
        other => panic!("expected a Filecoin refusal, got {other:?}"),
    }
}

/// The NRM-5 fixture parses, every Filecoin field lands where it says, and it comes back out as
/// the same document.
///
/// ⛔ What would make this pass while the format was broken: reading the copies as a set. The
///    order is the order a reader tries the companies in, so it is asserted element by element.
#[test]
fn manifest_reads_the_filecoin_nrm5_fixture() {
    let raw = include_bytes!("vectors/nrm5-sample.json");
    let parsed = RecoveryManifest::from_json(raw).expect("the NRM-5 fixture must parse");
    assert_eq!(parsed.v, 5);
    assert_eq!(manifest::minimum_version(&parsed.items), 5);

    // A Walrus part is untouched by NRM-5 and carries neither new field.
    let walrus = &parsed.items[0].parts[0];
    assert_eq!(walrus.network_name(), "walrus");
    assert_eq!(
        (walrus.chain.as_deref(), walrus.filecoin_copies().len()),
        (None, 0)
    );

    let heavy = &parsed.items[1].parts[0];
    assert_eq!(heavy.network_name(), "filecoin");
    assert_eq!(heavy.chain.as_deref(), Some("calibration"));
    let providers: Vec<&str> = heavy
        .filecoin_copies()
        .iter()
        .map(|c| c.provider_id.as_str())
        .collect();
    assert_eq!(providers, ["7", "11"]);
    let first = &heavy.filecoin_copies()[0];
    assert_eq!(
        (first.data_set_id.as_str(), first.piece_id.as_str()),
        ("301", "0")
    );
    assert!(first
        .retrieval_url
        .ends_with(heavy.blob_id.as_deref().expect("a piece id")));

    // Two parts, each its own piece, each kept at the same two companies under its own number.
    let two = &parsed.items[2];
    assert_eq!(two.parts.len(), 2);
    assert!(two
        .parts
        .iter()
        .all(|p| p.chain.as_deref() == Some("mainnet")));
    assert_eq!(two.parts[1].filecoin_copies()[0].piece_id, "13");
    assert!(parsed.items.iter().all(|i| i.parts_add_up()));

    let emitted = parsed.to_json().unwrap();
    assert_eq!(fixture_json(&emitted), fixture_json(raw));
}

/// ⛔ A list with no Filecoin part still claims only the version its contents need, so every
///    recovery program already published goes on opening it.
#[test]
fn a_list_without_a_filecoin_part_does_not_claim_nrm5() {
    let parsed = RecoveryManifest::from_json(include_bytes!("vectors/nrm5-sample.json")).unwrap();
    assert_eq!(manifest::minimum_version(&parsed.items[..1]), 2);
    assert_eq!(
        manifest::minimum_version(&parsed.items[1..2]),
        MANIFEST_VERSION_WITH_FILECOIN
    );
    // And declaring v5 without needing it is still a document, not a contradiction.
    let walrus_only = doc(
        5,
        r#"{"part_index":0,"blob_id":"a","plaintext_len":4,"network":"walrus"}"#,
        "null",
    );
    assert!(RecoveryManifest::from_json(&walrus_only).is_ok());
}

/// ⛔ Every Filecoin form a reader would have to guess about is refused.
///
/// Each case changes ONE thing in a part that is otherwise valid, so a refusal here is about that
/// thing and not the accident of another.
#[test]
fn manifest_refuses_every_filecoin_form_it_would_have_to_guess_about() {
    let copies = good_copies();
    let good = filecoin_part(CID, Some("calibration"), Some(&copies));
    assert!(
        RecoveryManifest::from_json(&doc(5, &good, "null")).is_ok(),
        "the control must parse"
    );

    // The version first: in a v4 document each of these is an alteration, not an early writer.
    assert_eq!(
        problem(&doc(4, &good, "null")),
        FilecoinProblem::TooOld { v: 4 }
    );
    let walrus_with = |field: &str| {
        format!(r#"{{"part_index":0,"blob_id":"a","plaintext_len":4,"network":"walrus",{field}}}"#)
    };
    let with_copies = walrus_with(&format!(r#""copies":[{copies}]"#));
    let with_chain = walrus_with(r#""chain":"mainnet""#);
    assert_eq!(
        problem(&doc(4, &with_copies, "null")),
        FilecoinProblem::TooOld { v: 4 }
    );
    assert_eq!(
        problem(&doc(2, &with_chain, "null")),
        FilecoinProblem::TooOld { v: 2 }
    );
    // Filecoin's fields on a part that is not on Filecoin.
    assert_eq!(
        problem(&doc(5, &with_copies, "null")),
        FilecoinProblem::NotFilecoin
    );
    assert_eq!(
        problem(&doc(5, &with_chain, "null")),
        FilecoinProblem::NotFilecoin
    );

    // The chain.
    let no_chain = filecoin_part(CID, None, Some(&copies));
    assert_eq!(
        problem(&doc(5, &no_chain, "null")),
        FilecoinProblem::ChainMissing
    );
    let testnet = filecoin_part(CID, Some("testnet"), Some(&copies));
    assert_eq!(
        problem(&doc(5, &testnet, "null")),
        FilecoinProblem::ChainUnknown("testnet".into())
    );

    // The copies: none, an empty list, and more than the ceiling.
    let none = filecoin_part(CID, Some("mainnet"), None);
    assert_eq!(
        problem(&doc(5, &none, "null")),
        FilecoinProblem::CopiesMissing
    );
    let empty = filecoin_part(CID, Some("mainnet"), Some(""));
    assert_eq!(
        problem(&doc(5, &empty, "null")),
        FilecoinProblem::CopiesCount(0)
    );
    let one = copy("7", &format!("https://sp-a.example/piece/{CID}"));
    let thirteen = [one.as_str(); 13].join(",");
    let many = filecoin_part(CID, Some("mainnet"), Some(&thirteen));
    assert_eq!(
        problem(&doc(5, &many, "null")),
        FilecoinProblem::CopiesCount(13)
    );
    let twelve = [one.as_str(); 12].join(",");
    assert!(RecoveryManifest::from_json(&doc(
        5,
        &filecoin_part(CID, Some("mainnet"), Some(&twelve)),
        "null"
    ))
    .is_ok());

    // The piece id: a Walrus-style id, a path, and the right prefix in the wrong case.
    for bad in ["blobA", "bafkzcib/../x", "BAFKZCIBD5ADQY", "bafkzcib"] {
        let url = format!("https://sp-a.example/piece/{bad}");
        let part = filecoin_part(bad, Some("mainnet"), Some(&copy("7", &url)));
        assert_eq!(
            problem(&doc(5, &part, "null")),
            FilecoinProblem::PieceCidMalformed,
            "{bad}"
        );
    }

    // The numbers: canonical decimal uint256 only. 2²⁵⁶ − 1 is the largest that passes.
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    let url = format!("https://sp-a.example/piece/{CID}");
    assert!(RecoveryManifest::from_json(&doc(
        5,
        &filecoin_part(CID, Some("mainnet"), Some(&copy(max, &url))),
        "null"
    ))
    .is_ok());
    for bad in ["", "07", "-1", "1.0", "0x1", " 1", over] {
        let part = filecoin_part(CID, Some("mainnet"), Some(&copy(bad, &url)));
        assert_eq!(
            problem(&doc(5, &part, "null")),
            FilecoinProblem::NumberMalformed {
                copy: 0,
                field: "provider_id"
            },
            "{bad:?}"
        );
    }
    let bad_piece = copy("7", &url).replace(r#""piece_id":"0""#, r#""piece_id":"00""#);
    assert_eq!(
        problem(&doc(
            5,
            &filecoin_part(CID, Some("mainnet"), Some(&bad_piece)),
            "null"
        )),
        FilecoinProblem::NumberMalformed {
            copy: 0,
            field: "piece_id"
        }
    );

    // The address: https only, a host, this piece and no other, nothing after it.
    for bad in [
        format!("http://sp-a.example/piece/{CID}"),
        format!("https:///piece/{CID}"),
        format!("https://sp-a.example/piece/{CID}x"),
        format!("https://sp-a.example/{CID}"),
        format!("https://sp-a.example/piece/{CID}?a=1"),
        format!("https://sp-a.example/pie ce/piece/{CID}"),
    ] {
        let two = format!("{},{}", copy("7", &url), copy("11", &bad));
        let part = filecoin_part(CID, Some("mainnet"), Some(&two));
        assert_eq!(
            problem(&doc(5, &part, "null")),
            FilecoinProblem::RetrievalUrlWrong { copy: 1 },
            "{bad}"
        );
    }

    // A piece is stored on its own; a quilt is Walrus's.
    let quilt = r#"{"quilt_blob_id":"q","patch_id":"p"}"#;
    assert_eq!(problem(&doc(5, &good, quilt)), FilecoinProblem::InQuilt);
}

/// ⛔ The same refusals on the way OUT. This crate is what the browser compiles to WASM, so a
///    refusal on `to_json` is what stops a contradictory list being sealed and handed to somebody
///    as their only copy.
#[test]
fn a_filecoin_form_that_would_be_refused_cannot_be_written() {
    let copies = good_copies();
    let good = filecoin_part(CID, Some("calibration"), Some(&copies));
    let mut m = RecoveryManifest::from_json(&doc(5, &good, "null")).expect("the honest form");
    m.v = 4;
    assert!(matches!(
        m.to_json(),
        Err(ManifestError::Filecoin {
            problem: FilecoinProblem::TooOld { v: 4 },
            ..
        })
    ));
    m.v = 5;
    m.items[0].parts[0].network = Some("walrus".into());
    assert!(matches!(
        m.to_json(),
        Err(ManifestError::Filecoin {
            problem: FilecoinProblem::NotFilecoin,
            ..
        })
    ));
    m.items[0].parts[0].network = Some("filecoin".into());
    m.items[0].parts[0].copies = Some(Vec::new());
    assert!(
        m.encrypt(&[0x21u8; 32]).is_err(),
        "nothing is sealed past the refusal"
    );
}
