//! Unit tests for [`crate::opener`] — the opener layer (NCF-3 §1.7).
//!
//! ⛔ ITS OWN FILE BECAUSE `opener.rs` HAS A CEILING. `check:size` holds Rust files to 700 lines
//!    and the module crossed it with its tests inside. Nothing about the tests moved: they are
//!    still `mod tests` inside the module (`#[cfg(test)] #[path = "opener_tests.rs"] mod tests;`),
//!    so `super::*` reaches the private helpers exactly as before — which is the point, since the
//!    seal body and the two canonicalisers are private and a test outside the module could not
//!    see them.

use super::*;

/// A fixed, canonical Sui address for the tests: `0x` + 64 `a`.
const ADDRESS_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// One serialized Ed25519 signature over `pure`.
fn serialized(flag: u8, pure: &[u8; PURE_SIGNATURE_LEN], pk_len: usize) -> Vec<u8> {
    let mut out = vec![flag];
    out.extend_from_slice(pure);
    out.extend(std::iter::repeat_n(0x11u8, pk_len));
    out
}

fn pure_a() -> [u8; PURE_SIGNATURE_LEN] {
    core::array::from_fn(|i| i as u8)
}

/// ⛔ THE MESSAGE, WRITTEN OUT. Asserted as a whole literal rather than assembled from the
/// pieces the function uses — the latter only proves the function agrees with itself. This
/// layer is not frozen, but a message that moves without the slots being re-wrapped locks
/// every wallet out of its account, and the only symptom is a sign-in that stops working.
#[test]
fn the_message_is_exactly_these_bytes() {
    let expected = "NMTS wallet sign-in\n\
         \n\
         Signing this message lets this wallet open your NMTS account.\n\
         Sign it only on nmts.me or in a tool you trust with your files.\n\
         Anyone who gets this signature can open your files\n\
         until you remove this wallet from the account.\n\
         \n\
         Wallet: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
         Account: 1\n\
         Version: 1";
    let got = opener_message(ADDRESS_A, 1, None).expect("canonical address, account >= 1");
    assert_eq!(String::from_utf8(got.clone()).expect("ASCII"), expected);
    assert!(got.is_ascii(), "the message must be ASCII");
    assert!(!got.ends_with(b"\n"), "no trailing newline");
    assert_eq!(got.iter().filter(|&&b| b == b'\n').count(), 9, "LF count");
    assert!(!got.contains(&b'\r'), "LF endings only, never CRLF");
    // The heading must differ from the side road's, or one signature serves two purposes.
    assert!(got.starts_with(b"NMTS wallet sign-in\n"));
}

#[test]
fn the_app_line_sits_between_account_and_version() {
    let with = opener_message(ADDRESS_A, 7, Some("example.com")).unwrap();
    let text = String::from_utf8(with.clone()).unwrap();
    assert!(text.ends_with("\nAccount: 7\nApp: example.com\nVersion: 1"));
    assert_eq!(with.iter().filter(|&&b| b == b'\n').count(), 10);
    // Present or absent is a different message, and therefore a different slot.
    assert_ne!(with, opener_message(ADDRESS_A, 7, None).unwrap());
}

#[test]
fn near_miss_inputs_are_refused_and_never_repaired() {
    let hex64 = &ADDRESS_A[2..];
    for bad in [
        "",
        "0x",
        hex64,                                  // no 0x
        &format!("0X{hex64}"),                  // capital X
        &format!("0x{}", hex64.to_uppercase()), // capital hex
        &format!("0x{hex64}b"),                 // 65 hex characters
        &format!("0x{}", &hex64[1..]),          // 63 hex characters
        &format!(" 0x{hex64}"),                 // leading space
        &format!("0x{hex64}\n"),                // trailing newline
        &format!("0x{}g", &hex64[1..]),         // not hex
    ] {
        assert_eq!(
            opener_message(bad, 1, None),
            Err(OpenerRefusal::AddressNotCanonical),
            "{bad:?} must be refused, not normalised"
        );
    }
    assert_eq!(
        opener_message(ADDRESS_A, 0, None),
        Err(OpenerRefusal::AccountZero)
    );
    // ⛔ The newline cases are the review's 1-A3: a caller that could smuggle one would be
    //    writing the wallet popup's text.
    for bad in [
        "",
        "-a",
        "a-",
        ".a",
        "a.",
        "Example",
        "a b",
        "a\nWallet: 0x0",
        &"a".repeat(APP_MAX_LEN + 1),
    ] {
        assert_eq!(
            opener_message(ADDRESS_A, 1, Some(bad)),
            Err(OpenerRefusal::AppNotCanonical),
            "{bad:?} must be refused"
        );
    }
    for good in [
        "a",
        "1",
        "example.com",
        "my-app.2",
        &"a".repeat(APP_MAX_LEN),
    ] {
        assert!(opener_message(ADDRESS_A, 1, Some(good)).is_ok(), "{good:?}");
    }
}

#[test]
fn the_account_number_is_decimal_and_starts_at_one() {
    let one = opener_message(ADDRESS_A, 1, None).unwrap();
    let twelve = opener_message(ADDRESS_A, 12, None).unwrap();
    assert!(String::from_utf8(twelve)
        .unwrap()
        .contains("\nAccount: 12\n"));
    assert!(!String::from_utf8(one).unwrap().contains("Account: 01"));
    // u32 covers the spec's ceiling exactly; the top value is a message like any other.
    assert!(opener_message(ADDRESS_A, u32::MAX, None).is_ok());
}

#[test]
fn only_the_three_allowed_schemes_are_accepted() {
    let pure = pure_a();
    for (flag, pk_len) in [
        (FLAG_ED25519, 32),
        (FLAG_SECP256K1, 33),
        (FLAG_SECP256R1, 33),
    ] {
        let got = pure_signature_of(&serialized(flag, &pure, pk_len)).expect("accepted");
        assert_eq!(*got, pure, "flag 0x{flag:02x} must yield bytes 1..65");
    }

    assert_eq!(pure_signature_of(&[]), Err(OpenerRefusal::Empty));
    assert_eq!(
        pure_signature_of(&serialized(FLAG_MULTISIG, &pure, 32)),
        Err(OpenerRefusal::Multisig)
    );
    assert_eq!(
        pure_signature_of(&serialized(FLAG_ZKLOGIN, &pure, 32)),
        Err(OpenerRefusal::ZkLogin)
    );
    assert_eq!(
        pure_signature_of(&serialized(FLAG_PASSKEY, &pure, 32)),
        Err(OpenerRefusal::Passkey)
    );
    // ⛔ Allow list, not deny list: 0x04 and 0xff have never been judged, so they are refused.
    assert_eq!(
        pure_signature_of(&serialized(0x04, &pure, 32)),
        Err(OpenerRefusal::UnknownScheme { flag: 0x04 })
    );
    assert_eq!(
        pure_signature_of(&serialized(0xff, &pure, 32)),
        Err(OpenerRefusal::UnknownScheme { flag: 0xff })
    );
    // Accepted flag, wrong length — refused rather than sliced.
    assert_eq!(
        pure_signature_of(&serialized(FLAG_ED25519, &pure, 33)),
        Err(OpenerRefusal::WrongLength {
            flag: FLAG_ED25519,
            expected: ED25519_SERIALIZED_LEN,
            got: ECDSA_SERIALIZED_LEN,
        })
    );
    assert_eq!(
        pure_signature_of(&serialized(FLAG_SECP256K1, &pure, 32)),
        Err(OpenerRefusal::WrongLength {
            flag: FLAG_SECP256K1,
            expected: ECDSA_SERIALIZED_LEN,
            got: ED25519_SERIALIZED_LEN,
        })
    );
    assert_eq!(
        pure_signature_of(&[FLAG_ED25519]),
        Err(OpenerRefusal::WrongLength {
            flag: FLAG_ED25519,
            expected: ED25519_SERIALIZED_LEN,
            got: 1,
        })
    );
}

#[test]
fn every_refusal_reads_differently() {
    let all = [
        OpenerRefusal::AddressNotCanonical,
        OpenerRefusal::AccountZero,
        OpenerRefusal::AppNotCanonical,
        OpenerRefusal::Empty,
        OpenerRefusal::Multisig,
        OpenerRefusal::ZkLogin,
        OpenerRefusal::Passkey,
        OpenerRefusal::UnknownScheme { flag: 0x04 },
        OpenerRefusal::WrongLength {
            flag: FLAG_ED25519,
            expected: ED25519_SERIALIZED_LEN,
            got: 1,
        },
        OpenerRefusal::SlotLength { got: 3 },
        OpenerRefusal::SlotVersion { version: 0x02 },
        OpenerRefusal::SlotKind { kind: 0x09 },
        OpenerRefusal::DoesNotOpen,
    ];
    let mut seen: Vec<String> = all.iter().map(|e| e.to_string()).collect();
    seen.sort();
    let count = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), count, "two refusals share a sentence");
}

#[test]
fn a_slot_round_trips_and_only_under_its_own_signature() {
    let key: [u8; ACCOUNT_CODE_BYTES] = core::array::from_fn(|i| 0x80 ^ i as u8);
    let sig = serialized(FLAG_ED25519, &pure_a(), 32);
    let opener = opener_from_signature(&sig).expect("accepted");

    let slot = opener.seal(&key).expect("known kind");
    assert_eq!(slot.len(), SLOT_LEN);
    assert_eq!(slot[0], SLOT_VERSION);
    assert_eq!(slot[1], KIND_WALLET_SIGNATURE);
    assert_eq!(*opener.open(&slot).expect("opens"), key);

    // A fresh nonce every time, so two seals of one key are different bytes.
    assert_ne!(slot, opener.seal(&key).unwrap());

    // ⛔ The bytes are opaque: the NMTS key must not appear anywhere in the slot.
    assert!(!slot.windows(key.len()).any(|w| w == key));

    // Another signature — one bit apart — opens neither the slot nor the locator.
    let mut other_pure = pure_a();
    other_pure[63] ^= 0x01;
    let other = opener_from_signature(&serialized(FLAG_ED25519, &other_pure, 32)).unwrap();
    assert_ne!(other.locator(), opener.locator());
    assert_eq!(other.open(&slot), Err(OpenerRefusal::DoesNotOpen));
}

#[test]
fn a_tampered_slot_never_opens() {
    let key = [0x5au8; ACCOUNT_CODE_BYTES];
    let opener = opener_from_signature(&serialized(FLAG_ED25519, &pure_a(), 32)).unwrap();
    let slot = opener.seal(&key).unwrap();

    // Length, version and kind are each answered on their own terms.
    assert_eq!(
        opener.open(&slot[..SLOT_LEN - 1]),
        Err(OpenerRefusal::SlotLength { got: SLOT_LEN - 1 })
    );
    let mut wrong_version = slot;
    wrong_version[0] = 0x02;
    assert_eq!(
        opener.open(&wrong_version),
        Err(OpenerRefusal::SlotVersion { version: 0x02 })
    );
    // The kind is inside the AAD, so re-labelling a slot fails the tag rather than passing.
    let mut relabelled = slot;
    relabelled[1] = KIND_PASSKEY_PRF;
    assert_eq!(opener.open(&relabelled), Err(OpenerRefusal::DoesNotOpen));
    // And so does every other byte.
    for at in [2, 10, SLOT_LEN - 1] {
        let mut bad = slot;
        bad[at] ^= 0x01;
        assert_eq!(
            opener.open(&bad),
            Err(OpenerRefusal::DoesNotOpen),
            "byte {at}"
        );
    }
}

#[test]
fn the_labels_are_the_registered_ones() {
    // Not a cryptographic assertion — a tripwire. Moving either string orphans every slot
    // stored under it until its owner signs in and re-wraps, so the change is typed twice.
    assert_eq!(OPENER_WRAP_INFO, b"nmts/v3/opener-wrap/1");
    assert_eq!(OPENER_LOCATOR_INFO, b"nmts/v3/opener-locator/1");
    assert_eq!(MESSAGE_VERSION, 1);
    assert_eq!(SLOT_LEN, 62);
}

#[test]
fn debug_never_prints_the_wrapping_key() {
    let opener = opener_from_signature(&serialized(FLAG_ED25519, &pure_a(), 32)).unwrap();
    let printed = format!("{opener:?}");
    assert!(printed.contains(&hex_locator(&opener.locator())));
    // The wrapping key's first bytes, in the two spellings a Debug could produce.
    let hk = Hkdf::<Sha256>::new(Some(b""), &pure_a());
    let mut wrap = [0u8; WRAP_KEY_LEN];
    hk.expand(OPENER_WRAP_INFO, &mut wrap).unwrap();
    assert!(!printed.contains(&format!("{:?}", &wrap[..4])));
    assert!(!printed.contains(&hex_locator(&<[u8; 16]>::try_from(&wrap[..16]).unwrap())));
}
