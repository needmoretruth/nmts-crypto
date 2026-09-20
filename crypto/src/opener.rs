//! Openers — ways to reach an account's NMTS key that can be added and taken away (NCF-3 §1.7).
//!
//! # Purpose
//! An NMTS account is one secret: the 20-byte NMTS key (§1.1). Until now there was one way to
//! present it — type it in. This module adds a second SHAPE of way: a small record called a
//! **slot** that holds the NMTS key wrapped under a key derived from something else the person
//! has. The disk-encryption analogue is exact: LUKS key slots, several of them, each addable and
//! removable, none of them the master key and all of them opening it.
//!
//! The first opener is a Sui wallet's signature over the fixed message in [`opener_message`]:
//!
//! ```text
//! sig(64)  = the PURE signature inside the wallet's serialized one (flag and public key dropped)
//! wrapKey  = HKDF-Expand(HKDF-Extract(salt = "", ikm = sig), "nmts/v3/opener-wrap/1",    32)
//! locator  = HKDF-Expand(HKDF-Extract(salt = "", ikm = sig), "nmts/v3/opener-locator/1", 16)
//! slot     = version(1) || kind(1) || nonce(24) || XChaCha20-Poly1305(wrapKey, key20, version||kind)
//! ```
//!
//! # ⭐ This layer is NOT frozen, and that is the whole reason it exists
//! Every byte of §1 is frozen because a value derived under it can never be recomputed any other
//! way. Nothing here has that property: a slot carries its own version byte, the server holds it
//! under a name the person can ask for and delete, and the day the message or the derivation has
//! to change, the next sign-in re-wraps the same NMTS key into a new slot and removes the old one.
//! So this is an ADDITION to NCF-3, never a change to it — no existing key, envelope, address or
//! code moves, and no reader of existing data behaves differently. What is taken is two labels in
//! the §2.1 registry.
//!
//! # ⛔ The signature and the wrapping key do not leave this module
//! [`opener_from_signature`] takes the SERIALIZED signature and hands back an [`Opener`], which
//! answers with a locator, a sealed slot, or an opened NMTS key — never with the 64 signature
//! bytes and never with the 32 wrapping bytes. That is the review's finding 2-B3 turned into an
//! API shape rather than a sentence: a boundary that cannot return the secret cannot leak it
//! through a caller that forgot, and the wasm surface above has the same three answers.
//!
//! # ⛔ What the holder of a slot can do, and what removing one does not undo
//! Whoever has the 64 signature bytes has the account for as long as that slot exists. Removing
//! the slot means "this wallet can no longer open the account" — it does not mean the wallet never
//! knew the NMTS key. A device that opened the account once holds the root, and the only answer to
//! that is a new account. The screens that offer removal say so; this module's part is to make
//! removal a real thing rather than a claim.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::codes::ACCOUNT_CODE_BYTES;

/// HKDF `info` for the key a slot is sealed under (NCF-3 §2.1, added 2026-09-20).
///
/// ⚠ The trailing `/1` is the version of the pair (message, derivation), not a family index like
/// `nmts/v3/wallet/<N>`. A `/2` would be a new registry row and a new `Version:` line, and slots
/// made under `/1` would go on opening until their owner re-wrapped them — which, unlike §1, is
/// something this layer can actually do.
pub const OPENER_WRAP_INFO: &[u8] = b"nmts/v3/opener-wrap/1";

/// HKDF `info` for the name the server files a slot under (NCF-3 §2.1, added 2026-09-20).
///
/// ⛔ IT COMES FROM THE SECRET, and that is what the server does not learn. A locator is 16 bytes
/// expanded from the same signature the wrapping key comes from, so the server can store, find and
/// delete a slot while knowing neither which wallet it belongs to nor what is in it. It is not a
/// credential: knowing a locator fetches an opaque 62 bytes that only the signature opens.
pub const OPENER_LOCATOR_INFO: &[u8] = b"nmts/v3/opener-locator/1";

/// Bytes of the key a slot is sealed under. Never crosses this module's boundary.
pub const WRAP_KEY_LEN: usize = 32;

/// Bytes of the name a slot is stored under.
pub const LOCATOR_LEN: usize = 16;

/// The slot's XChaCha20-Poly1305 nonce, drawn fresh for every seal.
pub const SLOT_NONCE_LEN: usize = 24;

/// Poly1305 tag length.
pub const SLOT_TAG_LEN: usize = 16;

/// Version byte every slot this code writes carries.
///
/// ⚠ Read on open and refused when unknown, so a client that meets a slot from a later version of
/// this layer says "this needs a newer build" instead of failing at the AEAD, where the symptom
/// would be indistinguishable from a wrong wallet.
pub const SLOT_VERSION: u8 = 0x01;

/// Slot kind: a Sui wallet's signature over the [`opener_message`] text.
pub const KIND_WALLET_SIGNATURE: u8 = 0x01;

/// Slot kind: a WebAuthn passkey's PRF output. Reserved — nothing in this crate writes it yet.
///
/// ⚠ The number is spent here rather than later on purpose: the kind is inside the slot's AAD, so
/// two implementations disagreeing about which byte means "passkey" would produce slots neither
/// could open, and the cost of reserving it now is one line.
pub const KIND_PASSKEY_PRF: u8 = 0x02;

/// Exactly 62 bytes: `version(1) || kind(1) || nonce(24) || ciphertext(20) || tag(16)`.
pub const SLOT_LEN: usize = 2 + SLOT_NONCE_LEN + ACCOUNT_CODE_BYTES + SLOT_TAG_LEN;

/// Length of the pure signature every accepted Sui scheme produces (`r || s`, or Ed25519's
/// `R || S`).
pub const PURE_SIGNATURE_LEN: usize = 64;

/// Hex characters in a Sui address after the `0x`.
pub const ADDRESS_HEX_LEN: usize = 64;

/// Longest `App:` value accepted, in characters.
pub const APP_MAX_LEN: usize = 64;

/// The value of the message's `Version:` line. See [`OPENER_WRAP_INFO`].
pub const MESSAGE_VERSION: u32 = 1;

/// Sui signature-scheme flag: Ed25519. Accepted.
pub const FLAG_ED25519: u8 = 0x00;
/// Sui signature-scheme flag: ECDSA secp256k1. Accepted.
pub const FLAG_SECP256K1: u8 = 0x01;
/// Sui signature-scheme flag: ECDSA secp256r1. Accepted.
pub const FLAG_SECP256R1: u8 = 0x02;
/// Sui signature-scheme flag: multisig. Refused.
pub const FLAG_MULTISIG: u8 = 0x03;
/// Sui signature-scheme flag: zkLogin. Refused.
pub const FLAG_ZKLOGIN: u8 = 0x05;
/// Sui signature-scheme flag: passkey. Refused.
pub const FLAG_PASSKEY: u8 = 0x06;

/// Serialized Ed25519 signature: `flag(1) || sig(64) || pk(32)`.
pub const ED25519_SERIALIZED_LEN: usize = 1 + PURE_SIGNATURE_LEN + 32;
/// Serialized ECDSA signature: `flag(1) || sig(64) || compressed pk(33)`.
pub const ECDSA_SERIALIZED_LEN: usize = 1 + PURE_SIGNATURE_LEN + 33;

/// The seven fixed lines that open the message, in order. `Wallet:`, `Account:`, the optional
/// `App:` and `Version:` follow them.
///
/// ⛔ The heading differs from the side road's (`NMTS key`, §1.6's signature-derived account) and
/// has to. One signature must not serve two purposes: a person who signed to DERIVE an account
/// would otherwise be handing over the bytes that unwrap a slot, and the only thing keeping the
/// two apart is the first line of what they signed.
///
/// ⚠ One English wording and no translations — a translated line is different bytes, and different
/// bytes are a different wrapping key and a different locator. The warning is the phishing defence:
/// this is what a wallet popup shows, and a site that gets these exact bytes signed gets the slot.
const FIXED_LINES: [&str; 7] = [
    "NMTS wallet sign-in",
    "",
    "Signing this message lets this wallet open your NMTS account.",
    "Sign it only on nmts.me or in a tool you trust with your files.",
    "Anyone who gets this signature can open your files",
    "until you remove this wallet from the account.",
    "",
];

/// Why an opener path was refused, in the words a caller has to be able to turn into a sentence.
///
/// ⛔ ONE VARIANT PER REASON rather than one "bad input". A person whose passkey wallet is refused
/// needs to be told that passkeys sign differently every time; a person whose address was typed
/// with capitals needs to be told that the address is inside the signed bytes. The answer differs
/// per reason, so the reason has to survive the return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenerRefusal {
    /// The `Wallet:` line was not `0x` followed by 64 lowercase hex characters.
    ///
    /// Refused rather than normalised: the address is INSIDE the signed bytes, so trimming a space
    /// or lowercasing a capital would silently sign a different message, producing a different
    /// wrapping key and a locator that finds nothing.
    #[error("wallet address must be 0x followed by {ADDRESS_HEX_LEN} lowercase hex characters")]
    AddressNotCanonical,
    /// An account number of 0. They are numbered from 1.
    #[error("account number must be 1 or greater, got 0")]
    AccountZero,
    /// The optional `App:` value was not 1–64 characters of `a-z0-9.-`, starting and ending
    /// alphanumeric. Refused rather than repaired, for the reason the address is.
    #[error("app must be 1 to {APP_MAX_LEN} characters of a-z, 0-9, dot and hyphen, starting and ending with a letter or digit")]
    AppNotCanonical,
    /// Nothing at all — not even a scheme flag.
    #[error("the wallet returned an empty signature")]
    Empty,
    /// Flag `0x03`: a multisig signature. Its bytes depend on which signers took part, so the same
    /// message does not always give the same signature and the slot would not reopen.
    #[error("multisig wallets sign differently depending on which signers take part")]
    Multisig,
    /// Flag `0x05`: zkLogin. The ephemeral key and the proof change from session to session.
    ///
    /// ⛔ Caught HERE, by the flag, and not by asking for two signatures: inside one session
    /// zkLogin can return the same bytes twice, so a two-signature check would pass and the slot
    /// would be unopenable tomorrow.
    #[error("zkLogin signatures change with every session")]
    ZkLogin,
    /// Flag `0x06`: a passkey. WebAuthn signs over data that includes a counter, so no two
    /// signatures over one message are the same.
    #[error("passkey wallets produce a different signature every time")]
    Passkey,
    /// A flag this layer does not know. Refused rather than guessed — an allow list, not a deny
    /// list, so a scheme nobody has judged cannot arrive by being new (review 3-A2).
    #[error("unknown Sui signature scheme 0x{flag:02x}")]
    UnknownScheme {
        /// The first byte of the serialized signature.
        flag: u8,
    },
    /// The scheme is accepted but the serialized signature is not the length that scheme has.
    #[error("a 0x{flag:02x} signature is {expected} bytes serialized, got {got}")]
    WrongLength {
        /// The scheme flag that was read.
        flag: u8,
        /// The length that scheme's serialized form has.
        expected: usize,
        /// The length handed in.
        got: usize,
    },
    /// A slot that is not exactly [`SLOT_LEN`] bytes.
    #[error("a slot is {SLOT_LEN} bytes, got {got}")]
    SlotLength {
        /// The length handed in.
        got: usize,
    },
    /// A slot whose version byte this build does not know.
    ///
    /// ⚠ Its own reason rather than an authentication failure: "your build is older than this
    /// slot" and "this is the wrong wallet" have different answers, and at the AEAD they would
    /// look identical.
    #[error("this slot is version {version} and this build writes version {SLOT_VERSION}")]
    SlotVersion {
        /// The first byte of the slot.
        version: u8,
    },
    /// A kind byte this layer has not reserved, met while sealing.
    #[error("unknown opener kind 0x{kind:02x}")]
    SlotKind {
        /// The kind that was asked for.
        kind: u8,
    },
    /// The slot did not open under this signature: a different wallet, a different message, or
    /// bytes that were altered.
    ///
    /// ⚠ One answer for all three on purpose. Telling them apart would tell somebody holding a
    /// fetched slot whether their guess at the wallet was getting warmer.
    #[error("this signature does not open this slot")]
    DoesNotOpen,
}

/// The EXACT bytes a Sui wallet is asked to sign for `address`, account number `account` and an
/// optional product scope `app` (NCF-3 §1.7).
///
/// ```text
/// NMTS wallet sign-in
///
/// Signing this message lets this wallet open your NMTS account.
/// Sign it only on nmts.me or in a tool you trust with your files.
/// Anyone who gets this signature can open your files
/// until you remove this wallet from the account.
///
/// Wallet: 0x…
/// Account: 1
/// App: example.com      ← only when one is given, between Account and Version
/// Version: 1
/// ```
///
/// LF line endings, **no trailing newline**, ASCII throughout.
///
/// Every input is checked and nothing is repaired (review 1-A3): the values are inside the bytes a
/// person reads in a wallet popup, so a caller that could smuggle a newline through `address` or
/// `app` could write the popup's text. `address` is `0x` + 64 lowercase hex; `account` is decimal
/// with no padding, from 1; `app` is 1–64 characters of `a-z`, `0-9`, `.` and `-`, starting and
/// ending alphanumeric.
///
/// ⚠ `app` is the caller's choice and it changes the key: with it, one wallet opens a different
/// account per product; without it, the same wallet opens the same account everywhere. The screen
/// that offers the choice is where that price is written down, not here.
pub fn opener_message(
    address: &str,
    account: u32,
    app: Option<&str>,
) -> Result<Vec<u8>, OpenerRefusal> {
    if !is_canonical_address(address) {
        return Err(OpenerRefusal::AddressNotCanonical);
    }
    if account == 0 {
        return Err(OpenerRefusal::AccountZero);
    }
    if let Some(app) = app {
        if !is_canonical_app(app) {
            return Err(OpenerRefusal::AppNotCanonical);
        }
    }

    let mut message = String::new();
    for line in FIXED_LINES {
        message.push_str(line);
        message.push('\n');
    }
    message.push_str("Wallet: ");
    message.push_str(address);
    message.push_str("\nAccount: ");
    message.push_str(&account.to_string());
    if let Some(app) = app {
        message.push_str("\nApp: ");
        message.push_str(app);
    }
    message.push_str("\nVersion: ");
    message.push_str(&MESSAGE_VERSION.to_string());
    debug_assert!(message.is_ascii(), "the message is ASCII by construction");
    Ok(message.into_bytes())
}

/// `0x` + exactly 64 lowercase hex characters, and nothing else.
fn is_canonical_address(address: &str) -> bool {
    let bytes = address.as_bytes();
    bytes.len() == 2 + ADDRESS_HEX_LEN
        && bytes[0] == b'0'
        && bytes[1] == b'x'
        && bytes[2..]
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `^[a-z0-9]([a-z0-9.-]{0,62}[a-z0-9])?$` — a hostname-shaped label, 1 to 64 characters.
fn is_canonical_app(app: &str) -> bool {
    let bytes = app.as_bytes();
    if bytes.is_empty() || bytes.len() > APP_MAX_LEN {
        return false;
    }
    let alnum = |b: &u8| matches!(b, b'a'..=b'z' | b'0'..=b'9');
    if !alnum(&bytes[0]) || !alnum(&bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|b| alnum(b) || matches!(b, b'.' | b'-'))
}

/// The PURE 64-byte signature inside a Sui serialized signature (`flag || sig || pk`), for the
/// three schemes this layer accepts — and a distinct reason for every one it does not.
///
/// Accepted: `0x00` Ed25519 at [`ED25519_SERIALIZED_LEN`] bytes, `0x01` secp256k1 and `0x02`
/// secp256r1 at [`ECDSA_SERIALIZED_LEN`]. Exactly those lengths (review 3-B3): under an accepted
/// flag, a buffer of another size is refused rather than sliced, because bytes 1..65 of a
/// differently shaped buffer are not the signature.
///
/// ⛔ **Nothing here is verified.** This does not know whether the bytes are a signature at all,
/// and it cannot know whose. Checking it against the address in the message is the caller's step,
/// with the Sui library, and it is what catches a wallet that signed bytes other than the ones it
/// displayed.
///
/// ⚠ `pub(crate)` on purpose: the pure signature is key material, and the only public road to it
/// is [`opener_from_signature`], which consumes it. See this module's header.
pub(crate) fn pure_signature_of(
    serialized: &[u8],
) -> Result<Zeroizing<[u8; PURE_SIGNATURE_LEN]>, OpenerRefusal> {
    let flag = *serialized.first().ok_or(OpenerRefusal::Empty)?;
    let expected = match flag {
        FLAG_ED25519 => ED25519_SERIALIZED_LEN,
        FLAG_SECP256K1 | FLAG_SECP256R1 => ECDSA_SERIALIZED_LEN,
        FLAG_MULTISIG => return Err(OpenerRefusal::Multisig),
        FLAG_ZKLOGIN => return Err(OpenerRefusal::ZkLogin),
        FLAG_PASSKEY => return Err(OpenerRefusal::Passkey),
        other => return Err(OpenerRefusal::UnknownScheme { flag: other }),
    };
    if serialized.len() != expected {
        return Err(OpenerRefusal::WrongLength {
            flag,
            expected,
            got: serialized.len(),
        });
    }
    let mut pure = Zeroizing::new([0u8; PURE_SIGNATURE_LEN]);
    pure.copy_from_slice(&serialized[1..1 + PURE_SIGNATURE_LEN]);
    Ok(pure)
}

/// One opener, built from one secret: the locator the server files its slot under, and the key
/// that slot is sealed with.
///
/// ⛔ The wrapping key is private and zeroized on drop, and there is no accessor. Everything a
/// caller can ask for — [`Opener::locator`], [`Opener::seal`], [`Opener::open`] — is a value the
/// server or the rest of the app is allowed to hold. The secret this was built from is already
/// gone by the time the constructor returns.
pub struct Opener {
    locator: [u8; LOCATOR_LEN],
    wrap_key: Zeroizing<[u8; WRAP_KEY_LEN]>,
    kind: u8,
}

impl core::fmt::Debug for Opener {
    /// ⛔ Hand-written so `{:?}` on an `Opener` — in a log line, a panic message, a test failure —
    /// can never print the wrapping key. The derived implementation would.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Opener")
            .field("kind", &self.kind)
            .field("locator", &hex_locator(&self.locator))
            .finish_non_exhaustive()
    }
}

/// Lowercase hex of the locator, for [`Opener`]'s `Debug`. The locator is not a secret.
fn hex_locator(locator: &[u8; LOCATOR_LEN]) -> String {
    let mut out = String::with_capacity(LOCATOR_LEN * 2);
    for b in locator {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The opener a Sui wallet's serialized signature over the [`opener_message`] text yields.
///
/// The serialized form goes in, the 64 pure bytes are taken out, both HKDF expansions are run, and
/// the signature is wiped before this returns. Whatever the caller still holds is the caller's to
/// wipe too — it is the bytes the wallet handed back, and they are the account.
pub fn opener_from_signature(serialized: &[u8]) -> Result<Opener, OpenerRefusal> {
    let signature = pure_signature_of(serialized)?;
    Ok(opener_from_secret(&signature[..], KIND_WALLET_SIGNATURE))
}

/// Both expansions of one opener secret. Private: the only secrets this layer knows how to take
/// are the ones its public constructors accept, and a `pub` version of this would be a door for
/// any 32 bytes somebody had lying around.
///
/// The empty extract salt is §1.2's choice for §1.2's reason: the input cannot be guessed without
/// the wallet's private key, so there is no dictionary for a salt to defeat.
fn opener_from_secret(secret: &[u8], kind: u8) -> Opener {
    let hk = Hkdf::<Sha256>::new(Some(b""), secret);
    let mut wrap_key = Zeroizing::new([0u8; WRAP_KEY_LEN]);
    let mut locator = [0u8; LOCATOR_LEN];
    // Expand only fails past 255*HashLen; both widths are compile-time constants far below it.
    hk.expand(OPENER_WRAP_INFO, &mut *wrap_key)
        .expect("HKDF expand length within bounds");
    hk.expand(OPENER_LOCATOR_INFO, &mut locator)
        .expect("HKDF expand length within bounds");
    Opener {
        locator,
        wrap_key,
        kind,
    }
}

impl Opener {
    /// The 16-byte name the server files this opener's slot under, and the name a sign-in asks for
    /// it back by.
    ///
    /// ⚠ Public by design and secret by accident of its input: it goes to the server in a URL, and
    /// it says nothing about which wallet produced it.
    pub fn locator(&self) -> [u8; LOCATOR_LEN] {
        self.locator
    }

    /// Which kind of opener this is — [`KIND_WALLET_SIGNATURE`] here. It is written into the slot
    /// and into the slot's AAD.
    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// The 62-byte slot holding `key` (the account's 20 NMTS-key bytes), with a fresh nonce.
    ///
    /// `version || kind || nonce || XChaCha20-Poly1305(wrapKey, key, aad = version || kind)`.
    /// The two leading bytes are BOTH plaintext and AAD: they have to be readable to know how to
    /// open the slot, and authenticated so that nobody can re-label one kind's slot as another's.
    pub fn seal(&self, key: &[u8; ACCOUNT_CODE_BYTES]) -> Result<[u8; SLOT_LEN], OpenerRefusal> {
        let mut nonce = [0u8; SLOT_NONCE_LEN];
        crate::rng::OsRng::try_fill(&mut nonce).expect("OS CSPRNG unavailable");
        self.seal_inner(&nonce, key)
    }

    /// The NMTS key inside `slot`, or a reason.
    ///
    /// Refuses a slot of the wrong length or an unknown version by name, then lets the AEAD answer
    /// everything else with one indistinguishable [`OpenerRefusal::DoesNotOpen`].
    ///
    /// ⚠ The KIND byte is read and authenticated but not judged. A slot written by a kind this
    /// build has never heard of still opens if the wrapping key is right, which is the correct
    /// behaviour: the kind says how the secret was obtained, and this caller already obtained it.
    pub fn open(&self, slot: &[u8]) -> Result<Zeroizing<[u8; ACCOUNT_CODE_BYTES]>, OpenerRefusal> {
        if slot.len() != SLOT_LEN {
            return Err(OpenerRefusal::SlotLength { got: slot.len() });
        }
        if slot[0] != SLOT_VERSION {
            return Err(OpenerRefusal::SlotVersion { version: slot[0] });
        }
        let aad = &slot[..2];
        let nonce = &slot[2..2 + SLOT_NONCE_LEN];
        let body = &slot[2 + SLOT_NONCE_LEN..];

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.wrap_key));
        let mut plain = cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
            .map_err(|_| OpenerRefusal::DoesNotOpen)?;
        // The AEAD proved the length as well as the bytes — a 20-byte plaintext is what this
        // wrapping key and this AAD can produce — but the conversion is fallible, so it is
        // answered rather than unwrapped.
        let out = <[u8; ACCOUNT_CODE_BYTES]>::try_from(plain.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| OpenerRefusal::DoesNotOpen);
        plain.zeroize();
        out
    }

    /// Deterministic seal with a caller-supplied nonce — VECTORS AND TESTS ONLY.
    ///
    /// ⛔ Compiled only under `test` or the `vectors` feature, exactly as `wrap::seal_with_nonce`
    /// is and for the same reason: a production build that accepts a nonce is one that can be made
    /// to repeat one, and repeating an XChaCha20-Poly1305 nonce under one key reveals the
    /// plaintext difference — here, the NMTS key itself.
    #[cfg(any(test, feature = "vectors"))]
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; SLOT_NONCE_LEN],
        key: &[u8; ACCOUNT_CODE_BYTES],
    ) -> Result<[u8; SLOT_LEN], OpenerRefusal> {
        self.seal_inner(nonce, key)
    }

    /// The one body both seal paths run, so the production slot and the vector slot are the same
    /// construction and the fixture proves the shipped one.
    fn seal_inner(
        &self,
        nonce: &[u8; SLOT_NONCE_LEN],
        key: &[u8; ACCOUNT_CODE_BYTES],
    ) -> Result<[u8; SLOT_LEN], OpenerRefusal> {
        if !matches!(self.kind, KIND_WALLET_SIGNATURE | KIND_PASSKEY_PRF) {
            return Err(OpenerRefusal::SlotKind { kind: self.kind });
        }
        let header = [SLOT_VERSION, self.kind];
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.wrap_key));
        let body = cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &key[..],
                    aad: &header,
                },
            )
            .expect("XChaCha20Poly1305 encryption is infallible for valid inputs");

        let mut slot = [0u8; SLOT_LEN];
        slot[..2].copy_from_slice(&header);
        slot[2..2 + SLOT_NONCE_LEN].copy_from_slice(nonce);
        slot[2 + SLOT_NONCE_LEN..].copy_from_slice(&body);
        Ok(slot)
    }
}

#[cfg(test)]
#[path = "opener_tests.rs"]
mod tests;
