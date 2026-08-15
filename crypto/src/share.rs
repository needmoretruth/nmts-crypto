//! Private person-to-person sharing (NCF-3 §5).
//!
//! # What this solves
//! The owner of a file holds its DEK. To let ONE other account open that file — and nobody else,
//! including the server — the DEK must travel encrypted to that specific recipient. This module
//! is that transport.
//!
//! # The defects NCF-3 fixes here
//!
//! **A1 — the server was an undetectable man-in-the-middle.** In NCF-2 the share ADDRESS and the
//! share PUBLIC KEY were two independent HKDF outputs of the account code, so they were
//! cryptographically unrelated. A sender received the recipient's public key **from the server**
//! and had no way to check it belonged to that address: the server could hand over its own key,
//! read the DEK, and re-wrap to the real recipient with nothing odd on either screen. The
//! product's central claim — the server cannot reach file keys — was false on this path.
//!
//! NCF-3 makes the address a **fingerprint of the identity root**:
//! ```text
//! share_address = SHA-256("nmts/v3/share-address" || root)[0..16]
//! ```
//! The sender hashes the root of whatever bundle the server hands over and compares. A substituted
//! key does not match the address the recipient gave out, and the share is refused **before
//! anything is encrypted to it**.
//!
//! The reason NCF-2 kept them independent was to leave room to rotate a key without invalidating
//! a published address. That capability was given up when the address became a fingerprint — and
//! **since 2026-08-02 it is bought back a different way** (NCF-3 §5.2a): the fingerprint covers
//! only the permanent root, and every other key in the bundle is bound to that root by the
//! identity's own signature instead of by the fingerprint. The address stays immutable and stays
//! unforgeable; what is no longer frozen with it is the rest of the bundle.
//!
//! **A2 — X25519 alone is a harvest-now-decrypt-later target.** Walrus is a public network:
//! ciphertext can be collected today and opened years later by a large enough quantum computer.
//! An account's OWN files are safe (their keys come symmetrically from the account code, and
//! symmetric encryption survives), so the exposure was exactly the shared ones — permanently, on
//! an address that cannot be rotated.
//!
//! NCF-3 wraps with **X-Wing**, which combines X25519 and ML-KEM-768 so that **both** must be
//! broken to recover the DEK. A quantum computer alone does not open harvested ciphertext, and a
//! flaw found later in ML-KEM does not put us below where we are today.
//!
//! **Sender authentication (adversarial review, 2026-07-29 — NCF-3 §5.5; it has no defect letter, and in
//! particular is NOT "A3", which is the file-list rollback) — an envelope proved who it was FOR
//! and never who it was FROM.** X-Wing is an unauthenticated KEM: anyone holding a recipient's public key, which
//! is public by construction, can build a valid envelope for them. The "from" line in a recipient's
//! inbox was therefore a **server-supplied column**, so a hostile server — or, with a squatted
//! address, an ordinary account — could put a file in someone's inbox attributed to a contact they
//! trust. Confidentiality held; origin did not.
//!
//! NCF-3 adds a second static key to the share identity and mixes a **static-static** agreement
//! into the wrapping key. An envelope now opens **only if the claimed sender really produced it**.
//!
//! # Shape
//! ```text
//! (sk_kem, pk_kem) = X-Wing.KeyGenDerand(shareKemSeed)      // kdf::INFO_SHARE_KEM
//! (sk_auth,pk_auth)= X25519(shareAuthSecret)                // kdf::INFO_SHARE_AUTH
//! (sk_sig, pk_sig) = ML-DSA-44.KeyGen_internal(shareSigSeed) // kdf::INFO_SHARE_SIG, §5.2a
//!
//! identity = version(1) || derivation_index(4) || pk_sig(1312)     // = 1317
//!                       || key_epoch(4) || pk_kem(1216) || pk_auth(32)  // = 2569 signed
//!                       || self_sig(2420)                          // = 4989 published
//! root     = identity[1..1317]   = derivation_index || pk_sig      // = 1316, immutable
//! self_sig = ML-DSA-44.Sign_det(sk_sig, identity[0..2569),
//!                               ctx = "nmts/v3/identity-bundle")
//! address  = SHA-256("nmts/v3/share-address" || root)[0..16]
//!
//! (ct_kem, ss_kem) = X-Wing.Encapsulate(pk_kem_recipient)
//! ss_auth          = X25519(sk_auth_sender, pk_auth_recipient)
//! payload_cmt      = SHA-256("nmts/v3/share-payload"
//!                            || u32be(len) || item_id        // lowercased ASCII, as the API spells it
//!                            || u32be(len) || name_share_ct
//!                            || u32be(len) || content_hash_share_ct)
//! wrap_key         = HKDF(ikm = ss_kem || ss_auth,
//!                         info = "nmts/v3/share-wrap" || sender_address
//!                                                     || ct_kem || root_recipient
//!                                                     || payload_cmt, 32)
//! sealed_dek       = E(wrap_key, "nmts/v3/share-wrap", DEK)   // wrap.rs envelope, 104 B
//!
//! share envelope = sender_address(16) || ct_kem(1120) || sealed_dek(104) = 1240 bytes
//! ```
//!
//! ## The self-signature, and the only thing it is ever used for (NCF-3 §5.2a)
//! The address fingerprints the **root** and nothing else, so the root — the derivation index and
//! the ML-DSA-44 verification key — is frozen the moment an address is published. Everything after
//! it in the bundle is held in place by a signature the root's own key makes over the bundle. A
//! reader checks both: the root hashes to the address it asked for, and the signature verifies
//! under the key that root pins. A server that substitutes any key fails one of the two.
//!
//! What that buys is room to move later under an address that can never change: replacing
//! `pk_kem` or `pk_auth` is a `key_epoch` bump re-signed by the same root, and a different body
//! layout is a new `identity_version` under the same root. ⚠ **Neither procedure exists yet** —
//! both counters are always zero here, and a replacement flow has to be specified before any
//! non-zero value is published. The anchor is lattice-based on purpose: it is the one value that
//! must survive an adversary who breaks the classical keys.
//!
//! ⛔ **This is the only signature this format ever makes.** Envelopes, files and messages are
//! never signed — see the deniability argument below, which the self-signature does not touch: it
//! signs a bundle of public keys, which is a public fact and no receipt of anything.
//!
//! ⛔ **Only the deterministic FIPS 204 variant is used.** A hedged signature would give one
//! account different identity bytes on every device, which would make the server's first-writer
//! rule reject the account's own second device, make the account screen's comparison with the
//! server report a false mismatch, and leave the conformance vectors unpinnable.
//!
//! ## Why static-static rather than a signature
//! A signature over the envelope would also prove origin — and would prove it **to anyone**,
//! forever. That is a transferable receipt that account X sent file Y to account Z, produced by a
//! product whose whole design is about not generating such records. The static-static agreement
//! gives the recipient the same certainty (only the sender's private key could have produced an
//! envelope that opens) while giving a third party nothing: the recipient could have computed the
//! identical value themselves, so a leaked envelope proves nothing about who wrote it. Same
//! reasoning as HPKE's `mode_auth`, and it costs 16 bytes rather than 1300.
//!
//! ⚠ **Two limits, stated rather than implied.** ① The authentication half is X25519 — classical
//! only. Confidentiality is hybrid and survives a quantum adversary; *origin* does not, and a
//! future quantum attacker could forge a sender. Forging requires the machine at the time of
//! forging, unlike harvest-now-decrypt-later, which is why this was not worth another 1.2 KB per
//! envelope. ② Verifying origin needs the sender's published identity, which the recipient fetches
//! by address and checks against the fingerprint. A server that refuses to answer blocks the check
//! — the share then does not open, which is the safe direction.
//!
//! ## Why the ciphertext, the recipient identity and the sender address go into the HKDF `info`
//! Binding them means a `wrap_key` is only ever valid for the exact (encapsulation, recipient,
//! sender) triple it was made for. Without it, an attacker who can re-address an envelope could
//! make a recipient decrypt something under a key they did not think they were using (the
//! unknown-key-share family). Binding the sender address is what makes the 16 bytes in the
//! envelope self-authenticating: change them and the wrapping key changes, so the envelope stops
//! opening rather than opening under a false name.
//!
//! ## Why the shared payload goes in too (defect A6, found by an adversarial review of this path)
//! Authenticating the sender is not the same as authenticating **what they sent**, and until this
//! was added the envelope only did the first. Its plaintext is a DEK and nothing else, so an
//! envelope said "this key came from Alice" — never "and it belongs to *that* file".
//!
//! That gap is reachable, not theoretical, because a share wraps the file's **own** DEK: everyone
//! Alice ever shared that file with holds it. One such recipient, together with a server willing
//! to rewrite a row, can leave Alice's real envelope untouched and swap only the columns beside it
//! — the sealed name and the sealed content digest — for ones they sealed under that same DEK.
//! The victim's screen then shows an attacker-chosen file, attributed to Alice with the sender
//! check **passing**, and the download's digest check passes too because the digest was replaced
//! in the same breath.
//!
//! The fix binds the row to the key that opens it: the item id, the sealed name and the sealed
//! digest are hashed into the wrapping key's `info`. Change any of them and the key changes and
//! the envelope stops opening. No new field and no extra byte on the wire — the binding is in the
//! derivation, and both sides recompute it from data they already hold.
//!
//! ⚠ **Lengths are prefixed, and that is load-bearing.** A sealed name has no fixed length, so
//! plain concatenation is ambiguous: `("ab","cd")` and `("abc","d")` are the same bytes and would
//! commit to the same value. Each field is therefore preceded by its length as a big-endian
//! `u32`.
//!
//! ⚠ **What this still does not do.** It does not stop the server DELETING a share, replaying an
//! older one it kept, or showing the sender a "shared with" list that is fiction. It authenticates
//! the contents of a row that is shown, not the set of rows.
//!
//! ## Rules that are not negotiable here
//! * ⛔ **No algorithm-selection field.** One format. A field you can flip is a downgrade.
//! * ⛔ **No fallback to classical-only wrapping on failure.** ML-KEM does not report failure; it
//!   returns a random-looking secret (implicit rejection). Code that reacts to "it did not open"
//!   by trying a classical path is a downgrade oracle.
//! * ⛔ **The combiner is not ours.** X-Wing is used exactly as specified — see NCF-3 §5.3 for
//!   the one place that deviates from the audit plan's generic advice, and why.
//! * ⚠ **Public keys are validated on receipt** before anything is encrypted to them.
//!
//! # What the server learns
//! The recipient's PUBLIC key (it must, to hand it to senders) and the opaque envelope bytes. It
//! cannot derive the shared secret, so it cannot read the DEK, and it never sees plaintext or
//! file keys. **And since NCF-3 it cannot lie about which key belongs to an address.** What it
//! can still do is refuse to answer — this closes lying, not denial of service.
//!
//! # Recoverability
//! The seed comes from the account code, so a recipient who re-enters their code on any device
//! can still open shares received years earlier. There is no separate share key to back up and
//! none to lose — the same property the rest of NMTS relies on.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, Seed, Signature,
    VerifyingKey,
};
use sha2::{Digest, Sha256};
use x_wing::kem::{Decapsulator, KeyExport};
use x_wing::{Ciphertext, Decapsulate, DecapsulationKey, EncapsulationKey};
use zeroize::Zeroizing;

use crate::codes::{self, CodeError};
use crate::kdf::{SHARE_AUTH_SECRET_LEN, SHARE_KEM_SEED_LEN, SHARE_SIG_SEED_LEN};
use crate::wrap::{self, WrapError, DEK_LEN, WRAPPED_DEK_LEN};

/// Length of the X-Wing encapsulation (public) key: ML-KEM-768 key (1184) + X25519 key (32).
pub const SHARE_KEM_PUBLIC_LEN: usize = 1216;

/// Length of the X25519 sender-authentication public key.
pub const SHARE_AUTH_PUBLIC_LEN: usize = 32;

/// Length of the ML-DSA-44 verification key that anchors an identity (FIPS 204).
pub const SHARE_SIG_PUBLIC_LEN: usize = 1312;

/// Length of an ML-DSA-44 signature (FIPS 204).
pub const SHARE_SELF_SIG_LEN: usize = 2420;

/// Width of each reserved counter in the bundle — `derivation_index` and `key_epoch`, both
/// big-endian `u32` and both always zero today (NCF-3 §5.2a).
const COUNTER_LEN: usize = 4;

/// The identity layout version this build writes, and the only one it will parse.
///
/// It counts the IDENTITY's layout, not the format's: the whole point of §5.2a is that the bundle
/// can gain a new shape without the rest of NCF changing and without any address moving. An
/// unknown value is refused outright — there is deliberately no "parse it by the older rule"
/// path, because that is how a reader is talked into using a key a newer writer had retired.
pub const SHARE_IDENTITY_VERSION: u8 = 0x01;

/// Offset of the version byte. **It sits OUTSIDE the fingerprinted root and this offset can never
/// move** — it is the one byte every future reader must be able to find before it knows anything
/// else about the layout.
const OFF_VERSION: usize = 0;
/// Offset of `derivation_index`, the first byte of the root.
const OFF_DERIVATION_INDEX: usize = OFF_VERSION + 1;
/// Offset of the ML-DSA-44 verification key.
const OFF_PK_SIG: usize = OFF_DERIVATION_INDEX + COUNTER_LEN;
/// Offset of `key_epoch`, the first byte after the root.
const OFF_KEY_EPOCH: usize = OFF_PK_SIG + SHARE_SIG_PUBLIC_LEN;
/// Offset of the X-Wing encapsulation key.
const OFF_PK_KEM: usize = OFF_KEY_EPOCH + COUNTER_LEN;
/// Offset of the X25519 sender-authentication key.
const OFF_PK_AUTH: usize = OFF_PK_KEM + SHARE_KEM_PUBLIC_LEN;

/// Length of the immutable identity ROOT: `derivation_index(4) || pk_sig(1312)`.
///
/// This — and only this — is what the share address fingerprints (NCF-3 §5.2), and what a wrapping
/// key binds a recipient to (§5.3). It starts at [`OFF_DERIVATION_INDEX`], one byte in, because
/// the version byte must be readable by a reader that does not yet know the layout.
pub const SHARE_ROOT_LEN: usize = COUNTER_LEN + SHARE_SIG_PUBLIC_LEN;

/// Length of the prefix the self-signature covers: everything published except the signature.
///
/// It cannot cover its own bytes and does not need to — altering the signature breaks
/// verification, the verification key sits inside the root, and the root is pinned by the address.
pub const SHARE_SIGNED_LEN: usize = OFF_PK_AUTH + SHARE_AUTH_PUBLIC_LEN;

/// Offset of the self-signature: immediately after the signed prefix.
const OFF_SELF_SIG: usize = SHARE_SIGNED_LEN;

/// Length of a published share identity (NCF-3 §5.1).
pub const SHARE_PUBLIC_LEN: usize = SHARE_SIGNED_LEN + SHARE_SELF_SIG_LEN;

/// Length of an X-Wing ciphertext: ML-KEM-768 ciphertext (1088) + X25519 ephemeral key (32).
pub const KEM_CIPHERTEXT_LEN: usize = 1120;

/// Byte length of a public share address. 128 bits — see [`ShareAddress`] on why truncating here
/// is safe.
pub const SHARE_ADDRESS_LEN: usize = 16;

/// Crockford data symbols in a share address, before the check symbol (`ceil(128 / 5)`).
pub const SHARE_ADDRESS_SYMBOLS: usize = 26;

/// Display grouping for a share address: three groups (`9-9-9`, the last carrying the check
/// symbol). Deliberately NOT the account code's eight groups of four — the two values must be
/// distinguishable at a glance, because pasting an account code where an address belongs would
/// hand someone the login secret.
const SHARE_ADDRESS_GROUP: usize = 9;

/// Exact size of a share envelope: `sender_address(16) + kem_ciphertext(1120) + sealed DEK(104)`.
pub const SHARE_ENVELOPE_LEN: usize = SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN + WRAPPED_DEK_LEN;

/// Bytes of uniform randomness one X-Wing encapsulation consumes (the draft calls it `eseed`).
pub const KEM_RANDOMNESS_LEN: usize = 64;

/// AAD (and HKDF info prefix) for a DEK wrapped to a recipient's share key.
pub const AAD_SHARE_WRAP: &[u8] = b"nmts/v3/share-wrap";

/// Hash domain separator for the share address (NCF-3 §5.2).
pub const HASH_SHARE_ADDRESS: &[u8] = b"nmts/v3/share-address";

/// Hash domain separator for the shared-payload commitment (NCF-3 §5.3, defect A6).
pub const HASH_SHARE_PAYLOAD: &[u8] = b"nmts/v3/share-payload";

/// FIPS 204 signature context (`ctx`) for the identity self-signature (NCF-3 §5.2a).
///
/// A signature context is a domain separator by another name — it is folded into the message
/// representative, so a signature made under this context cannot be replayed as one made under any
/// other. It is registered in the format's separator table beside the hash prefixes for exactly
/// that reason.
pub const SIG_CTX_IDENTITY_BUNDLE: &[u8] = b"nmts/v3/identity-bundle";

/// Errors from share wrapping/unwrapping.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// The envelope was not exactly [`SHARE_ENVELOPE_LEN`] bytes.
    #[error("share envelope has wrong length")]
    BadEnvelopeLength,
    /// A public key was not exactly [`SHARE_PUBLIC_LEN`] bytes, or did not decode.
    #[error("share public key is not valid")]
    BadPublicKey,
    /// Decryption failed: not this recipient's envelope, or it was tampered with.
    #[error("share could not be opened")]
    Auth,
    /// A typed share address was malformed: wrong length, unknown symbol, or failed check.
    #[error("share address is not valid: {0}")]
    BadAddress(CodeError),
    /// The public key the server returned does not hash to the address it was asked for.
    ///
    /// **This is the A1 alarm.** It is not a transient error and must never be retried past: the
    /// only ways to reach it are a server substituting a key, a mistyped address that got through
    /// the check symbol, or corruption on the wire.
    #[error("public key does not match the share address")]
    AddressMismatch,
    /// A [`SharePayload`] field was empty.
    ///
    /// Refused rather than tolerated: an empty sealed digest is how "the recipient cannot verify
    /// the body" would sneak back in, and an empty item id or name would let two different rows
    /// commit to the same value. The caller must supply all three — see [`SharePayload`].
    #[error("share payload field is empty: {0}")]
    EmptyPayloadField(&'static str),
    /// A [`SharePayload`] field did not fit in the `u32` length prefix. Unreachable with the
    /// API's own limits; refused rather than truncated, because a truncated length is a collision.
    #[error("share payload field is too long: {0}")]
    PayloadFieldTooLong(&'static str),
    /// The identity's self-signature does not verify under the verification key in its own root
    /// (NCF-3 §5.2a).
    ///
    /// The bundle was assembled by something that did not hold the root's signing key, or it was
    /// altered after it was signed. Either way the keys after the root are unattributed, so none
    /// of them may be used. Like [`ShareError::AddressMismatch`] this is never retried past.
    #[error("share identity self-signature is not valid")]
    BadSelfSignature,
    /// The identity claims a layout version this build does not know (NCF-3 §5.2a).
    ///
    /// ⛔ Refused rather than parsed by the rule this build does know. A reader that falls back to
    /// an older layout is a reader an attacker can talk into using a key the writer had replaced.
    #[error("share identity version {0} is not supported")]
    UnknownIdentityVersion(u8),
}

/// The three columns that travel beside a share envelope, as the recipient will receive them.
///
/// They are hashed into the wrapping key, so an envelope opens only next to the exact row it was
/// made for — see the module docs on defect A6. Both sides build this from bytes they already
/// hold: the sender from what it is about to POST, the recipient from what the inbox returned.
///
/// ⚠ `item_id` must be spelled identically on both sides. Callers crossing the WASM boundary get
/// that for free — `crypto-wasm` lowercases it — but a Rust caller is responsible for passing the
/// canonical (lowercase, hyphenated) form the API serialises.
///
/// ⚠ `content_hash_ct` is **not** optional. Before A6 a share could omit the digest, which left
/// the recipient with no way to check the body it downloaded; a share whose body is unverifiable
/// is exactly the one an attacker wants, so the field is required at this layer rather than in a
/// UI that could forget.
#[derive(Debug, Clone, Copy)]
pub struct SharePayload<'a> {
    /// The NMTS item id of the file being shared, ASCII, as the API spells it.
    pub item_id: &'a [u8],
    /// The item name sealed under the file DEK (NCF-3 §5.4).
    pub name_ct: &'a [u8],
    /// The whole-file content digest sealed under the file DEK (NCF-3 §5.4).
    pub content_hash_ct: &'a [u8],
}

impl SharePayload<'_> {
    /// `SHA-256(domain || u32be(len) || field ...)` over the three fields, in order.
    ///
    /// Every field is length-prefixed because none of them has a fixed length; without the
    /// prefixes two different rows could hash to the same value by shifting the boundary between
    /// adjacent fields.
    pub fn commitment(&self) -> Result<[u8; 32], ShareError> {
        let mut hasher = Sha256::new();
        hasher.update(HASH_SHARE_PAYLOAD);
        for (name, field) in [
            ("item_id", self.item_id),
            ("name_ct", self.name_ct),
            ("content_hash_ct", self.content_hash_ct),
        ] {
            if field.is_empty() {
                return Err(ShareError::EmptyPayloadField(name));
            }
            // A field longer than u32::MAX cannot exist here — these are a UUID and two AEAD
            // envelopes the API already bounds — but silently truncating a length is how a
            // length prefix stops preventing collisions, so it is refused rather than cast.
            let len =
                u32::try_from(field.len()).map_err(|_| ShareError::PayloadFieldTooLong(name))?;
            hasher.update(len.to_be_bytes());
            hasher.update(field);
        }
        Ok(hasher.finalize().into())
    }
}

impl From<WrapError> for ShareError {
    fn from(_: WrapError) -> Self {
        // Every wrap failure here means the same thing to a caller — the envelope did not
        // open — and distinguishing "bad tag" from "wrong length" would only tell an
        // attacker which of their guesses got further.
        ShareError::Auth
    }
}

/// The public half of an account's share identity: what the server stores and hands to senders.
///
/// Not secret and not PII — it is derived from the account code but reveals nothing about it, and
/// it identifies an account only to someone already given the address.
#[derive(Clone)]
pub struct SharePublicKey {
    kem: EncapsulationKey,
    auth: x25519_dalek::PublicKey,
    /// The exact published bytes, kept so the fingerprint is over what was actually transmitted
    /// rather than over a re-encoding of it.
    raw: [u8; SHARE_PUBLIC_LEN],
}

impl SharePublicKey {
    /// Parse from raw bytes, performing the whole of NCF-3 §5.2a in the order that section fixes.
    ///
    /// 1. **Exact length** for the version it claims. 2. **Known version** — an unknown one is
    ///    refused, never parsed by an older rule. 3. **The self-signature verifies** under the
    ///    verification key inside the root, with the identity-bundle context. 4. **The ML-KEM half
    ///    decodes.** 5. **Neither X25519 half is a low-order encoding.**
    ///
    /// ⚠ **Step 3 of the specification's list — the root hashing to the address the bundle was
    /// fetched by — cannot happen here**, because these bytes carry no expected address to compare
    /// against. It is the caller's, and there is no way to reach a wrap or an unwrap without it:
    /// [`wrap_dek_for`] takes the address as an argument and [`unwrap_dek`] reads it out of the
    /// envelope, and both call [`verify_address`] before anything else happens.
    ///
    /// ⚠ **The X25519 check is not decoration.** `x25519-dalek` accepts every 32-byte string as a
    /// public key and its Diffie–Hellman is infallible, so a low-order point agrees to the
    /// all-zero shared secret with every private key. Inside X-Wing that does not leak the DEK —
    /// the ML-KEM half still carries it — but it silently removes the classical half of the
    /// hybrid, which is the entire promise of §5.3 ("both must be broken"). An account that
    /// published such a key would degrade EVERY share sent to it, and because the address pins the
    /// root, republishing under the same address is not something today's server offers. Rejecting
    /// it at parse time is the only moment that is still cheap.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShareError> {
        let raw: [u8; SHARE_PUBLIC_LEN] = bytes.try_into().map_err(|_| ShareError::BadPublicKey)?;
        if raw[OFF_VERSION] != SHARE_IDENTITY_VERSION {
            return Err(ShareError::UnknownIdentityVersion(raw[OFF_VERSION]));
        }
        // Before any key in the bundle is looked at: does the bundle's own anchor vouch for it?
        // The verification key comes out of the root, which the caller has already tied to an
        // address, so this is what makes `pk_kem` and `pk_auth` attributable at all.
        verify_self_signature(&raw)?;

        let kem = EncapsulationKey::try_from(&raw[OFF_PK_KEM..OFF_PK_KEM + SHARE_KEM_PUBLIC_LEN])
            .map_err(|_| ShareError::BadPublicKey)?;
        // Both X25519 halves get the same treatment: the one at the tail of the KEM key, and the
        // standalone authentication key. Neither may be a low-order point.
        let kem_x = &raw[OFF_PK_AUTH - 32..OFF_PK_AUTH];
        let auth_x = &raw[OFF_PK_AUTH..OFF_PK_AUTH + SHARE_AUTH_PUBLIC_LEN];
        if is_low_order_x25519(kem_x) || is_low_order_x25519(auth_x) {
            return Err(ShareError::BadPublicKey);
        }
        let mut auth_bytes = [0u8; SHARE_AUTH_PUBLIC_LEN];
        auth_bytes.copy_from_slice(auth_x);
        Ok(SharePublicKey {
            kem,
            auth: x25519_dalek::PublicKey::from(auth_bytes),
            raw,
        })
    }

    /// The raw [`SHARE_PUBLIC_LEN`] identity bytes, as stored and transmitted.
    pub fn to_bytes(&self) -> [u8; SHARE_PUBLIC_LEN] {
        self.raw
    }

    /// The immutable identity ROOT: `derivation_index || pk_sig` (NCF-3 §5.1).
    ///
    /// This is what the address fingerprints and what a wrapping key binds a recipient to — never
    /// the whole bundle, so that a future `key_epoch` bump does not silently change every wrapping
    /// key ever derived for this account.
    pub fn root(&self) -> &[u8; SHARE_ROOT_LEN] {
        self.raw[OFF_DERIVATION_INDEX..OFF_DERIVATION_INDEX + SHARE_ROOT_LEN]
            .try_into()
            .expect("the root is a fixed-width window of a fixed-length bundle")
    }

    /// The layout version this bundle declares. Always [`SHARE_IDENTITY_VERSION`] for anything
    /// that parsed.
    pub fn identity_version(&self) -> u8 {
        self.raw[OFF_VERSION]
    }

    /// The reserved derivation index — always 0 today, and part of the fingerprinted root.
    pub fn derivation_index(&self) -> u32 {
        read_u32(&self.raw, OFF_DERIVATION_INDEX)
    }

    /// The reserved key epoch — always 0 today. Outside the root, inside the signature: bumping it
    /// is how the KEM and authentication keys would be replaced under an unchanged address, once a
    /// replacement flow exists.
    pub fn key_epoch(&self) -> u32 {
        read_u32(&self.raw, OFF_KEY_EPOCH)
    }

    /// The address this identity's ROOT fingerprints to (NCF-3 §5.2).
    pub fn address(&self) -> ShareAddress {
        address_of_root(self.root())
    }
}

impl core::fmt::Debug for SharePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The address is the useful identity here and it is short; dumping five kilobytes into a
        // log line helps nobody.
        f.debug_tuple("SharePublicKey")
            .field(&self.address().display())
            .finish()
    }
}

/// Reads a big-endian `u32` counter out of the bundle.
fn read_u32(raw: &[u8; SHARE_PUBLIC_LEN], at: usize) -> u32 {
    let mut n = [0u8; COUNTER_LEN];
    n.copy_from_slice(&raw[at..at + COUNTER_LEN]);
    u32::from_be_bytes(n)
}

/// The address a given identity root fingerprints to (NCF-3 §5.2).
///
/// Split out from [`SharePublicKey::address`] because the two places that need an account's OWN
/// address — publishing it and stamping it into an envelope — hold the seed rather than a parsed
/// bundle, and building a bundle would mean making a signature to throw it away.
pub fn address_of_root(root: &[u8; SHARE_ROOT_LEN]) -> ShareAddress {
    let mut hasher = Sha256::new();
    hasher.update(HASH_SHARE_ADDRESS);
    hasher.update(root);
    let digest = hasher.finalize();
    let mut out = [0u8; SHARE_ADDRESS_LEN];
    out.copy_from_slice(&digest[..SHARE_ADDRESS_LEN]);
    ShareAddress(out)
}

/// Verifies a bundle's self-signature against the verification key carried in its own root.
///
/// Self-signed is not circular here: the root is what an address pins, so "signed by the key in
/// the root" means "signed by the account that owns this address", as long as the caller has
/// checked the address — which every path into this module does.
fn verify_self_signature(raw: &[u8; SHARE_PUBLIC_LEN]) -> Result<(), ShareError> {
    let encoded_vk: &EncodedVerifyingKey<MlDsa44> = raw[OFF_PK_SIG..OFF_KEY_EPOCH]
        .try_into()
        .expect("the verification key is a fixed-width window of a fixed-length bundle");
    let encoded_sig: &EncodedSignature<MlDsa44> = raw[OFF_SELF_SIG..]
        .try_into()
        .expect("the signature is the fixed-length tail of a fixed-length bundle");
    // A signature that does not decode is refused exactly like one that decodes and fails: the
    // caller learns "this bundle is not genuine" and nothing finer, because a caller that could
    // tell the cases apart would be telling a forger which half of the guess was right.
    let signature =
        Signature::<MlDsa44>::decode(encoded_sig).ok_or(ShareError::BadSelfSignature)?;
    let verifying_key = VerifyingKey::<MlDsa44>::decode(encoded_vk);
    if verifying_key.verify_with_context(
        &raw[..SHARE_SIGNED_LEN],
        SIG_CTX_IDENTITY_BUNDLE,
        &signature,
    ) {
        Ok(())
    } else {
        Err(ShareError::BadSelfSignature)
    }
}

/// The X25519 encodings that produce an all-zero (or otherwise non-contributory) shared secret.
///
/// Taken from the set every implementation that performs this check rejects: the identity, the two
/// order-8 points, the three points of order p / p+1 / p-1, and the high-bit-set spellings of the
/// last three (X25519 masks bit 255 of a public key, so those decode to the same values).
const LOW_ORDER_X25519: [[u8; 32]; 12] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    [
        0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    [
        0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    [
        0xcc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    [
        0x4c, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
];

/// True when `pk` is one of the encodings that agrees to a degenerate shared secret.
fn is_low_order_x25519(pk: &[u8]) -> bool {
    LOW_ORDER_X25519.iter().any(|bad| bad[..] == *pk)
}

/// Generate the account's share keypair from its 32-byte KEM seed.
///
/// Deterministic: the same seed always yields the same keypair, on any device, forever.
fn keypair(share_kem_seed: &[u8; SHARE_KEM_SEED_LEN]) -> DecapsulationKey {
    DecapsulationKey::from(*share_kem_seed)
}

/// The account's static X25519 sender-authentication keypair.
fn auth_keypair(share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN]) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(*share_auth_secret)
}

/// The account's ML-DSA-44 signing key, expanded from its 32-byte seed.
///
/// Deterministic by definition: FIPS 204 Algorithm 6 IS an expansion of ξ, so the same account
/// code produces the same signing key — and therefore the same verification key and the same
/// self-signature — on every device, forever. That is not a convenience here; it is what makes the
/// published identity a single value the server can hold first-writer-wins.
fn sig_keypair(share_sig_seed: &[u8; SHARE_SIG_SEED_LEN]) -> ExpandedSigningKey<MlDsa44> {
    let seed = Zeroizing::new(Seed::from(*share_sig_seed));
    ExpandedSigningKey::<MlDsa44>::from_seed(&seed)
}

/// The identity ROOT for a signing seed and derivation index: `derivation_index || pk_sig`.
///
/// This is the cheap half of building an identity — a key generation and no signature — and it is
/// all that is needed to know an account's own address or to bind a wrapping key to a recipient.
fn identity_root(
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    derivation_index: u32,
) -> [u8; SHARE_ROOT_LEN] {
    let verification_key = sig_keypair(share_sig_seed).verifying_key().encode();
    let mut root = [0u8; SHARE_ROOT_LEN];
    root[..COUNTER_LEN].copy_from_slice(&derivation_index.to_be_bytes());
    root[COUNTER_LEN..].copy_from_slice(&verification_key);
    root
}

/// Derive the published share identity from the account's three secrets (NCF-3 §5.1).
///
/// `derivation_index` and `key_epoch` are written as zero and there is no production way to write
/// anything else: both are reserved space, and publishing a non-zero value needs a replacement
/// flow that does not exist yet.
pub fn public_key(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
) -> SharePublicKey {
    public_key_inner(share_kem_seed, share_auth_secret, share_sig_seed, 0, 0)
}

/// The single body behind [`public_key`] and its counters-supplying twin below.
fn public_key_inner(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    derivation_index: u32,
    key_epoch: u32,
) -> SharePublicKey {
    let kem = keypair(share_kem_seed).encapsulation_key().clone();
    let auth = x25519_dalek::PublicKey::from(&auth_keypair(share_auth_secret));
    let signing_key = sig_keypair(share_sig_seed);

    let mut raw = [0u8; SHARE_PUBLIC_LEN];
    raw[OFF_VERSION] = SHARE_IDENTITY_VERSION;
    raw[OFF_DERIVATION_INDEX..OFF_PK_SIG].copy_from_slice(&derivation_index.to_be_bytes());
    raw[OFF_PK_SIG..OFF_KEY_EPOCH].copy_from_slice(&signing_key.verifying_key().encode());
    raw[OFF_KEY_EPOCH..OFF_PK_KEM].copy_from_slice(&key_epoch.to_be_bytes());
    raw[OFF_PK_KEM..OFF_PK_AUTH].copy_from_slice(&kem.to_bytes()[..]);
    raw[OFF_PK_AUTH..OFF_SELF_SIG].copy_from_slice(auth.as_bytes());

    // ⛔ The DETERMINISTIC variant, never the hedged one — see the module docs. The only way this
    // can fail is a context string longer than 255 bytes, and ours is a compile-time constant.
    let signature = signing_key
        .sign_deterministic(&raw[..SHARE_SIGNED_LEN], SIG_CTX_IDENTITY_BUNDLE)
        .expect("the identity-bundle context is a fixed 23-byte constant");
    raw[OFF_SELF_SIG..].copy_from_slice(&signature.encode());

    SharePublicKey { kem, auth, raw }
}

/// [`public_key`] with the two reserved counters supplied — TESTS AND VECTORS ONLY.
///
/// It exists to prove the property the reserved space was bought for: a bundle with a bumped
/// `key_epoch` is a different published identity with a **different signature** and **the same
/// address**, because the epoch is outside the root. Production cannot express a non-zero value,
/// and must not until a replacement flow is specified — a second bundle for one address is a
/// question about which one is current, and this format does not answer it (NCF-3 §5.2a).
#[cfg(any(test, feature = "vectors"))]
pub fn public_key_with_counters(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    derivation_index: u32,
    key_epoch: u32,
) -> SharePublicKey {
    public_key_inner(
        share_kem_seed,
        share_auth_secret,
        share_sig_seed,
        derivation_index,
        key_epoch,
    )
}

/// The account's own share address, straight from the one secret it depends on.
///
/// ⚠ **Only the signing seed is an input, and that is the point.** Since NCF-3 §5.2a the address
/// fingerprints the root, and the root is the derivation index and the verification key — so an
/// account's address does not move when its KEM or authentication key is replaced. Taking the
/// other two secrets here would say otherwise, and would also mean making a signature nobody reads
/// every time a screen wants to show an address.
pub fn address_for(share_sig_seed: &[u8; SHARE_SIG_SEED_LEN]) -> ShareAddress {
    address_of_root(&identity_root(share_sig_seed, 0))
}

/// The public share ADDRESS a user hands out to be shared with.
///
/// # Why 16 bytes is enough
/// Impersonating a *specific* address means finding a **preimage** — a keypair whose public key
/// hashes to that exact 128-bit value — which is 2¹²⁸ work, not the 2⁶⁴ a birthday bound would
/// suggest. A collision attack only produces two addresses that collide with each other, and the
/// address an attacker must match is fixed by their target's account code, not chosen by them.
///
/// # Why a typed code and not raw base64
/// This value is pasted into chat, read aloud, and re-typed. Base64url of 16 bytes is 22
/// characters with case-sensitive `l`/`I`/`O`/`0` collisions and no way to tell a typo from a real
/// address that simply does not exist — so a mistyped character would silently resolve to "no such
/// account", or worse, to somebody else's. The Crockford form NMTS already uses for account codes
/// folds those collisions away and carries a check symbol, so a typo is rejected locally before
/// any lookup leaves the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareAddress(pub [u8; SHARE_ADDRESS_LEN]);

impl ShareAddress {
    /// The raw 16 bytes — what the server stores and indexes.
    pub fn as_bytes(&self) -> &[u8; SHARE_ADDRESS_LEN] {
        &self.0
    }

    /// The display form: `XXXXXXXXX-XXXXXXXXX-XXXXXXXXC` (27 symbols, check symbol last).
    pub fn display(&self) -> String {
        codes::encode_checked_grouped(&self.0, SHARE_ADDRESS_GROUP)
    }

    /// Parses a user-entered address (any spacing/case/aliasing), verifying the check symbol.
    pub fn parse(input: &str) -> Result<Self, ShareError> {
        let bytes = codes::parse_checked(input, SHARE_ADDRESS_SYMBOLS, SHARE_ADDRESS_LEN)
            .map_err(ShareError::BadAddress)?;
        let mut out = [0u8; SHARE_ADDRESS_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

/// Check that a public key the server handed over really belongs to `address` (NCF-3 §5.2).
///
/// **Every path that obtains a recipient key from the server must go through this**, and there is
/// deliberately no way to wrap a DEK without it: [`wrap_dek_for`] takes the address as an argument
/// rather than trusting the caller to have checked.
pub fn verify_address(key: &SharePublicKey, address: &ShareAddress) -> Result<(), ShareError> {
    if &key.address() == address {
        Ok(())
    } else {
        Err(ShareError::AddressMismatch)
    }
}

/// Derive the wrapping key for one encapsulation.
///
/// The KEM ciphertext, the recipient's ROOT and the payload commitment go into the HKDF `info`, so
/// the key is bound to exactly this (encapsulation, recipient, sender, row) — see the module docs.
///
/// ⚠ **The root, not the whole published bundle** (NCF-3 §5.3, revised 2026-08-02). The recipient
/// recomputes this value from its own secrets at unwrap time, and it has no way to know which
/// version of its bundle the sender was looking at; binding the mutable part would mean an
/// envelope stops opening the day a key is replaced, or a retry loop over epochs, and a retry loop
/// is the shape this module refuses everywhere else. Nothing is lost: the EXACT KEM key is already
/// bound through `kem_ciphertext` here and through ML-KEM's own derivation, the EXACT
/// authentication key is bound through `ss_auth`, and both were verified against the root before
/// any of this ran.
fn wrap_key(
    ss_kem: &[u8; 32],
    ss_auth: &[u8; 32],
    sender_address: &ShareAddress,
    kem_ciphertext: &[u8; KEM_CIPHERTEXT_LEN],
    recipient_root: &[u8; SHARE_ROOT_LEN],
    payload_commitment: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    // Both secrets are input keying material, concatenated — NOT combined by hand. Concatenating
    // and letting HKDF-Extract do the mixing is the standard shape; XOR-ing them would not be.
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_kem);
    ikm[32..].copy_from_slice(ss_auth);

    let mut info = Vec::with_capacity(
        AAD_SHARE_WRAP.len() + SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN + SHARE_ROOT_LEN + 32,
    );
    info.extend_from_slice(AAD_SHARE_WRAP);
    info.extend_from_slice(sender_address.as_bytes());
    info.extend_from_slice(kem_ciphertext);
    info.extend_from_slice(recipient_root);
    info.extend_from_slice(payload_commitment);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(b""), &*ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *key)
        .expect("HKDF expand length within bounds");
    key
}

/// Wrap a file DEK for one recipient. Returns the [`SHARE_ENVELOPE_LEN`]-byte share envelope.
///
/// `address` is the address the SENDER was given out of band; `recipient` is the key the server
/// returned for it. The two are checked against each other first, so a substituted key fails here
/// rather than silently handing the server a readable DEK.
///
/// A fresh encapsulation is drawn from the OS CSPRNG every time, so wrapping the SAME DEK for the
/// SAME recipient twice yields unrelated bytes — otherwise the server could tell "these two shares
/// went to the same person" from the ciphertext alone, which is the exact correlation this product
/// exists to avoid.
///
/// `payload` is the row this envelope belongs beside, and it must be the row that is actually
/// POSTed. It is bound into the wrapping key, so an envelope stored next to different columns
/// stops opening (defect A6) — which also means the name and digest have to be sealed BEFORE this
/// is called, not after.
pub fn wrap_dek_for(
    sender_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    sender_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    recipient: &SharePublicKey,
    address: &ShareAddress,
    dek: &[u8; DEK_LEN],
    payload: &SharePayload<'_>,
) -> Result<Vec<u8>, ShareError> {
    // Both random values come from THIS crate's single audited CSPRNG seam (`rng::OsRng`, which is
    // `crypto.getRandomValues` in the browser build) rather than from the KEM crate's own rand
    // plumbing, which speaks a different `rand_core` generation. One randomness source for the
    // whole crate is an invariant worth more than the convenience — see `rng.rs`.
    //
    // ⚠ An envelope has TWO independent random inputs, not one: the KEM's 64-byte `eseed` and the
    // 24-byte nonce of the sealed-DEK envelope. Fixing only the first leaves the last 104 bytes
    // unreproducible, which is why the vectors-only twin below takes both. Reusing either even
    // once would be catastrophic, so they are drawn here and never stored.
    let kem_eseed = Zeroizing::new(crate::rng::OsRng::bytes::<KEM_RANDOMNESS_LEN>());
    let envelope_nonce = crate::rng::OsRng::bytes::<{ wrap::ENVELOPE_NONCE_LEN }>();
    wrap_dek_for_inner(
        sender_auth_secret,
        sender_sig_seed,
        recipient,
        address,
        dek,
        payload,
        &EnvelopeRandomness {
            kem_eseed: &kem_eseed,
            envelope_nonce: &envelope_nonce,
        },
    )
}

/// The two independent random inputs behind one share envelope.
///
/// They travel as one value because an envelope is not reproducible without BOTH, and a seam that
/// took only one would look complete while quietly fixing half the randomness — which is how a
/// "deterministic" path ends up emitting bytes a server can correlate. Keeping them together means
/// a caller cannot supply one and forget the other.
pub struct EnvelopeRandomness<'a> {
    /// X-Wing encapsulation randomness (`eseed`).
    pub kem_eseed: &'a [u8; KEM_RANDOMNESS_LEN],
    /// Nonce for the sealed DEK at the envelope's tail.
    pub envelope_nonce: &'a [u8; wrap::ENVELOPE_NONCE_LEN],
}

/// The single implementation behind [`wrap_dek_for`] and its vectors-only twin.
///
/// It exists so there is exactly ONE body: a separate deterministic copy could drift from the
/// production path, and the committed vectors would then attest to a construction nothing ships.
/// Both random inputs are parameters here — the caller above draws them, the vectors caller
/// supplies them — which is the same split [`wrap::seal`] and `wrap::seal_with_nonce` use.
fn wrap_dek_for_inner(
    sender_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    sender_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    recipient: &SharePublicKey,
    address: &ShareAddress,
    dek: &[u8; DEK_LEN],
    payload: &SharePayload<'_>,
    randomness: &EnvelopeRandomness<'_>,
) -> Result<Vec<u8>, ShareError> {
    verify_address(recipient, address)?;
    let payload_commitment = payload.commitment()?;

    let (ct, ss) = recipient
        .kem
        .encapsulate_deterministic(randomness.kem_eseed.into());
    let mut ct_bytes = [0u8; KEM_CIPHERTEXT_LEN];
    ct_bytes.copy_from_slice(&ct[..]);
    let mut ss_kem = Zeroizing::new([0u8; 32]);
    ss_kem.copy_from_slice(&ss[..]);

    // The static-static half: only the holder of THIS account's auth secret can compute it, and
    // only the intended recipient can recompute it. That is what turns "an envelope for you" into
    // "an envelope for you, from me".
    let sender_address = address_for(sender_sig_seed);
    let ss_auth = Zeroizing::new(
        auth_keypair(sender_auth_secret)
            .diffie_hellman(&recipient.auth)
            .to_bytes(),
    );

    let key = wrap_key(
        &ss_kem,
        &ss_auth,
        &sender_address,
        &ct_bytes,
        recipient.root(),
        &payload_commitment,
    );

    let mut out = Vec::with_capacity(SHARE_ENVELOPE_LEN);
    out.extend_from_slice(sender_address.as_bytes());
    out.extend_from_slice(&ct_bytes);
    out.extend_from_slice(&wrap::seal_inner(
        &key,
        randomness.envelope_nonce,
        AAD_SHARE_WRAP,
        dek,
    ));
    debug_assert_eq!(out.len(), SHARE_ENVELOPE_LEN);
    Ok(out)
}

/// The sender address an envelope claims, without opening it.
///
/// The claim is only a claim until [`unwrap_dek`] succeeds — it is bound into the wrapping key, so
/// an envelope that opens is one whose sender address is correct. This exists so a caller can know
/// WHICH identity to fetch before it can verify anything.
pub fn claimed_sender(envelope: &[u8]) -> Result<ShareAddress, ShareError> {
    if envelope.len() != SHARE_ENVELOPE_LEN {
        return Err(ShareError::BadEnvelopeLength);
    }
    let mut addr = [0u8; SHARE_ADDRESS_LEN];
    addr.copy_from_slice(&envelope[..SHARE_ADDRESS_LEN]);
    Ok(ShareAddress(addr))
}

/// Unwrap a share envelope addressed to us, returning the file DEK.
///
/// `sender` is the identity the caller fetched for the address the envelope claims — see
/// [`claimed_sender`]. `payload` is the rest of the row the envelope arrived in.
///
/// Fails with [`ShareError::Auth`] for an envelope meant for someone else, **equally for one whose
/// claimed sender did not produce it**, and **equally for one stored beside a name, digest or item
/// id the sender did not wrap** (defect A6). The three are indistinguishable by design. There is
/// no branch that retries with a different construction: ML-KEM answers a bad ciphertext with a
/// random-looking secret rather than an error, so the only correct response to "it did not open"
/// is to stop.
pub fn unwrap_dek(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    sender: &SharePublicKey,
    envelope: &[u8],
    payload: &SharePayload<'_>,
) -> Result<Zeroizing<[u8; DEK_LEN]>, ShareError> {
    if envelope.len() != SHARE_ENVELOPE_LEN {
        return Err(ShareError::BadEnvelopeLength);
    }
    // Built from the columns the caller was served. A row whose name, digest or item id is not
    // the one the sender wrapped derives a different key and does not open (defect A6).
    let payload_commitment = payload.commitment()?;
    // The claimed sender address must belong to the identity the caller fetched for it. Without
    // this, a caller could be handed any identity and the agreement below would be computed
    // against a key that has nothing to do with the name shown to the person.
    let claimed = claimed_sender(envelope)?;
    verify_address(sender, &claimed)?;

    let (_, rest) = envelope.split_at(SHARE_ADDRESS_LEN);
    let (ct_bytes, sealed) = rest.split_at(KEM_CIPHERTEXT_LEN);
    let ct_bytes: [u8; KEM_CIPHERTEXT_LEN] = ct_bytes
        .try_into()
        .expect("split at KEM_CIPHERTEXT_LEN yields exactly 1120 bytes");

    let sk = keypair(share_kem_seed);
    // Our own root, recomputed here rather than fetched: the sender bound the wrapping key to what
    // the ADDRESS pins, so the recipient can rebuild the exact same bytes from the account code
    // without knowing which version of its bundle the sender had. That is what the narrowing in
    // `wrap_key` bought.
    let our_root = identity_root(share_sig_seed, 0);
    let ct: &Ciphertext = (&ct_bytes).into();
    let ss = sk.decapsulate(ct);
    let mut ss_kem = Zeroizing::new([0u8; 32]);
    ss_kem.copy_from_slice(&ss[..]);

    let ss_auth = Zeroizing::new(
        auth_keypair(share_auth_secret)
            .diffie_hellman(&sender.auth)
            .to_bytes(),
    );

    let key = wrap_key(
        &ss_kem,
        &ss_auth,
        &claimed,
        &ct_bytes,
        &our_root,
        &payload_commitment,
    );

    // ⚠ THE SENDER CHECK AND THE PAYLOAD CHECK ARE THIS LINE. There is no separate "is the sender
    // genuine?" or "does this row belong to this envelope?" step: a wrong sender yields a
    // different `ss_auth` and a swapped column yields a different commitment, either of which
    // changes the wrapping key and stops the envelope opening. So "it opened", "the claimed
    // sender really sent it" and "these are the columns they sent it with" are one fact, and no
    // caller can take one without the others.
    let pt = Zeroizing::new(wrap::open(&key, AAD_SHARE_WRAP, sealed)?);
    if pt.len() != DEK_LEN {
        return Err(ShareError::Auth);
    }
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    dek.copy_from_slice(&pt);
    Ok(dek)
}

// ---------------------------------------------------------------------------------------
// Deterministic wrapping — VECTORS ONLY.
//
// This bypasses the "no caller randomness" production rule so the committed conformance
// vectors are byte-exact and reproducible. It is compiled only under `test` or the
// `vectors` feature and must never be reachable from a production build.
// ---------------------------------------------------------------------------------------

/// Deterministic [`wrap_dek_for`] with caller-supplied randomness, for the conformance vectors
/// only.
///
/// Takes BOTH of the envelope's random inputs, because an envelope is not reproducible without
/// both: `randomness` is the KEM's 64-byte `eseed`, and `envelope_nonce` is the 24-byte nonce of
/// the sealed DEK at the tail. Reusing either across two envelopes to one recipient reproduces
/// bytes the server could correlate — which is exactly what [`wrap_dek_for`] draws fresh values to
/// prevent, and exactly why this is vectors only.
///
/// Compiled only under `test` or the `vectors` feature; production code must use
/// [`wrap_dek_for`], whose signature cannot express a caller-chosen value.
#[cfg(any(test, feature = "vectors"))]
pub fn wrap_dek_for_with_randomness(
    sender_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    sender_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    recipient: &SharePublicKey,
    address: &ShareAddress,
    dek: &[u8; DEK_LEN],
    payload: &SharePayload<'_>,
    randomness: &EnvelopeRandomness<'_>,
) -> Result<Vec<u8>, ShareError> {
    wrap_dek_for_inner(
        sender_auth_secret,
        sender_sig_seed,
        recipient,
        address,
        dek,
        payload,
        randomness,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEM_A: [u8; SHARE_KEM_SEED_LEN] = [11u8; SHARE_KEM_SEED_LEN];
    const AUTH_A: [u8; SHARE_AUTH_SECRET_LEN] = [12u8; SHARE_AUTH_SECRET_LEN];
    const SIG_A: [u8; SHARE_SIG_SEED_LEN] = [13u8; SHARE_SIG_SEED_LEN];
    const KEM_B: [u8; SHARE_KEM_SEED_LEN] = [22u8; SHARE_KEM_SEED_LEN];
    const AUTH_B: [u8; SHARE_AUTH_SECRET_LEN] = [23u8; SHARE_AUTH_SECRET_LEN];
    const SIG_B: [u8; SHARE_SIG_SEED_LEN] = [24u8; SHARE_SIG_SEED_LEN];
    const KEM_C: [u8; SHARE_KEM_SEED_LEN] = [33u8; SHARE_KEM_SEED_LEN];
    const AUTH_C: [u8; SHARE_AUTH_SECRET_LEN] = [34u8; SHARE_AUTH_SECRET_LEN];
    const SIG_C: [u8; SHARE_SIG_SEED_LEN] = [35u8; SHARE_SIG_SEED_LEN];

    fn id_a() -> SharePublicKey {
        public_key(&KEM_A, &AUTH_A, &SIG_A)
    }
    fn id_b() -> SharePublicKey {
        public_key(&KEM_B, &AUTH_B, &SIG_B)
    }
    fn id_c() -> SharePublicKey {
        public_key(&KEM_C, &AUTH_C, &SIG_C)
    }

    /// A stand-in share row for the tests that are about something OTHER than the A6 binding.
    /// The bytes are arbitrary; both sides of a round trip just have to use the same ones.
    const T_ITEM_ID: &[u8] = b"6a0f2b1c-1111-4222-8333-444455556666";
    const T_NAME_CT: &[u8] = &[0xA1; 61];
    const T_HASH_CT: &[u8] = &[0xB2; 104];

    fn t_payload() -> SharePayload<'static> {
        SharePayload {
            item_id: T_ITEM_ID,
            name_ct: T_NAME_CT,
            content_hash_ct: T_HASH_CT,
        }
    }

    /// A wraps a DEK for B.
    fn a_to_b(dek: &[u8; DEK_LEN]) -> Vec<u8> {
        let b = id_b();
        wrap_dek_for(&AUTH_A, &SIG_A, &b, &b.address(), dek, &t_payload()).expect("wrap")
    }

    #[test]
    fn a_wrapped_dek_opens_for_the_recipient_and_nobody_else() {
        let dek = [5u8; DEK_LEN];
        let env = a_to_b(&dek);
        assert_eq!(env.len(), SHARE_ENVELOPE_LEN);

        assert_eq!(
            *unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &env, &t_payload()).expect("unwrap"),
            dek,
        );
        // C is not the recipient, even holding the real sender identity.
        assert_eq!(
            unwrap_dek(&KEM_C, &AUTH_C, &SIG_C, &id_a(), &env, &t_payload()).unwrap_err(),
            ShareError::Auth,
        );
    }

    #[test]
    fn an_envelope_cannot_be_opened_under_a_false_sender() {
        // The A3 fix (adversarial review, 2026-07-29). Before this, an envelope proved who it was FOR and never
        // who it was FROM, so the "from" line in an inbox was whatever the server said.
        let dek = [6u8; DEK_LEN];
        let env = a_to_b(&dek);

        // The claim in the envelope is A's address, and only A's identity opens it.
        assert_eq!(claimed_sender(&env).expect("claim"), id_a().address());
        assert!(unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &env, &t_payload()).is_ok());

        // Handing the opener a DIFFERENT identity fails at the fingerprint check…
        assert_eq!(
            unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_c(), &env, &t_payload()).unwrap_err(),
            ShareError::AddressMismatch,
        );

        // …and rewriting the claimed address so it DOES match that identity fails too, because
        // the address is bound into the wrapping key. There is no way to relabel an envelope.
        let mut relabelled = env.clone();
        relabelled[..SHARE_ADDRESS_LEN].copy_from_slice(id_c().address().as_bytes());
        assert_eq!(
            unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_c(), &relabelled, &t_payload()).unwrap_err(),
            ShareError::Auth,
        );
    }

    #[test]
    fn a_forger_holding_only_public_keys_cannot_produce_an_openable_envelope() {
        // Anyone can encapsulate to B — the key is public. What they cannot do is agree with B's
        // authentication key as A, so C's forgery does not open even though C addresses it
        // correctly and even though C is a real account.
        let dek = [7u8; DEK_LEN];
        let b = id_b();
        let forged =
            wrap_dek_for(&AUTH_C, &SIG_C, &b, &b.address(), &dek, &t_payload()).expect("wrap");

        // It opens as what it is — a share from C.
        assert_eq!(claimed_sender(&forged).expect("claim"), id_c().address());
        assert!(unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_c(), &forged, &t_payload()).is_ok());
        // It cannot be passed off as a share from A.
        assert_eq!(
            unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &forged, &t_payload()).unwrap_err(),
            ShareError::AddressMismatch,
        );
    }

    #[test]
    fn the_address_is_a_fingerprint_of_the_identity_root() {
        // This is the A1 fix. A key the server did not get from this account must not pass the
        // address check — that is the whole mechanism, so it gets a test that states it directly.
        let b = id_b();
        let attacker = id_a();

        assert!(verify_address(&b, &b.address()).is_ok());
        assert_eq!(
            verify_address(&attacker, &b.address()).unwrap_err(),
            ShareError::AddressMismatch,
        );

        // And wrapping refuses it, so there is no path that skips the check.
        assert_eq!(
            wrap_dek_for(
                &AUTH_A,
                &SIG_A,
                &attacker,
                &b.address(),
                &[1u8; DEK_LEN],
                &t_payload()
            )
            .unwrap_err(),
            ShareError::AddressMismatch,
        );

        // What the fingerprint covers, stated exactly (NCF-3 §5.2a, revised 2026-08-02): the ROOT
        // and nothing else. Two accounts differing only in their signing seed have different
        // addresses…
        assert_ne!(
            public_key(&KEM_B, &AUTH_B, &SIG_C).address(),
            b.address(),
            "the signing key is the root, so it must move the address"
        );
        // …and an account that changed only its KEM or authentication key keeps the SAME address.
        // That is the capability this revision bought, and it is only safe because the
        // self-signature — not the fingerprint — is what ties those two keys to the root.
        assert_eq!(
            public_key(&KEM_C, &AUTH_C, &SIG_B).address(),
            b.address(),
            "the working keys sit outside the root, so replacing them must not move the address"
        );
        assert_eq!(
            public_key(&KEM_C, &AUTH_C, &SIG_B).root(),
            b.root(),
            "…and the reason is that the root itself is unchanged"
        );
        assert_ne!(
            public_key(&KEM_C, &AUTH_C, &SIG_B).to_bytes(),
            b.to_bytes(),
            "the published bundles must still differ — same address, different keys"
        );
    }

    /// The bundle carries its own proof of authorship, and altering ANY of the bytes it covers
    /// destroys that proof. This is what stops a server handing a sender a genuine root with
    /// substituted working keys — the attack the fingerprint used to prevent by covering
    /// everything, and which §5.2a now prevents by signature so that the account itself can still
    /// change those keys.
    #[test]
    fn a_tampered_bundle_is_refused_at_parse() {
        let good = id_a().to_bytes();
        assert!(SharePublicKey::from_bytes(&good).is_ok());

        // One flipped bit anywhere in the signed prefix, and anywhere in the signature itself.
        for at in [
            OFF_VERSION + 1,        // derivation index
            OFF_PK_SIG,             // the verification key
            OFF_KEY_EPOCH,          // the reserved epoch
            OFF_PK_KEM,             // the KEM key
            OFF_PK_AUTH,            // the authentication key
            OFF_SELF_SIG,           // the signature's first byte
            SHARE_PUBLIC_LEN - 1,   // and its last
        ] {
            let mut bad = good;
            bad[at] ^= 0x01;
            let err = SharePublicKey::from_bytes(&bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    ShareError::BadSelfSignature | ShareError::BadPublicKey
                ),
                "flipping byte {at} must not yield a usable identity, got {err:?}",
            );
        }

        // The whole working half swapped for another account's — the substitution the signature
        // exists to catch. Both keys are individually valid; what is missing is authorisation.
        let mut swapped = good;
        swapped[OFF_PK_KEM..OFF_SELF_SIG].copy_from_slice(&id_b().to_bytes()[OFF_PK_KEM..OFF_SELF_SIG]);
        assert_eq!(
            SharePublicKey::from_bytes(&swapped).unwrap_err(),
            ShareError::BadSelfSignature,
            "keys the root never signed must not be usable, even though each is well formed",
        );
    }

    /// An identity claiming a version this build does not know is refused outright — never parsed
    /// by the rule this build happens to implement, because that is how a reader is talked into
    /// using a key the writer had already replaced.
    #[test]
    fn an_unknown_identity_version_is_refused() {
        let good = id_a().to_bytes();
        for version in [0x00u8, 0x02, 0x04, 0xff] {
            let mut bad = good;
            bad[OFF_VERSION] = version;
            assert_eq!(
                SharePublicKey::from_bytes(&bad).unwrap_err(),
                ShareError::UnknownIdentityVersion(version),
                "version {version} must be refused rather than parsed by the v1 rule",
            );
        }
        // And the refusal happens BEFORE the signature is even looked at: re-signing the bundle
        // under its new version byte does not buy an unknown version a way in.
        let mut bad = good;
        bad[OFF_VERSION] = 0x02;
        let resigned = resign(bad, &SIG_A);
        assert_eq!(
            SharePublicKey::from_bytes(&resigned).unwrap_err(),
            ShareError::UnknownIdentityVersion(0x02),
        );
    }

    /// Two devices, one account code: the published identity must be **byte-identical**, or the
    /// server's first-writer-wins column rejects the account's own second device forever and the
    /// account screen reports a mismatch that is not one. This is why only the deterministic FIPS
    /// 204 variant is ever called.
    #[test]
    fn the_same_account_produces_byte_identical_bundles_on_every_device() {
        let device_one = public_key(&KEM_A, &AUTH_A, &SIG_A).to_bytes();
        let device_two = public_key(&KEM_A, &AUTH_A, &SIG_A).to_bytes();
        assert_eq!(
            device_one, device_two,
            "a hedged signature would show up here as two different published identities",
        );
        // Including the signature itself, which is the half a hedged variant would move.
        assert_eq!(
            device_one[OFF_SELF_SIG..],
            device_two[OFF_SELF_SIG..],
            "the self-signature must be a function of the account code alone",
        );
    }

    /// The reserved space does what it was bought for: a bundle with a bumped `key_epoch` is a
    /// different published identity, signed afresh, at the **same address**. Production cannot
    /// produce one — this is the tests-only constructor — but if the address moved, the space
    /// would be reserved for nothing.
    #[test]
    fn bumping_the_key_epoch_keeps_the_address() {
        let now = public_key(&KEM_A, &AUTH_A, &SIG_A);
        let later = public_key_with_counters(&KEM_C, &AUTH_C, &SIG_A, 0, 7);

        assert_eq!(later.key_epoch(), 7);
        assert_eq!(now.key_epoch(), 0, "production always writes zero");
        assert_eq!(
            later.address(),
            now.address(),
            "the epoch sits outside the root, so an address survives a key replacement",
        );
        assert_ne!(later.to_bytes(), now.to_bytes());
        // And the newer bundle stands on its own: it verifies, because the same root signed it.
        assert!(SharePublicKey::from_bytes(&later.to_bytes()).is_ok());

        // The derivation index, by contrast, is INSIDE the root — a different index is a
        // different address by construction, which is what makes it usable for future
        // multiple-address accounts rather than for key replacement.
        let other_index = public_key_with_counters(&KEM_A, &AUTH_A, &SIG_A, 1, 0);
        assert_eq!(other_index.derivation_index(), 1);
        assert_ne!(other_index.address(), now.address());
    }

    /// Two independent implementations of ML-DSA-44 must agree on our bytes, or "we follow FIPS
    /// 204" is our own word for it. `fips204` is a dev-dependency and ships in nothing; it is here
    /// as a control, not as a second engine.
    #[test]
    fn an_independent_implementation_agrees_on_the_key_and_the_signature() {
        use fips204::traits::{KeyGen as _, SerDes, Signer as _, Verifier as _};

        let seed = SIG_A;
        let message = b"the identity bundle stands in for any message here";

        let ours = sig_keypair(&seed);
        let our_vk = ours.verifying_key().encode();
        let our_sig = ours
            .sign_deterministic(message, SIG_CTX_IDENTITY_BUNDLE)
            .expect("context is short")
            .encode();

        let (their_vk, their_sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&seed);
        let their_vk_bytes = their_vk.into_bytes();
        // FIPS 204's deterministic variant is `rnd = 0^32`, which is what both crates call
        // deterministic signing; `try_sign_with_seed` takes that value explicitly.
        let their_sig = their_sk
            .try_sign_with_seed(&[0u8; 32], message, SIG_CTX_IDENTITY_BUNDLE)
            .expect("deterministic signature");

        assert_eq!(
            hex_of(&our_vk),
            hex_of(&their_vk_bytes),
            "the same seed must give the same verification key in both implementations",
        );
        assert_eq!(
            hex_of(&our_sig),
            hex_of(&their_sig),
            "deterministic signing must be byte-identical, or our vectors pin an accident",
        );
        assert_eq!(our_vk.len(), SHARE_SIG_PUBLIC_LEN);
        assert_eq!(our_sig.len(), SHARE_SELF_SIG_LEN);

        // And each accepts the other's signature, which is the check that a matching byte string
        // is actually a valid signature rather than two implementations sharing one bug.
        let their_vk = fips204::ml_dsa_44::PublicKey::try_from_bytes(their_vk_bytes)
            .expect("verification key round-trips");
        let our_sig_bytes: &[u8; SHARE_SELF_SIG_LEN] =
            our_sig[..].try_into().expect("2420 bytes");
        assert!(their_vk.verify(message, our_sig_bytes, SIG_CTX_IDENTITY_BUNDLE));
        let encoded: &EncodedSignature<MlDsa44> =
            their_sig[..].try_into().expect("2420 bytes");
        assert!(ours.verifying_key().verify_with_context(
            message,
            SIG_CTX_IDENTITY_BUNDLE,
            &Signature::<MlDsa44>::decode(encoded).expect("their signature decodes"),
        ));
    }

    /// Re-signs a bundle whose body a test has edited.
    ///
    /// Needed because most tampering is caught by the signature first, which would hide whatever
    /// the test was actually about. An account CAN publish a self-consistent bundle carrying a bad
    /// working key, so the checks after the signature have to be exercised on one.
    fn resign(
        mut raw: [u8; SHARE_PUBLIC_LEN],
        sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    ) -> [u8; SHARE_PUBLIC_LEN] {
        let signature = sig_keypair(sig_seed)
            .sign_deterministic(&raw[..SHARE_SIGNED_LEN], SIG_CTX_IDENTITY_BUNDLE)
            .expect("context is short");
        raw[OFF_SELF_SIG..].copy_from_slice(&signature.encode());
        raw
    }

    /// Lowercase hex, for the cross-implementation comparison above.
    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn identity_is_deterministic_from_the_secrets() {
        // A recipient re-entering their account code on a new device must land on the same
        // address, or every share they ever published stops arriving.
        assert_eq!(id_a().to_bytes(), public_key(&KEM_A, &AUTH_A, &SIG_A).to_bytes());
        assert_eq!(address_for(&SIG_A), address_for(&SIG_A));
        assert_ne!(address_for(&SIG_A), address_for(&SIG_B));
        assert_eq!(id_a().to_bytes().len(), SHARE_PUBLIC_LEN);
    }

    #[test]
    fn two_wraps_of_one_dek_to_one_recipient_look_unrelated() {
        // Otherwise the server can link two shares to the same recipient from the bytes alone.
        // ⚠ The first 16 bytes ARE equal by design — they are the sender's address, which the
        // server already stores in its own column. What must not repeat is everything after it.
        let dek = [9u8; DEK_LEN];
        let one = a_to_b(&dek);
        let two = a_to_b(&dek);
        assert_ne!(one[SHARE_ADDRESS_LEN..], two[SHARE_ADDRESS_LEN..]);
        assert_eq!(
            *unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &one, &t_payload()).expect("unwrap"),
            dek
        );
        assert_eq!(
            *unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &two, &t_payload()).expect("unwrap"),
            dek
        );
    }

    #[test]
    fn a_tampered_envelope_does_not_open() {
        let dek = [3u8; DEK_LEN];
        let env = a_to_b(&dek);

        for at in [
            0usize,
            SHARE_ADDRESS_LEN,
            SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN - 1,
            SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN,
            SHARE_ENVELOPE_LEN - 1,
        ] {
            let mut bad = env.clone();
            bad[at] ^= 0x01;
            assert!(
                unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &bad, &t_payload()).is_err(),
                "flipping byte {at} must not yield a DEK",
            );
        }

        assert_eq!(
            unwrap_dek(
                &KEM_B,
                &AUTH_B,
                &SIG_B,
                &id_a(),
                &env[..env.len() - 1],
                &t_payload()
            )
            .unwrap_err(),
            ShareError::BadEnvelopeLength,
        );
    }

    #[test]
    fn a_degenerate_x25519_half_is_refused() {
        // Found by an adversarial review (2026-07-29): the spec promised this check and nothing performed it. A key
        // whose ML-KEM half is real but whose X25519 half is a low-order point parses, fingerprints
        // normally, and passes the address check — while silently reducing every share sent to that
        // address to ML-KEM alone. Because addresses are immutable, that degradation would be
        // permanent and invisible. BOTH X25519 halves are checked: the one inside the KEM key and
        // the standalone authentication key.
        //
        // ⚠ Each bundle below is RE-SIGNED after the substitution. That is not a convenience —
        // it is the threat. The account itself is what publishes an identity, so a degenerate key
        // arrives inside a bundle its own root signed, and the signature check waves it through.
        // Testing an unsigned edit would only prove the signature works.
        let good = id_a().to_bytes();
        let mut one = [0u8; 32];
        one[0] = 1;
        for bad in [[0u8; 32], one] {
            for offset in [OFF_PK_AUTH - 32, OFF_PK_AUTH] {
                let mut key = good;
                key[offset..offset + 32].copy_from_slice(&bad);
                assert_eq!(
                    SharePublicKey::from_bytes(&resign(key, &SIG_A)).unwrap_err(),
                    ShareError::BadPublicKey,
                    "a low-order X25519 half at offset {offset} must not parse",
                );
            }
        }
        assert!(SharePublicKey::from_bytes(&good).is_ok());
    }

    #[test]
    fn public_keys_are_validated_on_receipt() {
        let good = id_a().to_bytes();
        assert!(SharePublicKey::from_bytes(&good).is_ok());
        assert_eq!(
            SharePublicKey::from_bytes(&good[..SHARE_PUBLIC_LEN - 1]).unwrap_err(),
            ShareError::BadPublicKey,
        );
        assert_eq!(
            SharePublicKey::from_bytes(&[0u8; SHARE_PUBLIC_LEN + 1]).unwrap_err(),
            ShareError::BadPublicKey,
        );
    }

    #[test]
    fn the_deterministic_seam_produces_envelopes_the_production_path_accepts() {
        // The vectors-only entry point must not be a second implementation. It shares
        // `wrap_dek_for_inner` with production, and this pins the two observable consequences:
        // the same randomness reproduces the same bytes (that is what makes a committed vector a
        // contract), and those bytes open through the ordinary `unwrap_dek`, which knows nothing
        // about where the encapsulation came from.
        let dek = [4u8; DEK_LEN];
        let b = id_b();
        let eseed = [0x5au8; KEM_RANDOMNESS_LEN];
        let nonce = [0x6bu8; wrap::ENVELOPE_NONCE_LEN];

        let one = wrap_dek_for_with_randomness(
            &AUTH_A,
            &SIG_A,
            &b,
            &b.address(),
            &dek,
            &t_payload(),
            &EnvelopeRandomness {
                kem_eseed: &eseed,
                envelope_nonce: &nonce,
            },
        )
        .expect("wrap");
        let two = wrap_dek_for_with_randomness(
            &AUTH_A,
            &SIG_A,
            &b,
            &b.address(),
            &dek,
            &t_payload(),
            &EnvelopeRandomness {
                kem_eseed: &eseed,
                envelope_nonce: &nonce,
            },
        )
        .expect("wrap");
        assert_eq!(
            one, two,
            "fixed randomness must give a reproducible envelope"
        );
        assert_eq!(one.len(), SHARE_ENVELOPE_LEN);
        assert_eq!(
            *unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &one, &t_payload()).expect("unwrap"),
            dek
        );

        // Both random inputs matter. Holding the `eseed` and changing only the envelope nonce
        // still moves the bytes — this is the assertion that would have caught the seam taking
        // one of the two and calling the result deterministic.
        let other_nonce = [0x7cu8; wrap::ENVELOPE_NONCE_LEN];
        let three = wrap_dek_for_with_randomness(
            &AUTH_A,
            &SIG_A,
            &b,
            &b.address(),
            &dek,
            &t_payload(),
            &EnvelopeRandomness {
                kem_eseed: &eseed,
                envelope_nonce: &other_nonce,
            },
        )
        .expect("wrap");
        assert_eq!(
            one[..SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN],
            three[..SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN],
            "the same eseed must give the same encapsulation",
        );
        assert_ne!(
            one[SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN..],
            three[SHARE_ADDRESS_LEN + KEM_CIPHERTEXT_LEN..],
            "a different envelope nonce must give a different sealed DEK",
        );

        // The address check lives in the shared body, so the seam cannot skip it either.
        assert_eq!(
            wrap_dek_for_with_randomness(
                &AUTH_A,
                &SIG_A,
                &id_a(),
                &b.address(),
                &dek,
                &t_payload(),
                &EnvelopeRandomness {
                    kem_eseed: &eseed,
                    envelope_nonce: &nonce,
                },
            )
            .unwrap_err(),
            ShareError::AddressMismatch,
        );

        // Production, by contrast, cannot be pinned to a value: the same call twice differs.
        let fresh_one =
            wrap_dek_for(&AUTH_A, &SIG_A, &b, &b.address(), &dek, &t_payload()).expect("wrap");
        let fresh_two =
            wrap_dek_for(&AUTH_A, &SIG_A, &b, &b.address(), &dek, &t_payload()).expect("wrap");
        assert_ne!(
            fresh_one[SHARE_ADDRESS_LEN..],
            fresh_two[SHARE_ADDRESS_LEN..]
        );
    }

    /// **The A6 fix, stated end to end.** An envelope must not open beside a row the sender did
    /// not wrap — not even a row a colluding co-recipient could legitimately have sealed, since
    /// they hold the same DEK.
    #[test]
    fn a_rewritten_row_stops_the_envelope_from_opening() {
        let b = id_b();
        let dek = [0x5Au8; DEK_LEN];
        let env =
            wrap_dek_for(&AUTH_A, &SIG_A, &b, &b.address(), &dek, &t_payload()).expect("wrap");

        // The row it was wrapped with opens it.
        assert_eq!(
            *unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &env, &t_payload()).expect("open"),
            dek
        );

        let other_id: &[u8] = b"6a0f2b1c-1111-4222-8333-444455556667";
        let mut other_name = [0xA1u8; 61];
        other_name[0] ^= 0x01;
        let mut other_hash = [0xB2u8; 104];
        other_hash[103] ^= 0x80;

        for (what, payload) in [
            (
                "item id",
                SharePayload {
                    item_id: other_id,
                    ..t_payload()
                },
            ),
            (
                "sealed name",
                SharePayload {
                    name_ct: &other_name,
                    ..t_payload()
                },
            ),
            (
                "sealed content digest",
                SharePayload {
                    content_hash_ct: &other_hash,
                    ..t_payload()
                },
            ),
        ] {
            assert_eq!(
                unwrap_dek(&KEM_B, &AUTH_B, &SIG_B, &id_a(), &env, &payload),
                Err(ShareError::Auth),
                "a share whose {what} was rewritten must not open"
            );
        }
    }

    /// The length prefixes are not decoration: without them a row could be re-cut at a different
    /// boundary and commit to the same value, which is precisely a way to rewrite a name.
    #[test]
    fn the_commitment_separates_fields_that_share_a_boundary() {
        let left = SharePayload {
            item_id: b"item",
            name_ct: b"ab",
            content_hash_ct: b"cd",
        };
        let right = SharePayload {
            item_id: b"item",
            name_ct: b"abc",
            content_hash_ct: b"d",
        };
        assert_ne!(
            left.commitment().unwrap(),
            right.commitment().unwrap(),
            "two rows that differ only in where one field ends must not commit alike"
        );
    }

    /// A share with no sealed digest is one whose body the recipient cannot check. Refused at
    /// this layer rather than in a caller, so no screen can forget.
    #[test]
    fn an_empty_payload_field_is_refused() {
        let b = id_b();
        for (field, payload) in [
            (
                "item_id",
                SharePayload {
                    item_id: b"",
                    ..t_payload()
                },
            ),
            (
                "name_ct",
                SharePayload {
                    name_ct: b"",
                    ..t_payload()
                },
            ),
            (
                "content_hash_ct",
                SharePayload {
                    content_hash_ct: b"",
                    ..t_payload()
                },
            ),
        ] {
            assert_eq!(
                wrap_dek_for(&AUTH_A, &SIG_A, &b, &b.address(), &[0u8; DEK_LEN], &payload),
                Err(ShareError::EmptyPayloadField(field)),
                "wrapping must refuse an empty {field}"
            );
        }
    }

    #[test]
    fn addresses_survive_the_display_round_trip() {
        let a = address_for(&SIG_A);
        assert_eq!(ShareAddress::parse(&a.display()).expect("parse"), a);
        // Lower case, spaces instead of dashes, and Crockford aliases all resolve to the same
        // value — this is what makes an address safe to read aloud.
        let noisy = a.display().to_lowercase().replace('-', " ");
        assert_eq!(ShareAddress::parse(&noisy).expect("parse"), a);
    }
}
