//! Numbered share identities: the §5 operations for identity `N` of an account (NCF-3 §5.9).
//!
//! Everything here is re-exported from [`crate::share`] and is reached as `share::public_key_at`,
//! `share::unwrap_dek_as` and so on. The three seeds for identity `N` come from
//! [`crate::kdf::DerivedKeys::share_seeds_for`], or from [`crate::kdf::share_seeds_from_root`] when
//! only the parent is held.
//!
//! # One body per operation
//! An account's first identity is number 0. [`crate::share::wrap_dek_for`] and
//! [`crate::share::unwrap_dek`] are the functions here at index 0, by delegation, so the wrap and
//! the unwrap each have exactly one body. [`crate::share::public_key`] and
//! [`crate::share::address_for`] call the same internals as the functions here with 0.
//!
//! # What the number changes, and what it does not
//! The number is written into the bundle's `derivation_index`, the first four bytes of the ROOT.
//! The root is what the address fingerprints and what a wrapping key binds a recipient to. So
//! identity `N` has its own address, an envelope sealed to identity 1 binds identity 1's root, and
//! opening it as any other number derives a different key and fails like any other refusal. The
//! wrap, the row binding and the sender check are §5.3 and §5.5 unchanged; an envelope's
//! `sender_address` is the address of the identity the sender sends AS.
//!
//! ⚠ The seeds passed in must be identity `N`'s own. These functions take the number as given:
//! it is a label chosen by whoever holds the key, and nothing here can tell whether the seeds came
//! from `R(N)`. Seeds from one number under another number's index build a bundle that verifies
//! and an address nobody else computes — harmless, and useless.

use x_wing::{Ciphertext, Decapsulate};
use zeroize::Zeroizing;

use crate::kdf::{SHARE_AUTH_SECRET_LEN, SHARE_KEM_SEED_LEN, SHARE_SIG_SEED_LEN};
use crate::share::{
    address_of_root, auth_keypair, claimed_sender, identity_root, keypair, public_key_inner,
    verify_address, wrap_dek_for_inner, wrap_key, EnvelopeRandomness, ShareAddress, ShareError,
    SharePayload, SharePublicKey, AAD_SHARE_WRAP, KEM_CIPHERTEXT_LEN, KEM_RANDOMNESS_LEN,
    SHARE_ADDRESS_LEN, SHARE_ENVELOPE_LEN,
};
use crate::wrap::{self, DEK_LEN};

/// The published share identity number `index` (NCF-3 §5.9): the §5.1 bundle from that
/// identity's three seeds, with `derivation_index = index` and `key_epoch = 0`.
///
/// `public_key_at(kem, auth, sig, 0)` is [`crate::share::public_key`] byte for byte. There is no
/// refusal of 0 here: identity 0 is a real identity, and only the sub-root function refuses to
/// derive seeds for it a second way.
pub fn public_key_at(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    index: u32,
) -> SharePublicKey {
    public_key_inner(share_kem_seed, share_auth_secret, share_sig_seed, index, 0)
}

/// The address of identity number `index`, from its signing seed alone.
///
/// The root is `index || pk_sig`, so the number is part of what the address fingerprints: one
/// signing seed under two numbers is two addresses. `address_at(sig, 0)` is
/// [`crate::share::address_for`]; see there for why the other two secrets are not inputs.
pub fn address_at(share_sig_seed: &[u8; SHARE_SIG_SEED_LEN], index: u32) -> ShareAddress {
    address_of_root(&identity_root(share_sig_seed, index))
}

/// [`crate::share::wrap_dek_for`] sending AS identity number `sender_index`.
///
/// The two sender secrets are that identity's, and the envelope's `sender_address` is
/// `address_at(sender_sig_seed, sender_index)` — the address the recipient will fetch a bundle for
/// and check the sender against. Everything else is `wrap_dek_for`: the recipient key is checked
/// against `address` first, fresh randomness is drawn for every envelope, and `payload` is bound
/// into the wrapping key.
pub fn wrap_dek_for_as(
    sender_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    sender_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    sender_index: u32,
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
    // unreproducible, which is why the vectors-only twins take both. Reusing either even once
    // would be catastrophic, so they are drawn here and never stored. This is the only place a
    // production share envelope's randomness is drawn — `wrap_dek_for` comes through here.
    let kem_eseed = Zeroizing::new(crate::rng::OsRng::bytes::<KEM_RANDOMNESS_LEN>());
    let envelope_nonce = crate::rng::OsRng::bytes::<{ wrap::ENVELOPE_NONCE_LEN }>();
    wrap_dek_for_inner(
        sender_auth_secret,
        sender_sig_seed,
        sender_index,
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

/// [`crate::share::unwrap_dek`] as identity number `index` — the one body both run.
///
/// The three secrets are that identity's, and the wrapping key is rebuilt against that identity's
/// root. An envelope does not name its recipient, so the caller picks the number: the inbox knows
/// which address a share was stored against. Opening with the wrong number fails with
/// [`ShareError::Auth`], exactly like an envelope meant for someone else — a caller trying its
/// numbers in turn learns nothing about which one was close.
///
/// Every other property is `unwrap_dek`'s: an envelope whose claimed sender did not produce it, or
/// that is stored beside a name, digest or item id the sender did not wrap, fails identically,
/// and nothing retries with a different construction.
pub fn unwrap_dek_as(
    share_kem_seed: &[u8; SHARE_KEM_SEED_LEN],
    share_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    share_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    index: u32,
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
    // `wrap_key` bought. The number is part of the root, so this is where a wrong number fails.
    let our_root = identity_root(share_sig_seed, index);
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

/// Deterministic [`wrap_dek_for_as`] with caller-supplied randomness — CONFORMANCE VECTORS ONLY.
///
/// The numbered twin of `share::wrap_dek_for_with_randomness`, under the same rule: compiled only
/// under `test` or the `vectors` feature, because a caller-chosen `eseed` or nonce reused across
/// two envelopes to one recipient gives the server bytes it can correlate.
#[cfg(any(test, feature = "vectors"))]
#[allow(clippy::too_many_arguments)]
pub fn wrap_dek_for_as_with_randomness(
    sender_auth_secret: &[u8; SHARE_AUTH_SECRET_LEN],
    sender_sig_seed: &[u8; SHARE_SIG_SEED_LEN],
    sender_index: u32,
    recipient: &SharePublicKey,
    address: &ShareAddress,
    dek: &[u8; DEK_LEN],
    payload: &SharePayload<'_>,
    randomness: &EnvelopeRandomness<'_>,
) -> Result<Vec<u8>, ShareError> {
    wrap_dek_for_inner(
        sender_auth_secret,
        sender_sig_seed,
        sender_index,
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
    use crate::kdf::{share_seeds_from_root, ShareSeeds};
    use crate::share::{address_for, public_key, unwrap_dek, wrap_dek_for};

    /// Stand-ins for one account: identity 0's seeds, and the parent its numbers hang off.
    const KEM_0: [u8; SHARE_KEM_SEED_LEN] = [11u8; SHARE_KEM_SEED_LEN];
    const AUTH_0: [u8; SHARE_AUTH_SECRET_LEN] = [12u8; SHARE_AUTH_SECRET_LEN];
    const SIG_0: [u8; SHARE_SIG_SEED_LEN] = [13u8; SHARE_SIG_SEED_LEN];
    const ROOT: [u8; 32] = [14u8; 32];
    /// Another account's parent, for the sender.
    const SENDER_ROOT: [u8; 32] = [44u8; 32];
    /// Deliberately not the recipient's number, so a mixed-up index cannot pass by accident.
    const SENDER_N: u32 = 3;

    fn seeds(index: u32) -> ShareSeeds {
        if index == 0 {
            return ShareSeeds {
                kem: Zeroizing::new(KEM_0),
                auth: Zeroizing::new(AUTH_0),
                sig: Zeroizing::new(SIG_0),
            };
        }
        share_seeds_from_root(&ROOT, index).expect("index >= 1")
    }

    fn identity(index: u32) -> SharePublicKey {
        let s = seeds(index);
        public_key_at(&s.kem, &s.auth, &s.sig, index)
    }

    fn payload() -> SharePayload<'static> {
        SharePayload {
            item_id: b"6a0f2b1c-1111-4222-8333-444455556666",
            name_ct: &[0xA1; 61],
            content_hash_ct: &[0xB2; 104],
        }
    }

    #[test]
    fn identity_zero_through_the_numbered_path_is_the_identity_every_account_has() {
        assert_eq!(
            public_key_at(&KEM_0, &AUTH_0, &SIG_0, 0).to_bytes(),
            public_key(&KEM_0, &AUTH_0, &SIG_0).to_bytes()
        );
        assert_eq!(address_at(&SIG_0, 0), address_for(&SIG_0));
        // And the two delegating doors are identity 0's: a share wrapped by the old door opens
        // through the numbered one at 0, and the other way round.
        let me = identity(0);
        let dek = [9u8; DEK_LEN];
        let env = wrap_dek_for(&AUTH_0, &SIG_0, &me, &me.address(), &dek, &payload()).unwrap();
        let opened = unwrap_dek_as(&KEM_0, &AUTH_0, &SIG_0, 0, &me, &env, &payload()).unwrap();
        assert_eq!(*opened, dek);
        let env =
            wrap_dek_for_as(&AUTH_0, &SIG_0, 0, &me, &me.address(), &dek, &payload()).unwrap();
        assert_eq!(
            *unwrap_dek(&KEM_0, &AUTH_0, &SIG_0, &me, &env, &payload()).unwrap(),
            dek
        );
    }

    #[test]
    fn each_number_is_its_own_identity_under_its_own_address() {
        let ids: Vec<SharePublicKey> = [0u32, 1, 2].into_iter().map(identity).collect();
        for (n, id) in (0u32..).zip(&ids) {
            assert_eq!(id.derivation_index(), n);
            assert_eq!(id.key_epoch(), 0);
            assert_eq!(address_at(&seeds(n).sig, n), id.address());
            // The self-signature covers the number, so a numbered bundle parses like identity 0.
            let parsed =
                SharePublicKey::from_bytes(&id.to_bytes()).expect("a numbered bundle parses");
            assert_eq!(parsed.address(), id.address());
        }
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a.address(), b.address());
                assert_ne!(a.root(), b.root());
            }
        }
        // The number is inside the root: one signing seed under two numbers is two addresses.
        assert_ne!(address_at(&SIG_0, 0), address_at(&SIG_0, 1));
    }

    #[test]
    fn a_share_to_identity_one_opens_only_as_identity_one() {
        let sender_seeds = share_seeds_from_root(&SENDER_ROOT, SENDER_N).expect("index >= 1");
        let sender = public_key_at(
            &sender_seeds.kem,
            &sender_seeds.auth,
            &sender_seeds.sig,
            SENDER_N,
        );
        let recipient = identity(1);
        let dek = [5u8; DEK_LEN];
        let env = wrap_dek_for_as(
            &sender_seeds.auth,
            &sender_seeds.sig,
            SENDER_N,
            &recipient,
            &recipient.address(),
            &dek,
            &payload(),
        )
        .expect("wrap");
        // The envelope names the number the sender sent as.
        assert_eq!(claimed_sender(&env).unwrap(), sender.address());

        let one = seeds(1);
        let opened = unwrap_dek_as(&one.kem, &one.auth, &one.sig, 1, &sender, &env, &payload());
        assert_eq!(*opened.expect("identity 1 opens it"), dek);

        // Every other number of the same account is refused with the one error every refusal
        // gives — including identity 1's own secrets under a wrong number.
        for (secrets, n) in [
            (seeds(0), 0u32),
            (seeds(2), 2),
            (seeds(1), 2),
            (seeds(1), 0),
        ] {
            let refused = unwrap_dek_as(
                &secrets.kem,
                &secrets.auth,
                &secrets.sig,
                n,
                &sender,
                &env,
                &payload(),
            );
            assert_eq!(
                refused.unwrap_err(),
                ShareError::Auth,
                "opened as number {n}"
            );
        }
        let zero = seeds(0);
        let refused = unwrap_dek(&zero.kem, &zero.auth, &zero.sig, &sender, &env, &payload());
        assert_eq!(refused.unwrap_err(), ShareError::Auth);
    }
}
