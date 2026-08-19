//! The one derivation that does not start from an account code (NCF-3 §1.4).
//!
//! ```text
//! deviceWrapKey = HKDF-Expand(
//!                   HKDF-Extract(salt = "", ikm = Argon2id(pwd = passphrase,
//!                                                           salt = 16 random bytes per record,
//!                                                           m = 65536 KiB, t = 3, p = 1)),
//!                   "nmts/v3/device-wrap", 32)
//! ```
//!
//! It lives in its own file because it is the exception to everything the parent module says: no
//! account key is an input, its salt is random rather than constant, and its output opens exactly
//! one record on exactly one device. Keeping it beside the account chain was how the fixed-salt
//! rule nearly got applied to a human-chosen passphrase.

use argon2::Params;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{KdfError, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, MASTER_LEN};

/// HKDF label for the "remember this device" wrapping key. Its own domain so a passphrase-derived
/// key can never coincide with anything expanded from an account code.
pub const INFO_DEVICE_WRAP: &[u8] = b"nmts/v3/device-wrap";

/// Length of the wrapping key from [`derive_device_wrap_key`].
pub const DEVICE_WRAP_KEY_LEN: usize = 32;

/// Salt length for passphrase derivations. Unlike the account chain's salt this is NOT a constant
/// value: the caller generates 16 fresh random bytes per record. A human-chosen passphrase is
/// exactly the case the fixed-salt argument excludes — with a shared salt, one precomputation
/// would cover every NMTS user at once.
pub const PASSPHRASE_SALT_LEN: usize = 16;

/// Shortest passphrase [`derive_device_wrap_key`] will derive from, in bytes.
///
/// Eight is a floor against typos and empty input, NOT a claim that an 8-byte passphrase is
/// strong. It is enforced in the crate rather than only in the UI so every caller inherits it.
pub const MIN_PASSPHRASE_BYTES: usize = 8;

/// Derives the wrapping key for a passphrase-protected "remember this device" record.
///
/// # What it buys and what it does not
/// The attacker this defends against holds the device's disk (E-stage measurement: a
/// non-extractable AES-GCM key is written to the browser profile in the clear, so the disk — not
/// the key handle — is the real boundary). Argon2id at 64 MiB × 3 makes guessing that passphrase
/// cost real memory and time per attempt. It does NOT make a weak passphrase strong, and it does
/// nothing about an attacker who reads the passphrase as it is typed.
///
/// # Errors
/// [`KdfError::Argon2`] if Argon2id rejects the parameters (should not happen with the constants
/// above), [`KdfError::SaltLength`] for a salt that is not [`PASSPHRASE_SALT_LEN`] bytes, and
/// [`KdfError::PassphraseTooShort`] below [`MIN_PASSPHRASE_BYTES`].
pub fn derive_device_wrap_key(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; DEVICE_WRAP_KEY_LEN]>, KdfError> {
    if salt.len() != PASSPHRASE_SALT_LEN {
        return Err(KdfError::SaltLength(salt.len()));
    }
    // Enforced HERE and not only in the UI: this function is the one place every caller — the
    // browser today, a recovery tool tomorrow — has to pass through, and a 3-character passphrase
    // would make the Argon2id cost irrelevant.
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        return Err(KdfError::PassphraseTooShort(passphrase.len()));
    }

    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(MASTER_LEN),
    )
    .map_err(|e| KdfError::Argon2(e.to_string()))?;
    let mut prk = Zeroizing::new([0u8; MASTER_LEN]);
    // Through the wiping wrapper, like every other Argon2id call here — see its comment for what
    // the convenience entry point leaves behind.
    super::argon2id_into(params, passphrase, salt, &mut *prk)?;

    let hk = Hkdf::<Sha256>::new(Some(b""), &*prk);
    let mut key = Zeroizing::new([0u8; DEVICE_WRAP_KEY_LEN]);
    hk.expand(INFO_DEVICE_WRAP, &mut *key)
        .expect("HKDF expand length within bounds");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::ACCOUNT_CODE_BYTES;
    use crate::kdf::{derive_from_bytes, ARGON2_SALT};

    #[test]
    fn device_wrap_key_is_deterministic_and_salt_bound() {
        let salt_a = [7u8; PASSPHRASE_SALT_LEN];
        let salt_b = [8u8; PASSPHRASE_SALT_LEN];
        let pass = b"correct horse battery";

        let one = derive_device_wrap_key(pass, &salt_a).unwrap();
        let two = derive_device_wrap_key(pass, &salt_a).unwrap();
        assert_eq!(*one, *two, "same passphrase + salt must give the same key");

        let other_salt = derive_device_wrap_key(pass, &salt_b).unwrap();
        assert_ne!(
            *one, *other_salt,
            "a different record salt must give a different key — that is what stops one \
             precomputation covering every user"
        );

        let other_pass = derive_device_wrap_key(b"correct horse batteryX", &salt_a).unwrap();
        assert_ne!(
            *one, *other_pass,
            "a different passphrase must give a different key"
        );
    }

    #[test]
    fn device_wrap_key_rejects_bad_inputs() {
        assert_eq!(
            derive_device_wrap_key(b"short", &[0u8; PASSPHRASE_SALT_LEN]),
            Err(KdfError::PassphraseTooShort(5)),
        );
        assert_eq!(
            derive_device_wrap_key(b"long enough passphrase", &[0u8; 8]),
            Err(KdfError::SaltLength(8)),
        );
    }

    #[test]
    fn device_wrap_key_shares_no_domain_with_account_keys() {
        // The wrap key must not collide with anything expanded from an account code. Using the
        // code bytes as a "passphrase" is the closest an input can get; the labels keep them apart.
        let code = [0u8; ACCOUNT_CODE_BYTES];
        let account = derive_from_bytes(&code).unwrap();
        let wrap = derive_device_wrap_key(&[0u8; 20], ARGON2_SALT).unwrap();
        assert_ne!(*wrap, *account.data_key);
        assert_ne!(*wrap, *account.auth_secret);
        assert_ne!(*wrap, *account.file_list_key);
        assert_ne!(*wrap, *account.share_kem_seed);
        assert_ne!(*wrap, *account.share_auth_secret);
    }
}
