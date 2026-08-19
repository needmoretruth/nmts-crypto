//! Key derivation chain: account code → master → every key an account has (NCF-3 §1).
//!
//! # Purpose
//! Turn a 160-bit account code into the keys one NMTS session needs. Everything an account can
//! do descends from here, which is why this module is the one with the longest comments.
//!
//! # Contract (NCF-3 §1 — re-freezes at the mainnet cutover)
//! ```text
//! master       = Argon2id(pwd = code_bytes, salt = "NMTS-KDF-v3-salt",
//!                          m = 65536 KiB, t = 3, p = 1, out = 32)
//! PRK          = HKDF-Extract(salt = "", ikm = master)
//!
//! accountId    = HKDF-Expand(PRK, "nmts/v3/account-id",    16)   // public — server lookup key
//! authSecret   = HKDF-Expand(PRK, "nmts/v3/auth-secret",   32)   // sent to the server over TLS
//! dataKey      = HKDF-Expand(PRK, "nmts/v3/data-key",      32)   // never leaves the browser
//! fileListKey  = HKDF-Expand(PRK, "nmts/v3/file-list-key", 32)   // opens the file list only
//! shareKemSeed = HKDF-Expand(PRK, "nmts/v3/share-kem",     32)   // X-Wing seed  (crate::share)
//! shareAuthSk  = HKDF-Expand(PRK, "nmts/v3/share-auth",    32)   // sender-auth scalar   (§5.5)
//! shareSigSeed = HKDF-Expand(PRK, "nmts/v3/share-sig",     32)   // ML-DSA-44 seed ξ    (§5.2a)
//! walletRoot   = HKDF-Expand(PRK, "nmts/v3/wallet-root",   32)   // parent of every wallet
//!
//! walletSeed(N) = HKDF-Expand(walletRoot, "nmts/v3/wallet/" || dec(N), 32)   // every N >= 0
//! ```
//! HKDF-Extract uses an empty salt (RFC 5869): identical to an all-zero salt, since HMAC
//! zero-pads the key to the block size either way.
//!
//! # What changed from NCF-1/NCF-2, and why it was worth breaking every account
//! * **The Argon2id salt moved to `…v3…`.** This buys nothing cryptographically and the comment
//!   below says so plainly. It buys a *version boundary*: no value derived under the old format
//!   can be accepted by a v3 path, because the roots are unrelated. [`KdfVersion`] existed with a
//!   single variant and nothing to distinguish; now it distinguishes.
//! * **Wallet 0 lost its special case.** NCF-2 froze wallet 0 at its own label off the account
//!   PRK because it already existed on chain and could not move; wallets 1, 2, 3… hung off a
//!   separate root. NCF-3 breaks every address anyway, so the exception is deleted and
//!   [`wallet_seed_from_root`] answers for every index under one rule. One rule cannot drift out
//!   of step with itself.
//! * **The share scalar and share address left this module.** The address is no longer derived
//!   from the account code at all — it is a fingerprint of the share public key ([`crate::share`]),
//!   which is what closes the server's man-in-the-middle position on sharing (NCF-3 §5.2). What
//!   remains here is the 32-byte seed the X-Wing keypair is generated from.
//! * **`manifestKey` → `fileListKey`.** Three unrelated objects were called "manifest"; see
//!   NCF-3 §2.4.
//!
//! # Invariants
//! * The Argon2id salt is a fixed constant **for the account-code chain**. That is safe ONLY
//!   because the input is a 160-bit machine-generated code — there is no dictionary to
//!   precompute against and no user choosing a weak one. A human-chosen passphrase is the case
//!   that argument excludes, so [`device::derive_device_wrap_key`] takes a fresh random salt per
//!   record instead.
//! * ⛔ The salt is NOT split per purpose. Purpose separation is what HKDF's `info` is for; one
//!   64 MiB memory-hard pass per purpose would multiply the cost by the number of keys for no
//!   gain. One Argon2id pass, many Expands.
//! * Every secret is zeroized on drop; `accountId` is public.
//! * Every derivation is tagged [`KdfVersion`]; accounts never silently migrate.
//!
//! # Layout
//! * this module — the account-code chain.
//! * [`device`] — the ONE derivation that does not start from an account code.

pub mod device;

pub use device::{
    derive_device_wrap_key, DEVICE_WRAP_KEY_LEN, INFO_DEVICE_WRAP, MIN_PASSPHRASE_BYTES,
    PASSPHRASE_SALT_LEN,
};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::codes::{AccountCode, ACCOUNT_CODE_BYTES};

/// The NCF-3 Argon2id salt (16 ASCII bytes). See the module invariant on why a constant salt is
/// acceptable for this input, and NCF-3 §1.1 on why the version in it is the whole point.
pub const ARGON2_SALT: &[u8; 16] = b"NMTS-KDF-v3-salt";
/// Argon2id memory cost, in KiB (64 MiB).
///
/// Re-examined for NCF-3 and deliberately unchanged. The commonly cited OWASP minimum is 19 MiB
/// at t = 2; we are well above it on the expensive axis. Raising it further would cost seconds on
/// a low-end phone to slow down a guessing attack that cannot be mounted against a 160-bit
/// machine-generated code in the first place.
pub const ARGON2_M_COST: u32 = 65_536;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism lanes. One, because the browser build is single-threaded.
pub const ARGON2_P_COST: u32 = 1;
/// Argon2id output length, in bytes.
pub const MASTER_LEN: usize = 32;

/// HKDF `info` label for `accountId`.
pub const INFO_ACCOUNT_ID: &[u8] = b"nmts/v3/account-id";
/// HKDF `info` label for `authSecret`.
pub const INFO_AUTH_SECRET: &[u8] = b"nmts/v3/auth-secret";
/// HKDF `info` label for `dataKey`.
pub const INFO_DATA_KEY: &[u8] = b"nmts/v3/data-key";

/// HKDF `info` for the FILE-LIST key (NCF-3 §6).
///
/// Separate from `dataKey` on purpose. `dataKey` opens every file name and unwraps every file
/// DEK; this one opens only the *index*. Keeping them apart is what would let a future
/// "hand someone a read-only view of my drive" feature exist without also handing over the key
/// that decrypts contents. It costs one extra HKDF-Expand off the same PRK.
pub const INFO_FILE_LIST_KEY: &[u8] = b"nmts/v3/file-list-key";

/// HKDF `info` for the SENDER-AUTHENTICATION scalar (NCF-3 §5.5).
///
/// A second, static X25519 key belonging to the same share identity. The KEM above proves who an
/// envelope was FOR; this one proves who it came FROM — the sender agrees with the recipient's
/// matching key and mixes the result into the wrapping key, so an envelope only opens if the
/// claimed sender really produced it.
///
/// Deliberately a separate key rather than the X25519 half inside X-Wing: that half is an
/// implementation detail of the KEM, is not exposed by the crate, and reusing one key for
/// encapsulation and authentication is the kind of cross-protocol shortcut this file exists to
/// avoid.
pub const INFO_SHARE_AUTH: &[u8] = b"nmts/v3/share-auth";

/// HKDF `info` for the X-Wing decapsulation-key seed (NCF-3 §5.1).
///
/// The seed, not the keypair: X-Wing expands these 32 bytes with SHAKE-256 into both halves, so
/// the whole share identity is reproducible on any device from the account code alone. There is
/// no share key to back up and none to lose.
pub const INFO_SHARE_KEM: &[u8] = b"nmts/v3/share-kem";

/// HKDF `info` for the ML-DSA-44 signing-key seed ξ (NCF-3 §5.1, §5.2a).
///
/// The third and last secret of the share identity. Its verification key is the identity's
/// permanent ROOT — the only part the share address fingerprints — and its one and only job is to
/// sign the rest of the bundle, so that the other two keys can one day be replaced without the
/// address changing. 32 bytes because FIPS 204 keygen is defined as a deterministic expansion of a
/// 32-byte seed; like the other two, it is re-derived from the account code rather than stored, so
/// there is still no share key to back up and none to lose.
///
/// ⛔ Deliberately NOT a prefix of any other label, and nothing derives from it in turn. A sibling
/// label for a caller-chosen signing `rnd` was considered and rejected: it would have made this
/// label a prefix of another one (the mistake `wallet-root` and the numbered wallets were named to
/// avoid), and the standard's own deterministic variant — `rnd` = 32 zero bytes — is the one this
/// format uses.
pub const INFO_SHARE_SIG: &[u8] = b"nmts/v3/share-sig";

/// HKDF `info` label for the wallet ROOT.
///
/// Wallets hang off this rather than off the account PRK so the root can be held alone: it yields
/// wallets and nothing else, never `authSecret` (the login proof) or `dataKey` (which opens every
/// file). That separation is what makes "export this wallet's key" a bounded disclosure rather
/// than a total one.
pub const INFO_WALLET_ROOT: &[u8] = b"nmts/v3/wallet-root";

/// HKDF `info` PREFIX for wallet number `N`: the full label is `nmts/v3/wallet/N` with `N` in
/// decimal ASCII, no padding. Wallet 10 is `nmts/v3/wallet/10`; there is no `nmts/v3/wallet/010`.
pub const INFO_WALLET_PREFIX: &str = "nmts/v3/wallet/";

/// Byte length of a derived `accountId`.
pub const ACCOUNT_ID_LEN: usize = 16;
/// Byte length of a derived `authSecret`.
pub const AUTH_SECRET_LEN: usize = 32;
/// Byte length of a derived `dataKey`.
pub const DATA_KEY_LEN: usize = 32;
/// Byte length of the file-list key.
pub const FILE_LIST_KEY_LEN: usize = 32;
/// Byte length of the X-Wing decapsulation-key seed.
pub const SHARE_KEM_SEED_LEN: usize = 32;
/// Byte length of the X25519 sender-authentication scalar.
pub const SHARE_AUTH_SECRET_LEN: usize = 32;
/// Byte length of the ML-DSA-44 signing-key seed ξ (FIPS 204 fixes it at 32 for every parameter
/// set).
pub const SHARE_SIG_SEED_LEN: usize = 32;
/// Byte length of a wallet's Ed25519 seed, and of the wallet root.
pub const WALLET_SEED_LEN: usize = 32;

/// Version tag for the derivation parameters, persisted per account (`account.kdf_version`).
///
/// NCF-1's `V1` is gone rather than kept as a legacy variant: no code path can produce or consume
/// it, and a variant nothing reaches is a comment pretending to be a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfVersion {
    /// The NCF-3 parameters defined in this module.
    V3,
}

impl KdfVersion {
    /// The on-record integer for this version.
    pub fn as_u8(self) -> u8 {
        match self {
            KdfVersion::V3 => 3,
        }
    }
}

/// Errors from the derivation chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KdfError {
    /// Argon2id rejected the parameters or failed to hash (should not occur with the
    /// constants above; surfaced defensively).
    #[error("argon2id failure: {0}")]
    Argon2(String),
    /// A passphrase derivation was handed a salt that is not [`PASSPHRASE_SALT_LEN`] bytes.
    #[error("passphrase salt must be {PASSPHRASE_SALT_LEN} bytes, got {0}")]
    SaltLength(usize),
    /// A passphrase shorter than [`MIN_PASSPHRASE_BYTES`]. Refused rather than derived: the
    /// Argon2id cost is meaningless against a passphrase a wordlist covers instantly.
    #[error("passphrase must be at least {MIN_PASSPHRASE_BYTES} bytes, got {0}")]
    PassphraseTooShort(usize),
}

/// Everything one account code produces, tagged with the KDF version that produced it.
///
/// Secret fields are wrapped in [`Zeroizing`] and cleared on drop. Read them only for as long as
/// needed; do not copy them into un-zeroized buffers.
pub struct DerivedKeys {
    /// Which parameter set produced these keys.
    pub version: KdfVersion,
    /// Public server lookup key (16 bytes).
    pub account_id: [u8; ACCOUNT_ID_LEN],
    /// Secret login proof (32 bytes) — the one derived value that is sent to the server.
    pub auth_secret: Zeroizing<[u8; AUTH_SECRET_LEN]>,
    /// Secret client-only data key (32 bytes) — wraps DEKs and seals names/metadata.
    pub data_key: Zeroizing<[u8; DATA_KEY_LEN]>,
    /// Secret client-only key for the sealed file list (32 bytes). Opens the index and nothing
    /// else — see [`INFO_FILE_LIST_KEY`].
    pub file_list_key: Zeroizing<[u8; FILE_LIST_KEY_LEN]>,
    /// Secret client-only X-Wing seed (32 bytes) for the share identity ([`crate::share`]).
    /// Never leaves the crypto worker; only the PUBLIC key it generates is sent to the server.
    pub share_kem_seed: Zeroizing<[u8; SHARE_KEM_SEED_LEN]>,
    /// Secret client-only X25519 scalar (32 bytes) that authenticates this account as the SENDER
    /// of a share ([`INFO_SHARE_AUTH`]). Never leaves the crypto worker.
    pub share_auth_secret: Zeroizing<[u8; SHARE_AUTH_SECRET_LEN]>,
    /// Secret client-only ML-DSA-44 seed (32 bytes) whose verification key is the share identity's
    /// permanent root, and which signs the identity bundle ([`INFO_SHARE_SIG`]). Never leaves the
    /// crypto worker; only the verification key and the signature are published.
    pub share_sig_seed: Zeroizing<[u8; SHARE_SIG_SEED_LEN]>,
    /// Secret client-only root for every wallet (32 bytes) — see [`INFO_WALLET_ROOT`].
    pub wallet_root: Zeroizing<[u8; WALLET_SEED_LEN]>,
}

impl DerivedKeys {
    /// The textual `accountId`: unpadded base64url of the 16 public bytes.
    pub fn account_id_b64(&self) -> String {
        crate::b64::encode(&self.account_id)
    }

    /// The Ed25519 seed for wallet number `index`.
    ///
    /// One rule for every index including 0 — see the module docs on why NCF-2's special case for
    /// wallet 0 is gone.
    pub fn wallet_seed_for(&self, index: u32) -> Zeroizing<[u8; WALLET_SEED_LEN]> {
        wallet_seed_from_root(&self.wallet_root, index)
    }
}

/// The Ed25519 seed for wallet number `index` from a 32-byte wallet root.
///
/// Split out from [`DerivedKeys::wallet_seed_for`] because the browser derives keys once at login
/// and keeps only the root — by the time a user asks for another wallet the account code is long
/// gone from memory, and re-running Argon2id would mean asking them to type it again.
pub fn wallet_seed_from_root(
    wallet_root: &[u8; WALLET_SEED_LEN],
    index: u32,
) -> Zeroizing<[u8; WALLET_SEED_LEN]> {
    let info = format!("{INFO_WALLET_PREFIX}{index}");
    // from_prk cannot fail for a 32-byte PRK (>= HashLen), and expand cannot fail for a
    // 32-byte output — both bounds are compile-time constants here.
    let hk = Hkdf::<Sha256>::from_prk(wallet_root).expect("wallet root is 32 bytes");
    let mut seed = Zeroizing::new([0u8; WALLET_SEED_LEN]);
    hk.expand(info.as_bytes(), &mut *seed)
        .expect("HKDF expand length within bounds");
    seed
}

impl core::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("version", &self.version)
            .field("account_id", &self.account_id_b64())
            .field("auth_secret", &"<redacted>")
            .field("data_key", &"<redacted>")
            .field("file_list_key", &"<redacted>")
            .field("share_kem_seed", &"<redacted>")
            .field("share_auth_secret", &"<redacted>")
            .field("share_sig_seed", &"<redacted>")
            .field("wallet_root", &"<redacted>")
            .finish()
    }
}

/// Derives the account keys from a parsed [`AccountCode`].
pub fn derive(code: &AccountCode) -> Result<DerivedKeys, KdfError> {
    derive_from_bytes(code.as_bytes())
}

/// Run Argon2id into `out`, **wiping the working memory before it is freed**.
///
/// # ⛔ Why the convenience entry point is not used
/// `Argon2::hash_password_into` allocates the ~64 MiB block array itself and drops it without
/// clearing it. That array is not scratch noise: the last block of a lane is XORed and hashed to
/// produce the output, so whatever reads that memory afterwards recomputes `master` — the root of
/// **every** key an account has, and the one secret with no reset (`codes.rs`). The library's
/// `zeroize` feature (on, see Cargo.toml) clears the library's OWN intermediates; the array is the
/// caller's, which makes wiping it the caller's job. `hash_password_into_with_memory` is the entry
/// point that lets a caller own it.
///
/// # Where it matters most
/// In the browser build. Freed WASM memory stays inside one linear `ArrayBuffer` for the life of
/// the page — nothing hands it back to an operating system — so "freed" there means "still there,
/// and reachable by anything that gets a view on it".
///
/// ⚠ This does not make key material un-leakable. A live process can still be read while the
/// values are IN USE; what it removes is the window that lasts from a login until the page closes.
fn argon2id_into(params: Params, pwd: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), KdfError> {
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon
        .hash_password_into_with_memory(pwd, salt, out, &mut memory)
        .map_err(|e| KdfError::Argon2(e.to_string()))
}

/// Derives the account keys directly from the 20 raw code bytes (the chain operates on the
/// decoded bytes, never the ASCII text).
pub fn derive_from_bytes(code_bytes: &[u8; ACCOUNT_CODE_BYTES]) -> Result<DerivedKeys, KdfError> {
    // 1) master = Argon2id(code_bytes, constant salt, 64 MiB / t=3 / p=1) → 32 bytes.
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(MASTER_LEN),
    )
    .map_err(|e| KdfError::Argon2(e.to_string()))?;
    let mut master = Zeroizing::new([0u8; MASTER_LEN]);
    argon2id_into(params, code_bytes, ARGON2_SALT, &mut *master)?;

    // 2) HKDF-Extract once (empty salt), then one Expand per label. The ONLY thing keeping these
    //    outputs apart is a distinct `info` per output — a copy-pasted label would silently
    //    collapse two of them into the same bytes and nothing else in the system would notice,
    //    which is what `every_derived_secret_is_a_different_value` below exists to catch.
    let hk = Hkdf::<Sha256>::new(Some(b""), &*master);

    let mut account_id = [0u8; ACCOUNT_ID_LEN];
    let mut auth_secret = Zeroizing::new([0u8; AUTH_SECRET_LEN]);
    let mut data_key = Zeroizing::new([0u8; DATA_KEY_LEN]);
    let mut file_list_key = Zeroizing::new([0u8; FILE_LIST_KEY_LEN]);
    let mut share_kem_seed = Zeroizing::new([0u8; SHARE_KEM_SEED_LEN]);
    let mut share_auth_secret = Zeroizing::new([0u8; SHARE_AUTH_SECRET_LEN]);
    let mut share_sig_seed = Zeroizing::new([0u8; SHARE_SIG_SEED_LEN]);
    let mut wallet_root = Zeroizing::new([0u8; WALLET_SEED_LEN]);

    // Expand only fails if the requested length exceeds 255*HashLen (32 here) — impossible.
    hk.expand(INFO_ACCOUNT_ID, &mut account_id)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_AUTH_SECRET, &mut *auth_secret)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_DATA_KEY, &mut *data_key)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_FILE_LIST_KEY, &mut *file_list_key)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_SHARE_KEM, &mut *share_kem_seed)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_SHARE_AUTH, &mut *share_auth_secret)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_SHARE_SIG, &mut *share_sig_seed)
        .expect("HKDF expand length within bounds");
    hk.expand(INFO_WALLET_ROOT, &mut *wallet_root)
        .expect("HKDF expand length within bounds");

    // `master` is zeroized when the `Zeroizing` wrapper drops at end of scope.
    Ok(DerivedKeys {
        version: KdfVersion::V3,
        account_id,
        auth_secret,
        data_key,
        file_list_key,
        share_kem_seed,
        share_auth_secret,
        share_sig_seed,
        wallet_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_derived_secret_is_a_different_value() {
        // One account code fans out into several keys, and the whole security story assumes they
        // are unrelated: the wallet root must not equal the value the server sees, the file-list
        // key must not equal the key that unwraps file contents, and so on. They all come from
        // ONE HKDF-Extract, so a duplicated `info` label is the one mistake that would collapse
        // two of them into identical bytes with no other symptom.
        let code = [7u8; ACCOUNT_CODE_BYTES];
        let k = derive_from_bytes(&code).expect("derivation");

        let outputs: [(&str, &[u8]); 8] = [
            ("account_id", &k.account_id),
            ("auth_secret", &k.auth_secret[..]),
            ("data_key", &k.data_key[..]),
            ("file_list_key", &k.file_list_key[..]),
            ("share_kem_seed", &k.share_kem_seed[..]),
            ("share_auth_secret", &k.share_auth_secret[..]),
            ("share_sig_seed", &k.share_sig_seed[..]),
            ("wallet_root", &k.wallet_root[..]),
        ];
        for (i, (name_a, a)) in outputs.iter().enumerate() {
            for (name_b, b) in outputs.iter().skip(i + 1) {
                assert_ne!(a, b, "{name_a} and {name_b} must not be the same value");
            }
        }
    }

    #[test]
    fn derivation_is_deterministic_and_code_bound() {
        let code = [3u8; ACCOUNT_CODE_BYTES];
        let a = derive_from_bytes(&code).expect("derivation");
        let b = derive_from_bytes(&code).expect("derivation");
        assert_eq!(a.account_id, b.account_id);
        assert_eq!(a.data_key[..], b.data_key[..]);
        assert_eq!(a.file_list_key[..], b.file_list_key[..]);
        assert_eq!(a.share_kem_seed[..], b.share_kem_seed[..]);

        let other = derive_from_bytes(&[4u8; ACCOUNT_CODE_BYTES]).expect("derivation");
        assert_ne!(a.account_id, other.account_id);
        assert_ne!(a.data_key[..], other.data_key[..]);
        assert_ne!(
            a.file_list_key[..],
            other.file_list_key[..],
            "two accounts must not share an index key"
        );
    }

    #[test]
    fn wallets_are_numbered_by_one_rule_including_zero() {
        // NCF-2 answered for wallet 0 from a different parent than every other wallet. That
        // exception is gone, and this is the test that keeps it gone: if someone reintroduces a
        // special case for 0, wallet 0 stops matching the root derivation and this fails.
        let k = derive_from_bytes(&[9u8; ACCOUNT_CODE_BYTES]).expect("derivation");

        for index in [0u32, 1, 2, 10] {
            assert_eq!(
                *k.wallet_seed_for(index),
                *wallet_seed_from_root(&k.wallet_root, index),
                "wallet {index} must come from the root like every other wallet",
            );
        }

        // Distinct per index, and never equal to the root itself.
        let seeds: Vec<_> = (0u32..4).map(|i| *k.wallet_seed_for(i)).collect();
        for (i, a) in seeds.iter().enumerate() {
            assert_ne!(a[..], k.wallet_root[..], "wallet {i} must not be the root");
            for (j, b) in seeds.iter().enumerate().skip(i + 1) {
                assert_ne!(a[..], b[..], "wallets {i} and {j} must differ");
            }
        }

        // Decimal ASCII with no padding: wallet 10 is not wallet 1 followed by a zero byte, and
        // "010" is not a spelling this scheme has.
        assert_ne!(*k.wallet_seed_for(1), *k.wallet_seed_for(10));
    }

    #[test]
    fn the_v3_salt_makes_the_old_chain_unreachable() {
        // The point of the salt bump is that nothing derived under NCF-1 can be accepted here.
        // Re-deriving with the old salt must produce a different master and therefore different
        // outputs — if these ever match, the version boundary is not a boundary.
        let code = [1u8; ACCOUNT_CODE_BYTES];
        let now = derive_from_bytes(&code).expect("derivation");

        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(MASTER_LEN),
        )
        .expect("params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut old_master = Zeroizing::new([0u8; MASTER_LEN]);
        argon
            .hash_password_into(&code, b"NMTS-KDF-v1-salt", &mut *old_master)
            .expect("argon2id");
        let old = Hkdf::<Sha256>::new(Some(b""), &*old_master);
        let mut old_account_id = [0u8; ACCOUNT_ID_LEN];
        old.expand(b"nmts/v1/account-id", &mut old_account_id)
            .expect("expand");

        assert_ne!(
            now.account_id, old_account_id,
            "an NCF-1 account id must not be reachable from the v3 chain",
        );
    }

    #[test]
    fn argon2_parameters_are_the_reviewed_ones() {
        // Not a cryptographic assertion — a tripwire. These three numbers were re-examined for
        // NCF-3 and deliberately left alone (NCF-3 §1.1); changing one silently changes every
        // account's keys, so the change should have to be typed twice.
        assert_eq!(ARGON2_M_COST, 65_536);
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 1);
        assert_eq!(ARGON2_SALT, b"NMTS-KDF-v3-salt");
    }

    /// ⛔ THE TRIPWIRE FOR THE WIPE. Two things, and the second is why the test is shaped this way.
    ///
    /// 1. **There really is something to wipe.** After a hash the working memory is full of
    ///    non-zero material — the last block of a lane is what the output is made from, so this is
    ///    not scratch noise but `master` one hash away. If this assertion ever failed, the wiping
    ///    wrapper would be pointless and should be deleted rather than kept as decoration.
    /// 2. **`Block: Zeroize` has to exist**, which it only does while `argon2`'s `zeroize` feature
    ///    is on in Cargo.toml. Drop the feature and this test stops COMPILING — the loudest a
    ///    missing feature can be, and louder than any runtime assertion could manage, because
    ///    nothing observable changes at runtime when memory is quietly left behind.
    ///
    /// ⚠ What this does NOT test: that `Zeroizing`'s own drop runs. Observing memory after it is
    /// freed cannot be done without `unsafe`, which this repository forbids. What is tested is
    /// every link we own; the last one is the `zeroize` crate's, under its own tests.
    #[test]
    fn the_argon2_working_memory_holds_key_material_and_can_be_wiped() {
        use zeroize::Zeroize;

        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(MASTER_LEN))
            .expect("params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
        let mut memory = vec![Block::default(); params.block_count()];
        let mut out = [0u8; MASTER_LEN];
        argon
            .hash_password_into_with_memory(&[7u8; ACCOUNT_CODE_BYTES], ARGON2_SALT, &mut out, &mut memory)
            .expect("argon2id");

        let live: usize = memory
            .iter()
            .filter(|b| b.as_ref().iter().any(|&word| word != 0))
            .count();
        assert!(
            live > memory.len() / 2,
            "the working memory came back mostly empty ({live} of {} blocks) — if Argon2id stopped \
             leaving material behind, the wiping wrapper is dead weight and should go",
            memory.len()
        );

        memory.zeroize();
        assert!(
            memory.iter().all(|b| b.as_ref().iter().all(|&word| word == 0)),
            "the working memory survived a wipe",
        );
    }

    /// The wrapper must not change a single derived byte — it changes WHERE the blocks live, and
    /// nothing else. A wrong block count would be caught by the conformance vectors eventually;
    /// this catches it here, next to the code that could cause it.
    #[test]
    fn wiping_the_working_memory_does_not_change_what_is_derived() {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(MASTER_LEN))
            .expect("params");
        let code = [0x5au8; ACCOUNT_CODE_BYTES];

        let mut ours = [0u8; MASTER_LEN];
        argon2id_into(params.clone(), &code, ARGON2_SALT, &mut ours).expect("wrapped");

        let mut theirs = [0u8; MASTER_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&code, ARGON2_SALT, &mut theirs)
            .expect("plain");

        assert_eq!(ours, theirs);
    }
}
