//! EVM wallets — the key that pays for NMTS Heavy on Filecoin (NCF-3 §1.9, added 2026-09-23).
//!
//! # Contract
//! ```text
//! evmSeed(N)  = HKDF-Expand(walletRoot, "nmts/v3/evm-wallet/" || dec(N), 48)   // every N >= 0
//! evmKey(N)   = (OS2IP(evmSeed(N)) mod (n - 1)) + 1        // n = the secp256k1 group order
//! evmAddr(N)  = keccak256(X || Y of evmKey(N)·G)[12..32]   // the 20-byte Ethereum address
//! ```
//! `OS2IP` reads the 48 bytes as one big-endian integer. The address is what Filecoin's EVM calls
//! `0x…` and its native side calls the delegated `f410…` / `t410…` address — one account, two
//! spellings of the same 20 bytes.
//!
//! # Why it hangs off `walletRoot`
//! An EVM key is a wallet. [`super::INFO_WALLET_ROOT`] was split off the account PRK so that
//! holding it yields wallets and nothing else — never `authSecret`, never `dataKey` — and that is
//! what keeps "export this wallet's key" a bounded disclosure. A root of its own would have been a
//! second thing to retain in the browser worker for the same property.
//!
//! # Why 48 bytes and `mod (n - 1)) + 1`
//! This is FIPS 186-5 Appendix A.2.1, "key pair generation using extra random bits": take at
//! least `len(n) + 64` bits, reduce modulo `n - 1`, add one. The result is never 0 and never `n`,
//! so there is no rejection loop and no retry counter for two implementations to disagree about,
//! and the bias is below 2⁻¹²⁸. 48 bytes is RFC 9380's `L` for a 256-bit order at the 128-bit
//! level — the same length `@noble/curves`' `mapHashToField` asks for, which is the independent
//! implementation the vectors were made with.
//!
//! # Why not the Ed25519 seed of the same index
//! One secret, one purpose: using `walletSeed(N)` as a secp256k1 scalar would make exporting a Sui
//! wallet also export an EVM wallet, and the reverse. The label keeps them apart.
//!
//! # Why not BIP-32 / BIP-44 (`m/44'/60'/0'/0/N`) from the recovery phrase
//! That would let a person type their NMTS phrase into any EVM wallet and see the same address.
//! It would also teach them to type the one secret that opens every file into software that only
//! needed a wallet key; and the Korean and English spellings of one phrase give two different
//! BIP-39 seeds, so "the phrase is only a spelling" (§1.8) would stop being true. NMTS's Sui
//! wallets already use this HKDF rule rather than SLIP-10, and the exported private key (32 bytes
//! of hex) imports into every EVM wallet — which is the interoperability that matters.
//!
//! # Why this is an ADDITION and not NCF-4
//! No existing key, envelope, address or code changes value, and no reader of existing data
//! behaves differently. It is one more `HKDF-Expand` off `walletRoot` under a label §2.1 records as
//! taken — the same test §2.5, §1.5 and §1.7 applied.

use hkdf::Hkdf;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::ReduceNonZero;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use super::WALLET_SEED_LEN;

/// HKDF `info` PREFIX for EVM wallet number `N`: the full label is `nmts/v3/evm-wallet/N` with `N`
/// in decimal ASCII, no padding — the rule [`super::INFO_WALLET_PREFIX`] uses. Not a prefix of any
/// other label and no other label is a prefix of it.
pub const INFO_EVM_WALLET_PREFIX: &str = "nmts/v3/evm-wallet/";

/// Byte length of an EVM seed: `len(n) + 128` bits, see the module docs.
pub const EVM_SEED_LEN: usize = 48;
/// Byte length of an EVM private key (a secp256k1 scalar, big-endian).
pub const EVM_KEY_LEN: usize = 32;
/// Byte length of an EVM address.
pub const EVM_ADDRESS_LEN: usize = 20;

/// The 48-byte seed of EVM wallet number `index`, from a 32-byte wallet root.
pub fn evm_seed_from_root(
    wallet_root: &[u8; WALLET_SEED_LEN],
    index: u32,
) -> Zeroizing<[u8; EVM_SEED_LEN]> {
    let info = format!("{INFO_EVM_WALLET_PREFIX}{index}");
    // from_prk cannot fail for a 32-byte PRK and expand cannot fail for 48 bytes (<= 255 * 32).
    let hk = Hkdf::<Sha256>::from_prk(wallet_root).expect("wallet root is 32 bytes");
    let mut seed = Zeroizing::new([0u8; EVM_SEED_LEN]);
    hk.expand(info.as_bytes(), &mut *seed)
        .expect("HKDF expand length within bounds");
    seed
}

/// The secp256k1 private key for a 48-byte EVM seed: `(OS2IP(seed) mod (n - 1)) + 1`, big-endian.
///
/// The seed is widened to 64 bytes with leading zeros — the same integer — so the library's
/// wide non-zero reduction computes exactly the FIPS 186-5 A.2.1 formula.
pub fn evm_key_from_seed(seed: &[u8; EVM_SEED_LEN]) -> Zeroizing<[u8; EVM_KEY_LEN]> {
    let mut wide = Zeroizing::new([0u8; 64]);
    wide[64 - EVM_SEED_LEN..].copy_from_slice(seed);
    let scalar = Zeroizing::new(<Scalar as ReduceNonZero<U512>>::reduce_nonzero(
        &U512::from_be_slice(&wide[..]),
    ));
    let mut key = Zeroizing::new([0u8; EVM_KEY_LEN]);
    key.copy_from_slice(scalar.to_repr().as_slice());
    key
}

/// The private key of EVM wallet number `index`, from a 32-byte wallet root.
pub fn evm_key_from_root(
    wallet_root: &[u8; WALLET_SEED_LEN],
    index: u32,
) -> Zeroizing<[u8; EVM_KEY_LEN]> {
    evm_key_from_seed(&evm_seed_from_root(wallet_root, index))
}

/// The 20-byte address of an EVM private key. `None` when the 32 bytes are not a scalar in
/// `[1, n - 1]` — a key from [`evm_key_from_seed`] always is.
pub fn evm_address_of_key(key: &[u8; EVM_KEY_LEN]) -> Option<[u8; EVM_ADDRESS_LEN]> {
    let repr = k256::FieldBytes::from(*key);
    let scalar: Option<Scalar> = Scalar::from_repr(repr).into();
    let scalar = Zeroizing::new(scalar?);
    if bool::from(scalar.is_zero()) {
        return None;
    }
    let point = (ProjectivePoint::GENERATOR * *scalar).to_affine();
    let encoded = point.to_sec1_point(false);
    // Uncompressed SEC1 is 0x04 || X(32) || Y(32); the address hashes X || Y.
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    let mut out = [0u8; EVM_ADDRESS_LEN];
    out.copy_from_slice(&hash[12..]);
    Some(out)
}

/// The EIP-55 mixed-case spelling of an address, with its `0x`.
pub fn evm_address_checksummed(address: &[u8; EVM_ADDRESS_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut lower = String::with_capacity(2 * EVM_ADDRESS_LEN);
    for b in address {
        lower.push(HEX[(b >> 4) as usize] as char);
        lower.push(HEX[(b & 0x0f) as usize] as char);
    }
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(2 + 2 * EVM_ADDRESS_LEN);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex48(s: &str) -> [u8; EVM_SEED_LEN] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
    }

    const ORDER_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    #[test]
    fn reduction_is_mod_n_minus_one_plus_one() {
        // 0 → 1: the formula's floor.
        assert_eq!(evm_key_from_seed(&[0u8; EVM_SEED_LEN])[31], 1);
        assert!(evm_key_from_seed(&[0u8; EVM_SEED_LEN])[..31]
            .iter()
            .all(|b| *b == 0));

        // n - 1 → 1 (it is the modulus itself), and n - 2 → n - 1 (the ceiling).
        let n_minus = |d: u8| {
            let mut s = hex48(&format!("{}{ORDER_HEX}", "0".repeat(32)));
            s[EVM_SEED_LEN - 1] -= d;
            s
        };
        let one = evm_key_from_seed(&n_minus(1));
        assert_eq!(one[31], 1);
        assert!(one[..31].iter().all(|b| *b == 0));
        let top = evm_key_from_seed(&n_minus(2));
        let mut expected = hex48(&format!("{}{ORDER_HEX}", "0".repeat(32)));
        expected[EVM_SEED_LEN - 1] -= 1;
        assert_eq!(&top[..], &expected[16..]);
    }

    #[test]
    fn labels_are_decimal_and_apart_from_the_sui_wallets() {
        let root = [9u8; WALLET_SEED_LEN];
        assert_ne!(
            *evm_seed_from_root(&root, 1),
            *evm_seed_from_root(&root, 10)
        );
        let sui = super::super::wallet_seed_from_root(&root, 0);
        assert_ne!(&evm_seed_from_root(&root, 0)[..32], &sui[..]);
    }

    #[test]
    fn a_zero_or_out_of_range_key_has_no_address() {
        assert!(evm_address_of_key(&[0u8; EVM_KEY_LEN]).is_none());
        assert!(evm_address_of_key(&[0xffu8; EVM_KEY_LEN]).is_none());
    }

    #[test]
    fn eip55_matches_the_standard_examples() {
        // EIP-55's own test addresses.
        for s in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let bytes: [u8; 20] = core::array::from_fn(|i| {
                u8::from_str_radix(&s[2 + 2 * i..4 + 2 * i], 16).expect("hex")
            });
            assert_eq!(evm_address_checksummed(&bytes), s);
        }
    }

    #[test]
    fn private_key_one_is_the_generator_address() {
        // secp256k1's generator G has the well-known Ethereum address below (private key 1).
        let mut key = [0u8; EVM_KEY_LEN];
        key[31] = 1;
        let addr = evm_address_of_key(&key).expect("valid");
        assert_eq!(
            evm_address_checksummed(&addr),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }
}
