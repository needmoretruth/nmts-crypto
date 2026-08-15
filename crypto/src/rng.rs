//! OS cryptographically-secure randomness.
//!
//! # Purpose
//! Single, auditable source of randomness for the whole crate. Every random value
//! required by NCF-1 (account/voucher codes, stream `nonce_prefix`es, envelope
//! nonces, file DEKs) is drawn from here so there is exactly one place that touches
//! the operating system's CSPRNG.
//!
//! # Contract
//! * [`OsRng`] wraps the [`getrandom`] crate, which reads from the platform CSPRNG
//!   (`/dev/urandom`, `getrandom(2)`, `BCryptGenRandom`, …) and — under the crate's
//!   `wasm` feature — from the browser's `crypto.getRandomValues`.
//! * It implements [`rand_core::RngCore`] + [`rand_core::CryptoRng`], so it can be
//!   handed to any RustCrypto API expecting a CSPRNG.
//!
//! # Invariants
//! * NCF-1 forbids caller-supplied nonces in production. This module is the ONLY
//!   randomness seam; deterministic test vectors bypass it exclusively through the
//!   `#[cfg(any(test, feature = "vectors"))]` constructors elsewhere in the crate.
//! * A failure of the OS CSPRNG is unrecoverable and non-negotiable for a crypto
//!   engine, so [`OsRng::fill_bytes`] panics rather than silently degrading.

use rand_core::{CryptoRng, RngCore};

/// Handle to the operating system's cryptographically-secure RNG.
///
/// Zero-sized; construct with `OsRng` and call [`RngCore`] methods, or use the
/// convenience helpers on this crate's internal call sites.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl OsRng {
    /// Fills `dest` with fresh OS randomness, returning an error instead of panicking.
    ///
    /// Prefer this at fallible boundaries; [`RngCore::fill_bytes`] panics on failure.
    pub fn try_fill(dest: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::getrandom(dest)
    }

    /// Returns `N` fresh random bytes, panicking if the OS CSPRNG is unavailable.
    pub fn bytes<const N: usize>() -> [u8; N] {
        let mut out = [0u8; N];
        getrandom::getrandom(&mut out).expect("OS CSPRNG unavailable");
        out
    }
}

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(Self::bytes::<4>())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(Self::bytes::<8>())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS CSPRNG unavailable");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // getrandom 0.2's `Error::code()` yields the underlying `NonZeroU32`, which
        // `rand_core::Error` wraps directly.
        getrandom::getrandom(dest).map_err(|e| rand_core::Error::from(e.code()))
    }
}

impl CryptoRng for OsRng {}
