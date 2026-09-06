# For programs and agents working in this repository

This is the NMTS crypto library: the Rust crate the browser (through WebAssembly) and the
recovery program both use. The format it implements is NCF-3, and the format document beside the
code is the specification; the code follows it, not the other way round.

## What to know before changing anything

- `docs/CRYPTO-FORMAT-NCF3.md` is the specification. Section 1 (the derivation chain) and section 5
  (the share identity) are frozen: a change there is a new format version, not an edit.
- Every HKDF `info` string, AEAD associated data and hash prefix is listed in section 2 of that
  document. A separator that is not listed there must not be used; adding one is a documented
  addition with a test vector.
- `tests/vectors/ncf3.json` is the conformance record. A change that alters any existing output
  in it is a bug, not an update. New outputs are added with their inputs.
- No `unsafe`. Cryptographic primitives come from the audited crates already in `Cargo.toml`;
  nothing is implemented by hand.

## How to check your work

Run the crate's tests with the `vectors` feature enabled, and clippy over all targets. Both must be
clean. The browser and the recovery program run the same vectors, so a change here that passes
only here is still wrong.

## What this repository is not

The server and the web application of NMTS are not published. This crate has no network code and
knows nothing about accounts, payments or the storage network; it turns an account code into keys
and seals and opens bytes.
