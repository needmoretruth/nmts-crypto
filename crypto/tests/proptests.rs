//! Property tests for NCF-1 framing (CRYPTO-FORMAT.md §8).
//!
//! Uses only the production API (random nonces): roundtrip over arbitrary sizes,
//! random-access equivalence versus full sequential decrypt, and the invariant that any
//! single-bit mutation of an encrypted stream is rejected. Plaintext is a deterministic
//! pattern so proptest never has to generate/shrink multi-MiB byte vectors.

use nmts_crypto::framing::{
    decrypt_chunk, Header, PartPlacement, StreamDecryptor, StreamEncryptor, HEADER_LEN,
};
use proptest::prelude::*;

/// `byte[i] = i mod 256` — same pattern used by the committed vectors.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

const CAP_12MIB: usize = 12 * 1024 * 1024;
const CAP_1MIB: usize = 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Encrypt → decrypt is the identity, and the stream length matches the header math.
    #[test]
    fn roundtrip(size in 0usize..=CAP_12MIB, dek in any::<[u8; 32]>()) {
        let pt = pattern(size);
        let stream = StreamEncryptor::encrypt_all(&dek, &pt);
        let header = Header::parse(&stream[..HEADER_LEN]).unwrap();
        prop_assert_eq!(stream.len() as u64, header.stream_len());
        let out = StreamDecryptor::decrypt_all(&dek, &stream).unwrap();
        prop_assert_eq!(out, pt);
    }

    /// Random-access chunk decryption reassembles exactly the sequential-decrypt output.
    #[test]
    fn ranged_read_equivalence(size in 0usize..=CAP_12MIB, dek in any::<[u8; 32]>()) {
        let pt = pattern(size);
        let stream = StreamEncryptor::encrypt_all(&dek, &pt);
        let header = Header::parse(&stream[..HEADER_LEN]).unwrap();

        let mut assembled = Vec::with_capacity(size);
        for i in 0..header.chunk_count() {
            let off = header.chunk_offset(i).unwrap() as usize;
            let clen = header.chunk_ciphertext_len(i).unwrap();
            let ct = &stream[off..off + clen];
            // These streams come from `encrypt_all`, i.e. a whole file in one blob.
            let chunk_pt = decrypt_chunk(&dek, &header, PartPlacement::whole_file(), i, ct).unwrap();
            assembled.extend_from_slice(&chunk_pt);
        }
        let full = StreamDecryptor::decrypt_all(&dek, &stream).unwrap();
        prop_assert_eq!(&assembled, &pt);
        prop_assert_eq!(assembled, full);
    }

    /// Flipping any single bit of the stream makes decryption fail (every byte is
    /// authenticated: header via AAD, chunks via tag).
    #[test]
    fn single_bit_mutation_rejected(
        size in 0usize..=CAP_1MIB,
        dek in any::<[u8; 32]>(),
        pos in any::<usize>(),
        bit in 0u32..8,
    ) {
        let pt = pattern(size);
        let mut stream = StreamEncryptor::encrypt_all(&dek, &pt);
        let idx = pos % stream.len();
        stream[idx] ^= 1u8 << bit;
        prop_assert!(StreamDecryptor::decrypt_all(&dek, &stream).is_err());
    }

    /// Feeding wrong-length ciphertext to a ranged read is rejected without a panic.
    #[test]
    fn ranged_read_wrong_length_rejected(size in 1usize..=CAP_1MIB, dek in any::<[u8; 32]>()) {
        let pt = pattern(size);
        let stream = StreamEncryptor::encrypt_all(&dek, &pt);
        let header = Header::parse(&stream[..HEADER_LEN]).unwrap();
        let off = header.chunk_offset(0).unwrap() as usize;
        let clen = header.chunk_ciphertext_len(0).unwrap();
        // One byte short.
        prop_assert!(decrypt_chunk(
            &dek,
            &header,
            PartPlacement::whole_file(),
            0,
            &stream[off..off + clen - 1]
        )
        .is_err());
    }
}

/// Exact chunk-boundary sizes, covering single- and multi-chunk streams deterministically
/// (proptest samples these only occasionally).
#[test]
fn boundary_sizes_roundtrip() {
    let mib4 = 4 * 1024 * 1024;
    let sizes = [
        0,
        1,
        mib4 - 1,
        mib4,
        mib4 + 1,
        2 * mib4,
        2 * mib4 + 1,
        3 * mib4 + 123,
    ];
    let dek = [0x5au8; 32];
    for &size in &sizes {
        let pt = pattern(size);
        let stream = StreamEncryptor::encrypt_all(&dek, &pt);
        let out = StreamDecryptor::decrypt_all(&dek, &stream).unwrap();
        assert_eq!(out.len(), size, "size {size}");
        assert!(out == pt, "roundtrip mismatch at size {size}");
    }
}

/// Large multi-chunk roundtrip; ignored by default for speed (run explicitly).
#[test]
#[ignore = "48 MiB roundtrip — run explicitly"]
fn roundtrip_48mib() {
    let dek = [0x11u8; 32];
    let pt = pattern(48 * 1024 * 1024);
    let stream = StreamEncryptor::encrypt_all(&dek, &pt);
    let out = StreamDecryptor::decrypt_all(&dek, &stream).unwrap();
    assert!(out == pt);
}
