//! NCF-3 chunk-framed stream encryption (NCF-3 §4).
//!
//! # Purpose
//! Encrypt and decrypt one NCF-1 *stream* = one Walrus blob (or one part of a multi-part
//! file). Encryption and decryption are **streaming**: callers push plaintext/ciphertext
//! in and pull the transformed bytes out chunk by chunk, so a multi-gigabyte file never
//! needs to be buffered whole. Random-access chunk decryption is also supported for
//! ranged reads.
//!
//! # Wire format (NCF-3 — re-freezes at the mainnet cutover)
//! ```text
//! stream = header(72) || C0 || C1 || …
//! header = "NCF3"(4) | version(1)=3 | chunk_size_log2(1)=22 | reserved(2)=0
//!          | part_index(4, u32 LE) | part_total(4, u32 LE)
//!          | plaintext_len(8, u64 LE) | nonce_prefix(16, random) | key_commitment(32)
//! chunk_size   = 1 << chunk_size_log2 (4 MiB)
//! chunk_count  = max(1, ceil(plaintext_len / chunk_size))   // 0 bytes ⇒ 1 empty chunk
//! nonce_i (24) = nonce_prefix(16) || i (u64 LE)
//! aad_i   (81) = header(72) || i (u64 LE) || is_final(1: 0x01 iff i == count-1)
//! C_i          = XChaCha20Poly1305(DEK, nonce_i, plaintext_i, aad_i)  // ct || 16B tag
//!
//! key_commitment = HKDF-SHA256(ikm = DEK, salt = nonce_prefix, "nmts/v3/stream-commit", 32)
//! ```
//!
//! # What NCF-3 added here, and why it could never be added later
//!
//! **`part_index` / `part_total` (defect A4).** A multi-part file is several streams under ONE
//! DEK, and NCF-1 put nothing in a part's header saying which part it was. Each part
//! authenticated perfectly against its own header, so the server could reorder parts, replay an
//! old one, or drop the tail and every chunk would still verify. The counters are in the header,
//! the header is in every chunk's AAD, so a misplaced part now fails authentication.
//! ⚠ A **missing** part is not caught by the AEAD (bytes never handed over are never checked) —
//! that is [`verify_part_set`], and every reassembly path has to call it.
//! ⚠ Neither is a part read on its OWN, because its header travels with it: the AAD is
//! self-consistent whichever part the server actually sent. A reader holding one part states
//! where it thinks it is with a [`PartPlacement`], which [`decrypt_chunk`] requires and
//! [`Header::verify_placement`] checks.
//!
//! **`key_commitment` (defect A5).** Poly1305 is not key-committing: one ciphertext can be built
//! to open under two different keys into two different plaintexts. Public links hand out the DEK
//! by design, so "this stored blob is that file" has to be a fact. Verified in constant time
//! before the first chunk is decrypted — [`Header::verify_commitment`].
//!
//! The header grew 32 → 72 bytes to hold both. On a 4 MiB part that is one ten-thousandth of it.
//!
//! # Anti-truncation / reorder (enforced on sequential decrypt)
//! * `plaintext_len` lives in the header, which is in every chunk's AAD → any header edit
//!   fails authentication.
//! * `is_final` in the AAD prevents dropping the tail (the real final chunk is the only
//!   one authenticated with `0x01`).
//! * `chunk_index` in both nonce and AAD prevents reordering.
//! * On sequential decrypt we additionally verify: exactly `chunk_count` chunks consumed,
//!   the last one is the final chunk, the decoded total equals `plaintext_len`, and no
//!   bytes follow the final chunk.
//!
//! # Layout
//! * [`header`] — the 72-byte header type, its parsing, the commitment, and the geometry math.
//! * [`stream`] — the streaming encryptor/decryptor, random-access decrypt, and the
//!   deterministic vectors-only helpers.
//!
//! # Invariant
//! Production constructors NEVER accept caller nonces: [`StreamEncryptor::new`] draws a
//! fresh random `nonce_prefix`. Deterministic constructors exist only behind
//! `#[cfg(any(test, feature = "vectors"))]` for the conformance vectors.

mod header;
mod stream;

pub use header::{stream_commitment, verify_part_set, Header, PartPlacement};
pub use stream::{decrypt_chunk, StreamDecryptor, StreamEncryptor};

#[cfg(any(test, feature = "vectors"))]
pub use stream::forge_stream_with_final_flag;

/// Stream magic: ASCII `"NCF3"`.
pub const MAGIC: [u8; 4] = *b"NCF3";
/// NCF-3 stream version byte.
pub const VERSION: u8 = 3;
/// The only `chunk_size_log2` encoders emit: `22` ⇒ 4 MiB chunks. Re-examined for NCF-3 and kept:
/// ranged reads and the memory ceiling were both sized around it, and no defect touches it.
pub const DEFAULT_CHUNK_SIZE_LOG2: u8 = 22;
/// Plaintext header length, in bytes.
pub const HEADER_LEN: usize = 72;
/// Key-commitment length inside the header, in bytes.
pub const COMMITMENT_LEN: usize = 32;
/// HKDF `info` PREFIX for the stream key commitment (NCF-3 §4.2). The header bytes above the
/// commitment field are appended to it — see [`header::stream_commitment`].
pub const INFO_STREAM_COMMIT: &[u8] = b"nmts/v3/stream-commit";
/// Length of [`INFO_STREAM_COMMIT`], as a constant so the commitment buffer can be sized.
pub const INFO_STREAM_COMMIT_LEN: usize = 21;
/// Header offset of the random nonce prefix.
pub const NONCE_PREFIX_OFFSET: usize = 24;
/// Header offset of the key commitment — and therefore the length of the committed prefix.
pub const COMMITMENT_OFFSET: usize = 40;
/// Poly1305 tag length appended to each chunk's ciphertext.
pub const TAG_LEN: usize = 16;
/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Length of the random per-stream nonce prefix.
pub const NONCE_PREFIX_LEN: usize = 16;
/// Per-chunk AAD length: `header(72) + index(8) + is_final(1)`.
pub const AAD_LEN: usize = HEADER_LEN + 8 + 1;
/// DEK length.
pub const DEK_LEN: usize = 32;

/// Errors from stream encryption/decryption.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    /// Header was shorter than [`HEADER_LEN`] bytes.
    #[error("header too short")]
    ShortHeader,
    /// Header magic was not `"NCF3"`.
    #[error("bad magic")]
    BadMagic,
    /// Header version byte was not supported by this implementation.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// A declared `chunk_size_log2` that this build refuses (e.g. absurdly large).
    #[error("unsupported chunk_size_log2: {0}")]
    UnsupportedChunkSize(u8),
    /// AEAD authentication failed: corruption, wrong key, tamper, reorder, or truncation.
    #[error("authentication failed")]
    Auth,
    /// More plaintext/ciphertext was supplied than `plaintext_len` allows.
    #[error("too much data for declared plaintext_len")]
    TooMuchData,
    /// Fewer bytes than a complete stream were supplied before `finish`.
    #[error("incomplete stream: expected more chunk bytes")]
    Incomplete,
    /// Bytes remained after the final chunk (a chunk followed the final one).
    #[error("trailing data after final chunk")]
    TrailingData,
    /// Sequential decrypt recovered a byte count that disagreed with `plaintext_len`.
    #[error("decoded length {decoded} != declared plaintext_len {declared}")]
    LengthMismatch {
        /// Bytes actually recovered.
        decoded: u64,
        /// `plaintext_len` from the header.
        declared: u64,
    },
    /// A requested chunk index does not exist in this stream.
    #[error("chunk index {0} out of range")]
    ChunkIndexOutOfRange(u64),
    /// The ciphertext handed to a chunk decrypt had the wrong length for that chunk.
    #[error("wrong ciphertext length for chunk")]
    WrongChunkLength,
    /// A header declared a part placement that cannot exist (`total == 0`, `index >= total`), a
    /// set of parts disagreed about the total or repeated an index, or a part was read in a
    /// position it does not claim. The fields are always what the PART declares, never what the
    /// caller expected — the caller already knows the latter.
    ///
    /// Distinct from [`FramingError::Auth`] on purpose: nothing here depends on the key, so
    /// naming the real problem costs no oracle. See [`super::Header::verify_placement`].
    #[error("part {index} of {total} is not a valid placement")]
    BadPartPlacement {
        /// The part index as declared.
        index: u32,
        /// The part total as declared.
        total: u32,
    },
    /// Fewer (or more) parts were handed over than the file declares — see [`verify_part_set`].
    /// The AEAD cannot catch this on its own: bytes that were never supplied are never checked.
    #[error("expected {expected} parts, got {found}")]
    IncompletePartSet {
        /// Parts the file says it has.
        expected: u32,
        /// Parts actually handed over.
        found: u64,
    },
}
