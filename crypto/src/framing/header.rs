//! NCF-3 stream header: the 72 plaintext bytes at offset 0, and the stream geometry
//! (chunk count, per-chunk lengths and offsets) derived from them.
//!
//! The header is bound verbatim into every chunk's AAD, so any edit to it is caught by
//! authentication. See the parent module for the wire layout.

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{
    FramingError, COMMITMENT_LEN, COMMITMENT_OFFSET, DEK_LEN, HEADER_LEN, INFO_STREAM_COMMIT,
    INFO_STREAM_COMMIT_LEN, MAGIC, NONCE_PREFIX_LEN, NONCE_PREFIX_OFFSET, TAG_LEN, VERSION,
};

/// The key commitment for a stream (NCF-3 §4.2).
///
/// Binds the DEK and every header byte ABOVE the commitment field. The commitment itself cannot
/// be an input — it lives inside the header — so the committed prefix stops exactly at its offset.
pub fn stream_commitment(
    dek: &[u8; DEK_LEN],
    header_prefix: &[u8; COMMITMENT_OFFSET],
) -> [u8; COMMITMENT_LEN] {
    // Everything in the header ABOVE the commitment field is an input: magic, version,
    // chunk_size_log2, the part counters, plaintext_len and the nonce prefix.
    //
    // Binding only the DEK and the nonce prefix was not enough. Those other fields are covered by
    // every chunk's AEAD tag, so a change to them is caught — but only AFTER a reader has already
    // used them to decide how much memory to allocate and how many chunks to expect. A rewritten
    // `chunk_size_log2` turns a bounded streaming read into an unbounded one before a single tag
    // is checked. Folding the prefix in means the header is rejected up front, at the same
    // constant-time comparison that catches the wrong key.
    let mut info = [0u8; INFO_STREAM_COMMIT_LEN + COMMITMENT_OFFSET];
    info[..INFO_STREAM_COMMIT_LEN].copy_from_slice(INFO_STREAM_COMMIT);
    info[INFO_STREAM_COMMIT_LEN..].copy_from_slice(header_prefix);
    let hk = Hkdf::<Sha256>::new(Some(&header_prefix[NONCE_PREFIX_OFFSET..]), dek);
    let mut out = [0u8; COMMITMENT_LEN];
    hk.expand(&info, &mut out)
        .expect("HKDF expand length within bounds");
    out
}

/// The placement a caller EXPECTS the part in front of it to declare: "I am about to read part
/// `index` of a `total`-part file" (NCF-3 §4.1, defect A4).
///
/// It is a type, rather than two loose integers, so that every path which opens part of a file
/// takes it as ONE required argument and a reader cannot silently omit half of it. The value must
/// come from where the caller is reading INTO — the write position, the loop counter, the seek
/// offset it computed the range from — never from anything the same server response carried.
/// Reading it back out of the header being checked compares a value with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartPlacement {
    /// Zero-based position in the file the caller is filling.
    pub index: u32,
    /// How many parts the caller believes the whole file has.
    pub total: u32,
}

impl PartPlacement {
    /// A whole file held in ONE stream: part 0 of 1.
    ///
    /// Not a formality — it is what stops one part of a multi-part file being read as if it were
    /// the entire file, which is otherwise a perfectly authenticating decrypt.
    pub const fn whole_file() -> Self {
        Self { index: 0, total: 1 }
    }

    /// Position `index` of a `total`-part file.
    pub const fn at(index: u32, total: u32) -> Self {
        Self { index, total }
    }
}

/// A parsed NCF-3 stream header plus the derived geometry of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Version byte (always [`VERSION`] for a stream this build accepts).
    pub version: u8,
    /// `log2` of the chunk size actually recorded in the header.
    pub chunk_size_log2: u8,
    /// Which part of the file this stream is (0-based). Single-blob files are part 0 of 1.
    pub part_index: u32,
    /// How many parts the whole file has. Never zero in a valid header.
    pub part_total: u32,
    /// Total plaintext bytes in THIS part.
    pub plaintext_len: u64,
    /// The random per-stream nonce prefix.
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// The key commitment (NCF-3 §4.2). Verify with [`Header::verify_commitment`] before
    /// decrypting anything.
    pub key_commitment: [u8; COMMITMENT_LEN],
    /// The exact 72 header bytes (used verbatim in every chunk's AAD).
    raw: [u8; HEADER_LEN],
}

impl Header {
    /// Chunk size in bytes (`1 << chunk_size_log2`).
    pub fn chunk_size(&self) -> u64 {
        1u64 << self.chunk_size_log2
    }

    /// Number of chunks: `max(1, ceil(plaintext_len / chunk_size))` (0 bytes ⇒ 1 chunk).
    pub fn chunk_count(&self) -> u64 {
        let cs = self.chunk_size();
        if self.plaintext_len == 0 {
            1
        } else {
            self.plaintext_len.div_ceil(cs)
        }
    }

    /// The verbatim 72 header bytes.
    pub fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.raw
    }

    /// Checks the key commitment in constant time (NCF-3 §4.2).
    ///
    /// ⚠ **Call this before decrypting.** Without it, one ciphertext can be built to open under
    /// two different keys into two different plaintexts — which matters here because a public
    /// link hands the DEK to whoever holds it, so "this blob is that file" must be a fact rather
    /// than a claim. Returns the same error as a failed tag: telling an attacker which half of
    /// their guess was right is itself an oracle.
    pub fn verify_commitment(&self, dek: &[u8; DEK_LEN]) -> Result<(), FramingError> {
        let prefix: &[u8; COMMITMENT_OFFSET] = self.raw[..COMMITMENT_OFFSET]
            .try_into()
            .expect("header is HEADER_LEN bytes");
        let expected = stream_commitment(dek, prefix);
        if bool::from(expected.ct_eq(&self.key_commitment)) {
            Ok(())
        } else {
            Err(FramingError::Auth)
        }
    }

    /// Checks that this part declares the placement the caller expects (NCF-3 §4.1, defect A4).
    ///
    /// This is the single-part twin of [`verify_part_set`]: that function needs every header of a
    /// file at once, which a reader holding one part — a ranged read, a preview, one iteration of
    /// a streaming download — never has. Both enforce the same rule from opposite ends, and both
    /// compare the SEALED position against a position the caller supplies from somewhere else.
    ///
    /// The refusal is [`FramingError::BadPartPlacement`], NOT [`FramingError::Auth`], and the
    /// difference from [`Header::verify_commitment`] is deliberate. The commitment folds into
    /// `Auth` because it is a check on the KEY: telling an attacker that their key was right but
    /// their tag was wrong (or the reverse) is an oracle. Placement involves no secret at all —
    /// both operands are plaintext, one chosen by whoever served the header and one by the caller
    /// — so distinguishing "wrong part" from "wrong key" hands over nothing that was not already
    /// known to the party who could trigger it, while naming it precisely is the difference
    /// between "this file is corrupt" and "you were served part 3 where part 1 belongs".
    pub fn verify_placement(&self, expected: PartPlacement) -> Result<(), FramingError> {
        if self.part_index == expected.index && self.part_total == expected.total {
            Ok(())
        } else {
            Err(FramingError::BadPartPlacement {
                index: self.part_index,
                total: self.part_total,
            })
        }
    }

    /// Plaintext byte length of chunk `index` (all non-final chunks are `chunk_size`).
    pub fn chunk_plaintext_len(&self, index: u64) -> Result<u64, FramingError> {
        let count = self.chunk_count();
        if index >= count {
            return Err(FramingError::ChunkIndexOutOfRange(index));
        }
        let cs = self.chunk_size();
        if index + 1 < count {
            Ok(cs)
        } else {
            // Final chunk: remainder (or a full/last-and-only chunk).
            let full = (count - 1) * cs;
            Ok(self.plaintext_len - full)
        }
    }

    /// Ciphertext byte length of chunk `index` (plaintext length + tag).
    pub fn chunk_ciphertext_len(&self, index: u64) -> Result<usize, FramingError> {
        Ok(self.chunk_plaintext_len(index)? as usize + TAG_LEN)
    }

    /// Byte offset of chunk `index` within the stream (after the header).
    ///
    /// All chunks before the final one occupy `chunk_size + TAG_LEN` bytes, so the offset
    /// is exact for ranged reads: `HEADER_LEN + index * (chunk_size + 16)`.
    pub fn chunk_offset(&self, index: u64) -> Result<u64, FramingError> {
        let count = self.chunk_count();
        if index >= count {
            return Err(FramingError::ChunkIndexOutOfRange(index));
        }
        Ok(HEADER_LEN as u64 + index * (self.chunk_size() + TAG_LEN as u64))
    }

    /// Total encrypted stream length: `HEADER_LEN + plaintext_len + 16 * chunk_count`.
    pub fn stream_len(&self) -> u64 {
        HEADER_LEN as u64 + self.plaintext_len + TAG_LEN as u64 * self.chunk_count()
    }

    /// Parses and validates a 72-byte header prefix.
    pub fn parse(bytes: &[u8]) -> Result<Header, FramingError> {
        if bytes.len() < HEADER_LEN {
            return Err(FramingError::ShortHeader);
        }
        let mut raw = [0u8; HEADER_LEN];
        raw.copy_from_slice(&bytes[..HEADER_LEN]);

        if raw[0..4] != MAGIC {
            return Err(FramingError::BadMagic);
        }
        let version = raw[4];
        if version != VERSION {
            return Err(FramingError::UnsupportedVersion(version));
        }
        let chunk_size_log2 = raw[5];
        // Reserved bytes (raw[6..8]) are covered by the AAD, so tampering is caught by
        // authentication; we do not otherwise constrain them here.
        // Guard against pathological shifts (`1 << log2` must fit in u64 with headroom).
        if chunk_size_log2 == 0 || chunk_size_log2 >= 63 {
            return Err(FramingError::UnsupportedChunkSize(chunk_size_log2));
        }
        let part_index = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let part_total = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        // A part index outside its own declared total is self-contradictory, and `part_total = 0`
        // describes a file with no parts. Rejecting both here means no later code has to wonder.
        if part_total == 0 || part_index >= part_total {
            return Err(FramingError::BadPartPlacement {
                index: part_index,
                total: part_total,
            });
        }
        let plaintext_len = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&raw[NONCE_PREFIX_OFFSET..COMMITMENT_OFFSET]);
        let mut key_commitment = [0u8; COMMITMENT_LEN];
        key_commitment.copy_from_slice(&raw[COMMITMENT_OFFSET..HEADER_LEN]);

        Ok(Header {
            version,
            chunk_size_log2,
            part_index,
            part_total,
            plaintext_len,
            nonce_prefix,
            key_commitment,
            raw,
        })
    }
}

/// Checks that `headers` really is the whole file, **in the order the caller will read them**
/// (NCF-3 §4.1, A4).
///
/// The per-part `part_index`/`part_total` in the header stop a part being decrypted as if it were
/// a different part — the header is in every chunk's AAD, so a swap fails authentication. What
/// they cannot do on their own is notice that a part is **missing**, because a part that is never
/// handed over is never authenticated. That is what this function is for, and **every path that
/// reassembles a multi-part file has to call it**: download, resume, and any ranged read that
/// spans parts.
///
/// ⚠ **`headers[i]` must be the part the caller intends to concatenate at position `i`.** The
/// check is `headers[i].part_index == i`, not "every index appears once": a first version of this
/// function accepted any permutation, which let a hostile server hand back a file's parts in a
/// scrambled order with every chunk still authenticating — each part is internally valid, and
/// nothing had compared its declared position against the position it was actually being used in.
/// Passing a set that has already been sorted by `part_index` therefore defeats the check; pass
/// them in server order.
pub fn verify_part_set(headers: &[Header]) -> Result<(), FramingError> {
    let Some(first) = headers.first() else {
        return Err(FramingError::IncompletePartSet {
            expected: 0,
            found: 0,
        });
    };
    let total = first.part_total;
    if headers.len() as u64 != u64::from(total) {
        return Err(FramingError::IncompletePartSet {
            expected: total,
            found: headers.len() as u64,
        });
    }
    for (position, h) in headers.iter().enumerate() {
        // Disagreement about the total means two different files, or one file's parts mixed with
        // another's — caught before the position check so the error names the real problem.
        if h.part_total != total {
            return Err(FramingError::BadPartPlacement {
                index: h.part_index,
                total: h.part_total,
            });
        }
        if u64::from(h.part_index) != position as u64 {
            return Err(FramingError::BadPartPlacement {
                index: h.part_index,
                total,
            });
        }
    }
    Ok(())
}

/// Builds the 72 raw header bytes, computing the key commitment over everything above it.
///
/// The commitment is derived HERE rather than by the caller so there is exactly one place that
/// decides what it covers. A caller that assembled the prefix itself could get the boundary wrong
/// and produce a header that verifies against less than it should.
pub(super) fn build_header(
    dek: &[u8; DEK_LEN],
    chunk_size_log2: u8,
    part_index: u32,
    part_total: u32,
    plaintext_len: u64,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&MAGIC);
    h[4] = VERSION;
    h[5] = chunk_size_log2;
    // h[6..8] reserved = 0.
    h[8..12].copy_from_slice(&part_index.to_le_bytes());
    h[12..16].copy_from_slice(&part_total.to_le_bytes());
    h[16..24].copy_from_slice(&plaintext_len.to_le_bytes());
    h[NONCE_PREFIX_OFFSET..COMMITMENT_OFFSET].copy_from_slice(nonce_prefix);
    let prefix: &[u8; COMMITMENT_OFFSET] = h[..COMMITMENT_OFFSET]
        .try_into()
        .expect("prefix is COMMITMENT_OFFSET bytes");
    let commitment = stream_commitment(dek, prefix);
    h[COMMITMENT_OFFSET..HEADER_LEN].copy_from_slice(&commitment);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_at(dek: &[u8; DEK_LEN], index: u32, total: u32) -> Header {
        let raw = build_header(dek, 22, index, total, 100, &[7u8; NONCE_PREFIX_LEN]);
        Header::parse(&raw).expect("built header parses")
    }

    #[test]
    fn a_permutation_of_the_right_parts_is_still_wrong() {
        // Found by an adversarial review (2026-07-29): the first version of `verify_part_set` checked that every
        // index appeared exactly once and nothing more, so a server could hand back all the right
        // parts in the wrong ORDER and every chunk would still authenticate — each part is
        // internally valid, and nothing compared its declared position with the position it was
        // being used in. That is the whole attack A4 was supposed to close.
        let dek = [1u8; DEK_LEN];
        let p0 = header_at(&dek, 0, 3);
        let p1 = header_at(&dek, 1, 3);
        let p2 = header_at(&dek, 2, 3);

        assert!(verify_part_set(&[p0.clone(), p1.clone(), p2.clone()]).is_ok());

        for scrambled in [
            vec![p1.clone(), p0.clone(), p2.clone()],
            vec![p0.clone(), p2.clone(), p1.clone()],
            vec![p2.clone(), p1.clone(), p0.clone()],
        ] {
            assert!(
                matches!(
                    verify_part_set(&scrambled),
                    Err(FramingError::BadPartPlacement { .. })
                ),
                "a reordered part set must be refused",
            );
        }
    }

    #[test]
    fn a_single_part_is_checked_against_the_position_the_reader_is_filling() {
        // Found by an adversarial review of the ranged-read path (2026-07-29): a reader holding
        // ONE part cannot call `verify_part_set`,
        // so before this existed the only "check" available to a ranged read was the AAD — which
        // is satisfied by every part of the file, because they all share a DEK and each carries
        // its own header. `verify_placement` is what a one-part reader compares against.
        let dek = [3u8; DEK_LEN];
        let p1 = header_at(&dek, 1, 3);

        assert!(p1.verify_placement(PartPlacement::at(1, 3)).is_ok());
        for wrong in [
            PartPlacement::at(0, 3),     // another position in the same file
            PartPlacement::at(2, 3),     // ditto, the other side
            PartPlacement::at(1, 4),     // same position, a file with a different part count
            PartPlacement::whole_file(), // one part of a file read as if it were all of it
        ] {
            assert!(
                matches!(
                    p1.verify_placement(wrong),
                    Err(FramingError::BadPartPlacement { index: 1, total: 3 })
                ),
                "a part must be refused wherever it does not belong, and the error must name what
                 the part ACTUALLY claims — not what the caller asked for",
            );
        }

        // A whole-file stream is part 0 of 1 and passes exactly that expectation.
        let whole = header_at(&dek, 0, 1);
        assert!(whole.verify_placement(PartPlacement::whole_file()).is_ok());
        assert!(whole.verify_placement(PartPlacement::at(0, 3)).is_err());
    }

    #[test]
    fn the_commitment_covers_the_whole_header_prefix() {
        // Found by an adversarial review (2026-07-29): binding only (DEK, nonce_prefix) left `chunk_size_log2` and
        // `plaintext_len` unchecked until the first AEAD tag — after a reader had already sized
        // its buffers from them. Every field above the commitment is an input now.
        let dek = [2u8; DEK_LEN];
        let base = build_header(&dek, 22, 0, 1, 100, &[9u8; NONCE_PREFIX_LEN]);

        for byte in [5usize, 8, 12, 16, 24] {
            let mut edited = base;
            edited[byte] ^= 0x01;
            // A parse error is not a miss: some edits (part counters, chunk size) are rejected by
            // `parse` outright, which is an even earlier refusal and equally fine. What must never
            // happen is an edited header that parses AND still verifies.
            if let Ok(h) = Header::parse(&edited) {
                assert!(
                    h.verify_commitment(&dek).is_err(),
                    "editing header byte {byte} must break the commitment",
                );
            }
        }
    }
}
