//! Streaming NCF-3 encryptor/decryptor, random-access chunk decryption, and the
//! deterministic (vectors-only) constructors.
//!
//! All per-chunk nonce/AAD construction and the raw AEAD calls live here; the header type
//! and geometry live in [`super::header`].

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use super::header::{build_header, Header, PartPlacement};
use super::{
    FramingError, AAD_LEN, DEFAULT_CHUNK_SIZE_LOG2, DEK_LEN, HEADER_LEN, NONCE_LEN,
    NONCE_PREFIX_LEN, TAG_LEN,
};
use crate::rng::OsRng;
use rand_core::RngCore;

/// Constructs the 24-byte nonce for a chunk: `nonce_prefix || index (u64 LE)`.
fn chunk_nonce(nonce_prefix: &[u8; NONCE_PREFIX_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    n[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_le_bytes());
    n
}

/// Constructs the 81-byte AAD for a chunk: `header || index (u64 LE) || is_final`.
fn chunk_aad(header: &[u8; HEADER_LEN], index: u64, is_final: bool) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    a[..HEADER_LEN].copy_from_slice(header);
    a[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&index.to_le_bytes());
    a[AAD_LEN - 1] = if is_final { 0x01 } else { 0x00 };
    a
}

/// Encrypts one chunk, returning `ciphertext || tag`.
fn seal_chunk(
    cipher: &XChaCha20Poly1305,
    header: &[u8; HEADER_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    index: u64,
    is_final: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = chunk_nonce(nonce_prefix, index);
    let aad = chunk_aad(header, index, is_final);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20Poly1305 encryption is infallible for valid inputs")
}

/// Decrypts one chunk (`ciphertext || tag`), verifying the tag against the derived AAD.
fn open_chunk(
    cipher: &XChaCha20Poly1305,
    header: &[u8; HEADER_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    index: u64,
    is_final: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FramingError> {
    let nonce = chunk_nonce(nonce_prefix, index);
    let aad = chunk_aad(header, index, is_final);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| FramingError::Auth)
}

fn new_cipher(dek: &[u8; DEK_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(dek))
}

/// Streaming NCF-1 encryptor.
///
/// The total `plaintext_len` must be known up front (it is written into the header). Push
/// plaintext with [`StreamEncryptor::push`]; each call returns any now-complete encrypted
/// chunks. Call [`StreamEncryptor::finish`] once all plaintext has been pushed to obtain
/// the final chunk. Concatenating the header with every returned buffer yields the stream.
pub struct StreamEncryptor {
    cipher: XChaCha20Poly1305,
    header: [u8; HEADER_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: usize,
    plaintext_len: u64,
    chunk_count: u64,
    buf: Vec<u8>,
    next_index: u64,
    received: u64,
    finished: bool,
}

impl StreamEncryptor {
    /// Creates an encryptor for a WHOLE file held in one blob — part 0 of 1 — with a fresh
    /// random `nonce_prefix` and the standard chunk size (4 MiB).
    pub fn new(dek: &[u8; DEK_LEN], plaintext_len: u64) -> Self {
        Self::new_part(dek, plaintext_len, 0, 1)
    }

    /// Creates an encryptor for ONE PART of a multi-part file (NCF-3 §4.1, defect A4).
    ///
    /// `part_index` and `part_total` go into the header and therefore into every chunk's AAD, so
    /// a part that is later served in another position fails authentication instead of decrypting
    /// into the wrong place. Callers must number parts `0 … part_total-1` and must not reuse a
    /// DEK across different files.
    ///
    /// # Panics
    /// If the placement is impossible (`part_total == 0` or `part_index >= part_total`). This is
    /// a caller bug, not an input: producing such a header would make a stream nothing can open.
    pub fn new_part(
        dek: &[u8; DEK_LEN],
        plaintext_len: u64,
        part_index: u32,
        part_total: u32,
    ) -> Self {
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        OsRng.fill_bytes(&mut nonce_prefix);
        Self::build(
            dek,
            plaintext_len,
            part_index,
            part_total,
            nonce_prefix,
            DEFAULT_CHUNK_SIZE_LOG2,
        )
    }

    /// Shared constructor for both production and deterministic paths.
    fn build(
        dek: &[u8; DEK_LEN],
        plaintext_len: u64,
        part_index: u32,
        part_total: u32,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        chunk_size_log2: u8,
    ) -> Self {
        assert!(
            part_total > 0 && part_index < part_total,
            "part {part_index} of {part_total} is not a valid placement",
        );
        let header = build_header(
            dek,
            chunk_size_log2,
            part_index,
            part_total,
            plaintext_len,
            &nonce_prefix,
        );
        let parsed = Header::parse(&header).expect("freshly built header is valid");
        Self {
            cipher: new_cipher(dek),
            header,
            nonce_prefix,
            chunk_size: parsed.chunk_size() as usize,
            plaintext_len,
            chunk_count: parsed.chunk_count(),
            buf: Vec::new(),
            next_index: 0,
            received: 0,
            finished: false,
        }
    }

    /// The 72 plaintext header bytes. Emit these first, before any chunk output.
    pub fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    /// Feeds plaintext in. Returns any chunks that became complete (may be empty).
    ///
    /// The final chunk is never emitted here (only [`StreamEncryptor::finish`] flags a
    /// chunk `is_final`), so full non-final chunks stream out as soon as they fill.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, FramingError> {
        self.received += data.len() as u64;
        if self.received > self.plaintext_len {
            return Err(FramingError::TooMuchData);
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        // Emit only non-final chunks; keep at least enough bytes to form the final chunk.
        while self.next_index + 1 < self.chunk_count && self.buf.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buf.drain(..self.chunk_size).collect();
            let sealed = seal_chunk(
                &self.cipher,
                &self.header,
                &self.nonce_prefix,
                self.next_index,
                false,
                &chunk,
            );
            out.extend_from_slice(&sealed);
            self.next_index += 1;
        }
        Ok(out)
    }

    /// Flushes the final chunk. Must be called exactly once, after all plaintext is in.
    pub fn finish(&mut self) -> Result<Vec<u8>, FramingError> {
        if self.finished {
            return Ok(Vec::new());
        }
        if self.received != self.plaintext_len {
            return Err(FramingError::Incomplete);
        }
        // Any full non-final chunks still buffered must go out first (e.g. all data was
        // pushed in one call). This loop leaves exactly the final chunk in `buf`.
        let mut out = Vec::new();
        while self.next_index + 1 < self.chunk_count {
            let take = self.chunk_size.min(self.buf.len());
            let chunk: Vec<u8> = self.buf.drain(..take).collect();
            out.extend_from_slice(&seal_chunk(
                &self.cipher,
                &self.header,
                &self.nonce_prefix,
                self.next_index,
                false,
                &chunk,
            ));
            self.next_index += 1;
        }
        // Final chunk = whatever remains (possibly empty for a 0-byte stream).
        let final_index = self.chunk_count - 1;
        out.extend_from_slice(&seal_chunk(
            &self.cipher,
            &self.header,
            &self.nonce_prefix,
            final_index,
            true,
            &self.buf,
        ));
        self.buf.clear();
        self.next_index = self.chunk_count;
        self.finished = true;
        Ok(out)
    }

    /// Convenience: encrypt an entire in-memory plaintext to a complete stream.
    pub fn encrypt_all(dek: &[u8; DEK_LEN], plaintext: &[u8]) -> Vec<u8> {
        let mut enc = Self::new(dek, plaintext.len() as u64);
        let mut stream =
            Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN * enc.chunk_count as usize);
        stream.extend_from_slice(enc.header());
        stream.extend_from_slice(&enc.push(plaintext).expect("push within declared length"));
        stream.extend_from_slice(&enc.finish().expect("finish after full push"));
        stream
    }
}

/// Streaming NCF-3 decryptor with full anti-truncation / reorder verification.
///
/// Construct from a DEK and the 72-byte header, push ciphertext with
/// [`StreamDecryptor::push`] (which yields decrypted plaintext as each chunk completes),
/// and call [`StreamDecryptor::finish`] to enforce the end-of-stream invariants.
pub struct StreamDecryptor {
    cipher: XChaCha20Poly1305,
    header: Header,
    buf: Vec<u8>,
    next_index: u64,
    decoded: u64,
    done: bool,
}

impl StreamDecryptor {
    /// Parses `header`, VERIFIES THE KEY COMMITMENT, and prepares to decrypt.
    ///
    /// The commitment check happens here rather than at the first chunk so that no construction
    /// of this type can skip it — a decryptor that exists is one whose header names this exact
    /// DEK. See [`Header::verify_commitment`] for why that matters.
    pub fn new(dek: &[u8; DEK_LEN], header: &[u8]) -> Result<Self, FramingError> {
        let header = Header::parse(header)?;
        header.verify_commitment(dek)?;
        Ok(Self {
            cipher: new_cipher(dek),
            header,
            buf: Vec::new(),
            next_index: 0,
            decoded: 0,
            done: false,
        })
    }

    /// The parsed header (geometry, `plaintext_len`, nonce prefix).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Feeds ciphertext in. Returns decrypted plaintext for any chunks that completed.
    ///
    /// Each chunk is authenticated against its derived AAD (with `is_final` computed from
    /// the chunk index), so reordering, truncation, and tampering all surface as
    /// [`FramingError::Auth`].
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, FramingError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let count = self.header.chunk_count();
        loop {
            if self.next_index >= count {
                // All chunks already decoded; nothing more may follow.
                if !self.buf.is_empty() {
                    return Err(FramingError::TrailingData);
                }
                break;
            }
            let need = self.header.chunk_ciphertext_len(self.next_index)?;
            if self.buf.len() < need {
                break;
            }
            let is_final = self.next_index + 1 == count;
            let chunk_ct: Vec<u8> = self.buf.drain(..need).collect();
            let pt = open_chunk(
                &self.cipher,
                self.header.as_bytes(),
                &self.header.nonce_prefix,
                self.next_index,
                is_final,
                &chunk_ct,
            )?;
            self.decoded += pt.len() as u64;
            out.extend_from_slice(&pt);
            self.next_index += 1;
        }
        Ok(out)
    }

    /// Verifies the stream ended cleanly: all chunks consumed, decoded total matches
    /// `plaintext_len`, and no trailing bytes remain.
    pub fn finish(&mut self) -> Result<(), FramingError> {
        if self.done {
            return Ok(());
        }
        let count = self.header.chunk_count();
        if self.next_index < count {
            return Err(FramingError::Incomplete);
        }
        if !self.buf.is_empty() {
            return Err(FramingError::TrailingData);
        }
        if self.decoded != self.header.plaintext_len {
            return Err(FramingError::LengthMismatch {
                decoded: self.decoded,
                declared: self.header.plaintext_len,
            });
        }
        self.done = true;
        Ok(())
    }

    /// Convenience: decrypt a complete in-memory stream, running all end-of-stream checks.
    pub fn decrypt_all(dek: &[u8; DEK_LEN], stream: &[u8]) -> Result<Vec<u8>, FramingError> {
        if stream.len() < HEADER_LEN {
            return Err(FramingError::ShortHeader);
        }
        let mut dec = Self::new(dek, &stream[..HEADER_LEN])?;
        let mut out = dec.push(&stream[HEADER_LEN..])?;
        dec.finish()?;
        out.shrink_to_fit();
        Ok(out)
    }
}

/// Decrypts a single chunk for random access (ranged reads), independent of stream state.
///
/// `ciphertext` must be exactly the bytes of chunk `index` (`chunk_ciphertext_len(index)`
/// bytes); use [`Header::chunk_offset`] and [`Header::chunk_ciphertext_len`] to locate
/// them. `is_final` is derived from the header, so a ranged read of the true final chunk
/// authenticates correctly while a wrongly-sized slice is rejected.
///
/// `expected` says WHICH PART of the file the caller believes it is reading. It is required, not
/// optional, and that is the whole point (an adversarial review of this path found it,
/// 2026-07-29). A ranged reader takes the
/// 72-byte header and the chunk from the SAME response, so the AAD binding it relies on is
/// self-consistent no matter which part the server actually sent: every part of a file is sealed
/// under one DEK, so part `j`'s chunk `k` served where part `i`'s chunk `k` was asked for opens
/// with a valid tag and yields clean plaintext from the wrong place. Nothing else on this path
/// can notice — [`super::verify_part_set`] needs every header at once and a ranged read holds
/// one. Passing a placement read back out of `header` restores exactly that hole, so take it from
/// wherever the byte range was computed: the seek offset, the preview's part number, the position
/// being written into.
pub fn decrypt_chunk(
    dek: &[u8; DEK_LEN],
    header: &Header,
    expected: PartPlacement,
    index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FramingError> {
    // The commitment check belongs on EVERY path that decrypts, not only the sequential one.
    // [`StreamDecryptor::new`] does it once at construction; a ranged read has no such
    // construction, so without this line the A5 guarantee simply would not hold for previews,
    // seeks, or any partial download — and the gap would be invisible, because the bytes come out
    // correctly for the key you actually used.
    //
    // It runs BEFORE the placement check on purpose: until the commitment holds, this header is
    // not known to describe anything sealed under this DEK, and reporting "you were served part 2
    // of 3" about a header belonging to some other file would name the wrong problem. Commitment
    // first ⇒ `Auth` means "not our stream", `BadPartPlacement` means "our stream, wrong place".
    header.verify_commitment(dek)?;
    header.verify_placement(expected)?;
    let expected_len = header.chunk_ciphertext_len(index)?;
    if ciphertext.len() != expected_len {
        return Err(FramingError::WrongChunkLength);
    }
    let is_final = index + 1 == header.chunk_count();
    let cipher = new_cipher(dek);
    open_chunk(
        &cipher,
        header.as_bytes(),
        &header.nonce_prefix,
        index,
        is_final,
        ciphertext,
    )
}

// ---------------------------------------------------------------------------------------
// Deterministic, caller-controlled constructors — VECTORS ONLY.
//
// These bypass the "no caller nonces" production rule so the committed conformance
// vectors are byte-exact and reproducible. They are compiled only under `test` or the
// `vectors` feature and must never be reachable from a production build.
// ---------------------------------------------------------------------------------------

/// Test-only helpers exposed under `#[cfg(any(test, feature = "vectors"))]`.
#[cfg(any(test, feature = "vectors"))]
impl StreamEncryptor {
    /// Deterministic constructor with a fixed `nonce_prefix` and chunk size.
    ///
    /// Small `chunk_size_log2` values make cheap multi-chunk streams for structural tests.
    /// Golden digest vectors, however, MUST use [`DEFAULT_CHUNK_SIZE_LOG2`] to match the
    /// real wire format.
    pub fn with_fixed(
        dek: &[u8; DEK_LEN],
        plaintext_len: u64,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        chunk_size_log2: u8,
    ) -> Self {
        Self::build(dek, plaintext_len, 0, 1, nonce_prefix, chunk_size_log2)
    }

    /// Deterministic constructor for one PART of a multi-part file. VECTORS ONLY.
    #[cfg(any(test, feature = "vectors"))]
    pub fn new_part_with_nonce_prefix(
        dek: &[u8; DEK_LEN],
        plaintext_len: u64,
        part_index: u32,
        part_total: u32,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        chunk_size_log2: u8,
    ) -> Self {
        Self::build(
            dek,
            plaintext_len,
            part_index,
            part_total,
            nonce_prefix,
            chunk_size_log2,
        )
    }
}

/// Forges a stream whose final chunk is authenticated with the given `is_final` value,
/// for the negative "wrong `is_final`" conformance vector. VECTORS ONLY.
///
/// With `final_is_final = false`, a conforming [`StreamDecryptor`] must reject the stream,
/// because it recomputes `is_final = true` for the last chunk and authentication fails.
#[cfg(any(test, feature = "vectors"))]
pub fn forge_stream_with_final_flag(
    dek: &[u8; DEK_LEN],
    plaintext: &[u8],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size_log2: u8,
    final_is_final: bool,
) -> Vec<u8> {
    let header = build_header(
        dek,
        chunk_size_log2,
        0,
        1,
        plaintext.len() as u64,
        &nonce_prefix,
    );
    let parsed = Header::parse(&header).expect("valid header");
    let cipher = new_cipher(dek);
    let count = parsed.chunk_count();
    let chunk_size = parsed.chunk_size() as usize;
    let mut out = Vec::new();
    out.extend_from_slice(&header);
    for index in 0..count {
        let start = (index as usize) * chunk_size;
        let end = (start + chunk_size).min(plaintext.len());
        let piece = &plaintext[start..end];
        let is_final = if index + 1 == count {
            final_is_final
        } else {
            false
        };
        out.extend_from_slice(&seal_chunk(
            &cipher,
            &header,
            &nonce_prefix,
            index,
            is_final,
            piece,
        ));
    }
    out
}
