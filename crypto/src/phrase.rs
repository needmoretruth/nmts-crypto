//! The recovery phrase — the account code written as 15 BIP-39 words.
//!
//! # What it is
//! The SAME 20 bytes as the account code, spelled with a public word list instead of Crockford
//! symbols. 160 bits of entropy plus BIP-39's 5 checksum bits are exactly 15 words of 11 bits, so
//! there is one phrase per code and one code per phrase. Nothing derived from the code changes:
//! the Argon2id input is still the 20 bytes (NCF-1 §2), which is why this needed no format change.
//!
//! # Why 15 and only 15
//! 12 words carry 128 bits and cannot hold the key; 24 carry 256 and would need 96 bits the key
//! does not have — a different secret. A 12- or 24-word input is therefore refused with its own
//! error ([`PhraseError::WrongWordCount`]), because the likeliest reason for one is a wallet's
//! seed phrase pasted into the wrong box.
//!
//! # Word lists
//! The official BIP-39 English and Korean lists (bitcoin/bips), through the `bip39` crate. The two
//! lists share no word (Latin letters against Hangul), so the language is read from the input. The
//! crate stores Korean decomposed (NFKD); what a person types is composed (NFC). Both are
//! accepted, and what this module hands out is composed — the form a keyboard produces, so a
//! phrase copied out and typed back compares equal.
//!
//! # Why Hangul is (de)composed here and not by a Unicode library
//! A general normalizer brings tables that doubled the size of the browser engine. The Korean list
//! is Hangul syllables only, and a Hangul syllable's decomposition is fixed arithmetic in the
//! Unicode Standard (§3.12, "Conjoining Jamo Behavior") — no tables. The English list is ASCII.
//!
//! # Why `AccountCode::parse` is untouched
//! Its contract is frozen (codes.rs). Entry points that should take either form call
//! [`parse_key_or_phrase`] instead; the code path underneath is the same function as before.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::codes::{AccountCode, CodeError, ACCOUNT_CODE_BYTES};

/// Number of words in an NMTS recovery phrase (160-bit entropy under BIP-39).
pub const PHRASE_WORDS: usize = 15;

/// A phrase needs at least this many word-like pieces before it is read as a phrase at all. Below
/// it the input is an account code (spaced in groups it has at most 9 pieces).
const MIN_PHRASE_PIECES: usize = 12;

/// The word lists a phrase can be written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseLanguage {
    /// The BIP-39 English list.
    English,
    /// The BIP-39 Korean list.
    Korean,
}

impl PhraseLanguage {
    fn list(self) -> Language {
        match self {
            PhraseLanguage::English => Language::English,
            PhraseLanguage::Korean => Language::Korean,
        }
    }

    /// Reads the short tag used across the WASM boundary and the CLI (`en` · `ko`).
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "en" => Some(PhraseLanguage::English),
            "ko" => Some(PhraseLanguage::Korean),
            _ => None,
        }
    }
}

/// Why an input that was read as a phrase did not become an account code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PhraseError {
    /// The phrase does not have 15 words.
    #[error("phrase:count:{0}")]
    WrongWordCount(usize),
    /// Word number `.0` (1-based) is in neither list, or not in the list the rest are in.
    #[error("phrase:word:{0}")]
    UnknownWord(usize),
    /// Every word is in the list but the checksum fails — a wrong word or a wrong order.
    #[error("phrase:checksum")]
    BadChecksum,
    /// The input was an account code, and that code did not parse.
    #[error(transparent)]
    Code(#[from] CodeError),
}

impl AccountCode {
    /// The recovery phrase for this code: 15 words, single-spaced, NFC.
    pub fn to_phrase(&self, language: PhraseLanguage) -> String {
        let mnemonic = Mnemonic::from_entropy_in(language.list(), self.as_bytes())
            .expect("20 bytes is a valid BIP-39 entropy length");
        let mut out = String::new();
        for (i, word) in mnemonic.words().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&compose_hangul(word));
        }
        out
    }
}

// Unicode Standard §3.12 — the Hangul syllable block is every (L, V, T?) jamo triple in order.
const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = 19 * N_COUNT;

/// Composed Hangul syllables → conjoining jamo (what the list stores). Anything else is kept.
fn decompose_hangul(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        let cp = c as u32;
        if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
            let i = cp - S_BASE;
            for part in [L_BASE + i / N_COUNT, V_BASE + (i % N_COUNT) / T_COUNT] {
                out.push(char::from_u32(part).expect("jamo"));
            }
            if !i.is_multiple_of(T_COUNT) {
                out.push(char::from_u32(T_BASE + i % T_COUNT).expect("jamo"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Conjoining jamo → composed syllables (what a keyboard types). Anything else is kept.
fn compose_hangul(s: &str) -> String {
    let mut out: Vec<char> = Vec::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if let Some(&last) = out.last() {
            let lp = last as u32;
            let l = lp.wrapping_sub(L_BASE);
            let v = cp.wrapping_sub(V_BASE);
            if l < 19 && v < V_COUNT {
                *out.last_mut().expect("last") =
                    char::from_u32(S_BASE + (l * V_COUNT + v) * T_COUNT).expect("syllable");
                continue;
            }
            let si = lp.wrapping_sub(S_BASE);
            let t = cp.wrapping_sub(T_BASE);
            if si < S_COUNT && si.is_multiple_of(T_COUNT) && t > 0 && t < T_COUNT {
                *out.last_mut().expect("last") = char::from_u32(lp + t).expect("syllable");
                continue;
            }
        }
        out.push(c);
    }
    out.into_iter().collect()
}

/// The word-like pieces of an input, with list numbers (`1.` `2)` `3`) dropped so a phrase copied
/// from a numbered list still reads. English is lowercased; Hangul has no case.
///
/// A piece with no letter in it is a list number (`1.` `2)` `11–15`), never a word — every word in
/// both lists is made of letters — so it is dropped.
fn pieces(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .filter(|p| p.chars().any(char::is_alphabetic))
        .map(|p| expand_english_prefix(decompose_hangul(&p.to_lowercase())))
        .collect()
}

/// An English word written with only its first letters (four or more) — the BIP-39 English list
/// is built so that the first four letters name one word, which is what lets a faded sheet of paper
/// still be read. A piece that is already a word, or that starts no word or several, is left as it
/// is and the list lookup below reports it.
fn expand_english_prefix(piece: String) -> String {
    let list = Language::English.word_list();
    if piece.len() < 4
        || !piece.bytes().all(|b| b.is_ascii_lowercase())
        || list.contains(&piece.as_str())
    {
        return piece;
    }
    let mut found = list
        .iter()
        .filter(|w| w.as_bytes().starts_with(piece.as_bytes()));
    match (found.next(), found.next()) {
        (Some(word), None) => (*word).to_string(),
        _ => piece,
    }
}

/// Whether an input will be read as a phrase: at least 12 pieces, each at least two characters.
/// An account code never qualifies — typed in groups it has at most 9 pieces, and typed one
/// symbol at a time its pieces are single characters.
pub fn looks_like_phrase(input: &str) -> bool {
    let p = pieces(input);
    p.len() >= MIN_PHRASE_PIECES && p.iter().all(|w| w.chars().count() >= 2)
}

/// Parses either an account code or a recovery phrase into the account code.
pub fn parse_key_or_phrase(input: &str) -> Result<AccountCode, PhraseError> {
    if !looks_like_phrase(input) {
        return Ok(AccountCode::parse(input)?);
    }
    let words = pieces(input);
    if words.len() != PHRASE_WORDS {
        return Err(PhraseError::WrongWordCount(words.len()));
    }
    let joined = Zeroizing::new(words.join(" "));
    let mnemonic = Mnemonic::parse_normalized(joined.as_str()).map_err(|e| match e {
        bip39::Error::UnknownWord(i) => PhraseError::UnknownWord(i + 1),
        bip39::Error::BadWordCount(n) => PhraseError::WrongWordCount(n),
        // Mixed lists: the crate reports the first word it could not place.
        bip39::Error::AmbiguousLanguages(_) => PhraseError::UnknownWord(1),
        _ => PhraseError::BadChecksum,
    })?;
    let (entropy, len) = mnemonic.to_entropy_array();
    if len != ACCOUNT_CODE_BYTES {
        return Err(PhraseError::WrongWordCount(mnemonic.word_count()));
    }
    let mut bytes = Zeroizing::new([0u8; ACCOUNT_CODE_BYTES]);
    bytes.copy_from_slice(&entropy[..ACCOUNT_CODE_BYTES]);
    Ok(AccountCode::from_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(seed: u8) -> AccountCode {
        AccountCode::from_bytes(core::array::from_fn(|i| {
            seed.wrapping_mul(31).wrapping_add(i as u8)
        }))
    }

    #[test]
    fn a_phrase_round_trips_in_both_lists() {
        for seed in 0..=255u8 {
            let c = code(seed);
            for lang in [PhraseLanguage::English, PhraseLanguage::Korean] {
                let phrase = c.to_phrase(lang);
                assert_eq!(phrase.split(' ').count(), PHRASE_WORDS);
                assert_eq!(parse_key_or_phrase(&phrase).unwrap(), c);
            }
        }
    }

    #[test]
    fn the_code_itself_still_parses_in_every_spacing() {
        let c = code(7);
        let display = c.display();
        assert_eq!(parse_key_or_phrase(&display).unwrap(), c);
        assert_eq!(parse_key_or_phrase(&display.replace('-', " ")).unwrap(), c);
        let spaced: String = c.canonical().chars().map(|ch| format!("{ch} ")).collect();
        assert!(!looks_like_phrase(&spaced));
        assert_eq!(parse_key_or_phrase(&spaced).unwrap(), c);
    }

    #[test]
    fn a_numbered_capitalised_phrase_still_reads() {
        let c = code(9);
        let numbered: String = c
            .to_phrase(PhraseLanguage::English)
            .split(' ')
            .enumerate()
            .map(|(i, w)| format!("{}. {} ", i + 1, w.to_uppercase()))
            .collect();
        assert_eq!(parse_key_or_phrase(&numbered).unwrap(), c);
        // The recovery kit's layout: five words to a line under a range, in either list.
        for lang in [PhraseLanguage::English, PhraseLanguage::Korean] {
            let words: Vec<String> = c.to_phrase(lang).split(' ').map(str::to_owned).collect();
            let kit: String = words
                .chunks(5)
                .enumerate()
                .map(|(i, five)| {
                    format!("      {}–{}   {}\n", i * 5 + 1, i * 5 + 5, five.join(" "))
                })
                .collect();
            assert_eq!(parse_key_or_phrase(&kit).unwrap(), c);
        }
    }

    #[test]
    fn english_words_read_from_their_first_four_letters() {
        let c = code(13);
        let short: Vec<String> = c
            .to_phrase(PhraseLanguage::English)
            .split(' ')
            .map(|w| w.chars().take(4).collect())
            .collect();
        assert_eq!(parse_key_or_phrase(&short.join(" ")).unwrap(), c);
        assert_eq!(expand_english_prefix("abanxyz".to_string()), "abanxyz");
    }

    #[test]
    fn a_decomposed_korean_phrase_reads_like_a_composed_one() {
        let c = code(11);
        let nfkd = decompose_hangul(&c.to_phrase(PhraseLanguage::Korean));
        assert_eq!(parse_key_or_phrase(&nfkd).unwrap(), c);
    }

    #[test]
    fn every_korean_word_composes_to_syllables_and_back() {
        for word in Language::Korean.word_list() {
            let composed = compose_hangul(word);
            assert!(composed
                .chars()
                .all(|c| (S_BASE..S_BASE + S_COUNT).contains(&(c as u32))));
            assert_eq!(decompose_hangul(&composed), *word);
        }
    }

    #[test]
    fn a_wallet_seed_phrase_is_refused_by_its_length() {
        let twelve = "abandon ".repeat(11) + "about";
        assert_eq!(
            parse_key_or_phrase(&twelve),
            Err(PhraseError::WrongWordCount(12))
        );
        let twenty_four = "abandon ".repeat(23) + "art";
        assert_eq!(
            parse_key_or_phrase(&twenty_four),
            Err(PhraseError::WrongWordCount(24))
        );
    }

    #[test]
    fn a_wrong_word_and_a_wrong_order_are_told_apart() {
        let phrase = code(3).to_phrase(PhraseLanguage::English);
        let mut words: Vec<&str> = phrase.split(' ').collect();
        let mut unknown = words.clone();
        unknown[4] = "nmtsword";
        assert_eq!(
            parse_key_or_phrase(&unknown.join(" ")),
            Err(PhraseError::UnknownWord(5))
        );
        words.swap(0, 1);
        if words[0] != words[1] {
            assert_eq!(
                parse_key_or_phrase(&words.join(" ")),
                Err(PhraseError::BadChecksum)
            );
        }
    }

    #[test]
    fn mixing_the_two_lists_is_refused() {
        let c = code(5);
        let en: Vec<String> = c
            .to_phrase(PhraseLanguage::English)
            .split(' ')
            .map(String::from)
            .collect();
        let ko: Vec<String> = c
            .to_phrase(PhraseLanguage::Korean)
            .split(' ')
            .map(String::from)
            .collect();
        let mixed: Vec<String> = en[..7].iter().chain(ko[7..].iter()).cloned().collect();
        assert!(matches!(
            parse_key_or_phrase(&mixed.join(" ")),
            Err(PhraseError::UnknownWord(_))
        ));
    }
}
