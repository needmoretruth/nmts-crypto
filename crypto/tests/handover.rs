//! The handover file (NCF-3 §5.6) — a share envelope that travels in a file instead of a server row.
//!
//! Nothing new is constructed here: the envelope is `share::wrap_dek_for` bit for bit, the name and
//! the digest are the §5.4 re-seals, and the only new label is the parts list's AAD. What these
//! tests pin is that the pieces still hold together when the recipient takes EVERY value from the
//! file — including the sender's identity, which the built-in share fetches from the server:
//!
//! 1. the file made for B opens for B, and yields the same DEK, name and parts list;
//! 2. it does not open for anybody else;
//! 3. a file whose `sender` field was swapped for another identity is refused by the address check,
//!    before any key agreement runs;
//! 4. an `item` spelled differently (upper case) is refused, because the item id is bound into the
//!    wrapping key byte for byte (§5.3);
//! 5. the parts list and the name, both under the same DEK, cannot stand in for each other.

use nmts_crypto::share::{self, SharePayload, SharePublicKey};
use nmts_crypto::wrap::{self, AAD_HANDOVER_PARTS};
use nmts_crypto::ShareError;

const AAD_SHARE_NAME: &[u8] = b"nmts/v3/share-name";
const AAD_SHARE_CONTENT_HASH: &[u8] = b"nmts/v3/share-content-hash";

const ITEM: &str = "3f2b1a90-0000-4000-8000-000000000001";
const NAME_DOC: &[u8] = br#"{"f":"nmts-share-file/1","name":"contract.pdf","size":1234}"#;
const PARTS_DOC: &[u8] =
    br#"{"f":"nmts-handover-parts/1","parts":[{"i":0,"blob":"blob-a","patch":null,"len":1322,"exp":42}]}"#;

/// One account's share secrets, fixed so a failure is reproducible.
struct Account {
    kem: [u8; 32],
    auth: [u8; 32],
    sig: [u8; 32],
}

impl Account {
    fn new(seed: u8) -> Self {
        Self {
            kem: [seed; 32],
            auth: [seed.wrapping_add(1); 32],
            sig: [seed.wrapping_add(2); 32],
        }
    }
    fn identity(&self) -> SharePublicKey {
        share::public_key(&self.kem, &self.auth, &self.sig)
    }
}

/// What a handover file carries, as bytes — the JSON around them is the web's and the CLI's job.
struct Handover {
    item: String,
    sender: Vec<u8>,
    envelope: Vec<u8>,
    name: Vec<u8>,
    hash: Vec<u8>,
    parts: Vec<u8>,
}

/// Build a handover exactly as the sender does: re-seal name and digest, wrap, then seal the parts.
fn make(sender: &Account, recipient: &SharePublicKey, dek: &[u8; 32]) -> Handover {
    let name = wrap::seal(dek, AAD_SHARE_NAME, NAME_DOC);
    let hash = wrap::seal(dek, AAD_SHARE_CONTENT_HASH, &[7u8; 32]);
    let payload = SharePayload {
        item_id: ITEM.as_bytes(),
        name_ct: &name,
        content_hash_ct: &hash,
    };
    let envelope = share::wrap_dek_for(
        &sender.auth,
        &sender.sig,
        recipient,
        &recipient.address(),
        dek,
        &payload,
    )
    .expect("wrap for a verified recipient");
    let parts = wrap::seal(dek, AAD_HANDOVER_PARTS, PARTS_DOC);
    Handover {
        item: ITEM.to_owned(),
        sender: sender.identity().to_bytes().to_vec(),
        envelope,
        name,
        hash,
        parts,
    }
}

/// Open a handover exactly as the recipient does, taking every value from the file.
fn open(me: &Account, file: &Handover) -> Result<[u8; 32], ShareError> {
    let sender = SharePublicKey::from_bytes(&file.sender)?;
    // The file names its sender twice — the identity and the envelope's first 16 bytes — and the
    // two must agree before anything else is looked at.
    share::verify_address(&sender, &share::claimed_sender(&file.envelope)?)?;
    let payload = SharePayload {
        item_id: file.item.as_bytes(),
        name_ct: &file.name,
        content_hash_ct: &file.hash,
    };
    let dek = share::unwrap_dek(
        &me.kem,
        &me.auth,
        &me.sig,
        &sender,
        &file.envelope,
        &payload,
    )?;
    Ok(*dek)
}

#[test]
fn a_handover_opens_for_its_recipient_with_the_same_key_name_and_parts() {
    let (a, b) = (Account::new(11), Account::new(22));
    let dek = *wrap::generate_dek();
    let file = make(&a, &b.identity(), &dek);

    assert_eq!(file.envelope.len(), share::SHARE_ENVELOPE_LEN);
    assert_eq!(file.sender.len(), share::SHARE_PUBLIC_LEN);
    assert_eq!(&file.envelope[..16], a.identity().address().as_bytes());

    let opened = open(&b, &file).expect("the recipient opens it");
    assert_eq!(opened, dek);
    assert_eq!(
        wrap::open(&opened, AAD_SHARE_NAME, &file.name).unwrap(),
        NAME_DOC
    );
    assert_eq!(
        wrap::open(&opened, AAD_HANDOVER_PARTS, &file.parts).unwrap(),
        PARTS_DOC
    );
}

#[test]
fn a_handover_does_not_open_for_anybody_else() {
    let (a, b, c) = (Account::new(11), Account::new(22), Account::new(33));
    let file = make(&a, &b.identity(), &wrap::generate_dek());
    assert_eq!(open(&c, &file), Err(ShareError::Auth));
    // Not even for the sender, who made it.
    assert_eq!(open(&a, &file), Err(ShareError::Auth));
}

#[test]
fn a_handover_whose_sender_field_was_swapped_is_refused_by_the_address_check() {
    let (a, b, c) = (Account::new(11), Account::new(22), Account::new(33));
    let mut file = make(&a, &b.identity(), &wrap::generate_dek());
    file.sender = c.identity().to_bytes().to_vec();

    let claimed = share::claimed_sender(&file.envelope).unwrap();
    assert_eq!(
        share::verify_address(&c.identity(), &claimed),
        Err(ShareError::AddressMismatch)
    );
    assert_eq!(open(&b, &file), Err(ShareError::AddressMismatch));
}

#[test]
fn a_handover_whose_item_was_upper_cased_is_refused() {
    let (a, b) = (Account::new(11), Account::new(22));
    let mut file = make(&a, &b.identity(), &wrap::generate_dek());
    file.item = file.item.to_ascii_uppercase();
    assert_ne!(
        file.item, ITEM,
        "the test must actually change the spelling"
    );
    assert_eq!(open(&b, &file), Err(ShareError::Auth));
}

#[test]
fn the_parts_list_and_the_name_cannot_stand_in_for_each_other() {
    let dek = *wrap::generate_dek();
    let parts = wrap::seal(&dek, AAD_HANDOVER_PARTS, PARTS_DOC);
    let name = wrap::seal(&dek, AAD_SHARE_NAME, NAME_DOC);
    assert!(wrap::open(&dek, AAD_SHARE_NAME, &parts).is_err());
    assert!(wrap::open(&dek, AAD_HANDOVER_PARTS, &name).is_err());
    assert!(wrap::open(&dek, AAD_SHARE_CONTENT_HASH, &parts).is_err());
}
