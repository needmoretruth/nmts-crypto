//! The public link's two envelopes (NCF-3 §5.8), through the production entry points — no
//! `vectors` feature. Its own file because `tests/api.rs` is over the length ceiling
//! (`check:size`); the fixed-byte pins are `tests/vectors_links.rs`.

use nmts_crypto::{kdf, wrap};

#[test]
fn a_link_secret_opens_only_its_own_wrapped_dek() {
    let secret = wrap::generate_link_secret();
    let other = wrap::generate_link_secret();
    assert_ne!(*secret, *other, "each link draws its own secret");
    let dek = wrap::generate_dek();

    let wrapped = wrap::wrap_dek_for_link(&secret, &dek);
    assert_eq!(wrapped.len(), wrap::WRAPPED_DEK_LEN);
    assert_eq!(
        *wrap::unwrap_dek_from_link(&secret, &wrapped).unwrap(),
        *dek
    );
    assert_eq!(
        wrap::unwrap_dek_from_link(&other, &wrapped).map(|_| ()),
        Err(wrap::WrapError::Auth)
    );

    // The same key and DEK under the account-wrap role is not a link envelope…
    let account_role = wrap::wrap_dek(&secret, &dek);
    assert_eq!(
        wrap::unwrap_dek_from_link(&secret, &account_role).map(|_| ()),
        Err(wrap::WrapError::Auth)
    );
    // …and a link envelope is not an account-wrapped DEK.
    assert_eq!(
        wrap::unwrap_dek(&secret, &wrapped).map(|_| ()),
        Err(wrap::WrapError::Auth)
    );
}

#[test]
fn the_uploader_reopens_a_link_secret_and_nobody_else_does() {
    let keys = kdf::derive_from_bytes(&[0x44u8; 20]).unwrap();
    let stranger = kdf::derive_from_bytes(&[0x45u8; 20]).unwrap();
    let secret = wrap::generate_link_secret();

    let sealed = wrap::seal_link_secret(&keys.data_key, &secret);
    assert_eq!(sealed.len(), wrap::WRAPPED_DEK_LEN);
    assert_eq!(
        *wrap::open_link_secret(&keys.data_key, &sealed).unwrap(),
        *secret
    );
    assert_eq!(
        wrap::open_link_secret(&stranger.data_key, &sealed).map(|_| ()),
        Err(wrap::WrapError::Auth)
    );
    // Same key, same length, different role: a sealed secret is never a wrapped DEK.
    assert_eq!(
        wrap::unwrap_dek(&keys.data_key, &sealed).map(|_| ()),
        Err(wrap::WrapError::Auth)
    );
}
