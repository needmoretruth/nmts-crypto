# NMTS Crypto Format v3 (NCF-3) — the mainnet format

> ⛔ **Status: FROZEN — re-frozen at the mainnet cutover, 2026-08-02 UTC.** The
> production service now runs against Sui/Walrus MAINNET; from this moment the §1 derivation
> chain and the §5 share identity never change again — changing them destroys real users'
> wallets and orphans addresses already handed out. Any future format change is a NEW version
> (NCF-4): bump the version byte, re-run the §2 registry discipline, regenerate the conformance
> vectors, and carry the recovery path — additive only, never a mutation of NCF-3.
>
> (History: first adversarial review, 2026-07-29 — a five-lens panel, 15 findings, all acted
> on including sender authentication (§5.5) and the file-list parent link (§6.1); wire sizes
> finalised 2026-08-02, with the launch audit confirming the registry 28/28.)
>
> ⚠ **The wire sizes in §5 changed again on 2026-08-02** — a published identity is now
> **4989 bytes**: it gained an ML-DSA-44 verification key and a deterministic self-signature over
> the key bundle, so that keys can still be added or replaced after the freeze while the published
> address stays immutable (§5.2a). A share envelope is still 1240 bytes. Anything quoting 1248 as
> the identity — or 1216/1224 — predates this revision.
>
> **A second adversarial review then attacked the wired share path and found A6** (§10.3): the envelope
> authenticated the DEK and the sender but not the FILE, so a colluding co-recipient and a server
> could swap the row beside a genuine envelope. Fixed in §5.3 by binding the row into the wrapping
> key — **no wire size changes**, the envelope is still 1240 bytes.
>
> **NCF-3 replaces NCF-1 and NCF-2 outright.** It is not additive. Every account, every stored
> object, and every share address produced under the old formats stops being readable, and that is
> deliberate — see §0.2.
>
> **It re-freezes at the mainnet cutover.** After that
> cutover the derivation chain in §1 and the share identity in §5 can never change again, because
> changing them destroys real users' wallets and orphans addresses they have already handed out.

---

## 0. Why this format exists

### 0.1 What was wrong

Seven defects, all found in stage E of the audit. Each one is unfixable after the mainnet cutover,
which is the only reason they are being fixed together and now. **A6 arrived after the others** —
the second adversarial review found it on 2026-07-29, once A1–A5 were already built.

| | Defect | Consequence |
|---|---|---|
| **A1** | The share **address** and the share **public key** are two independent derivations from the account code. A sender receives the recipient's public key **from the server** and has no way to check that it belongs to that address. | **The server is an undetectable man-in-the-middle for every person-to-person share.** It hands the sender its own public key, reads the DEK, re-wraps to the real recipient. Both screens look normal. The product's central claim — "the server cannot reach file keys" — is false on the sharing path. |
| **A2** | DEKs are wrapped to a recipient with **X25519** alone. | Walrus is a public network: ciphertext can be collected today and opened later by anyone with a large enough quantum computer ("harvest now, decrypt later"). Only *shared* files are exposed — an account's own files are protected by a symmetric key derived from its code — but shared files are exposed permanently, and the address that identifies the key cannot be rotated. |
| **A3** | The file-list version (`seq`) is a **server column**, not part of the sealed blob. | The server can serve an older `(seq, ciphertext)` pair. The client cannot tell. Deleted files reappear, recent uploads vanish, and a rename can be silently undone. |
| **A4** | A multi-part file's parts carry **no part number and no part count** in their headers. All parts of one file share one DEK. | The server can reorder parts, drop the tail, or replay an old part. Every chunk still authenticates, because each part's AAD covers only its own header. |
| **A5** | The AEAD is **not key-committing**. | One ciphertext can be constructed to decrypt to two different plaintexts under two different keys. Public links hand the DEK to the recipient, so "this ciphertext is that file" is a claim anyone can dispute. This matters for abuse reports and for any legal process that asks what a stored blob actually is. |
| **A6** | A share envelope authenticates the DEK, and since §5.5 the sender — and **nothing about which file that DEK belongs to**. The item id, the sealed name and the sealed content digest are server columns stored beside it. | A share wraps the file's **own** DEK, so every co-recipient of that file holds it. One of them, together with a server willing to rewrite a row, can leave the genuine envelope untouched and replace only the columns beside it with values sealed under that same DEK. The recipient then sees an attacker-chosen file attributed to a sender whose authentication **passed**, and the download's content-digest check passes too, because the digest was replaced in the same breath. |
| **N1** | The word **`manifest`** names three unrelated objects: the recovery list (`nmts/v1/recovery-manifest`), the sealed file list (`nmts/v2/manifest`), and the key that opens the file list (`nmts/v2/manifest-key`). | Not a vulnerability. It is the reason a reader has to hold three meanings at once, and domain-separator mistakes are exactly the class of bug that is invisible until it is catastrophic. |

### 0.2 Why nothing is migrated

There is no compatibility path and no reader for the old formats. Stored data is throwaway testnet
data (the database was measured before the cutover: nothing in it had to survive), and
the mainnet cutover invalidates it regardless.

The specific casualties, stated plainly rather than glossed:

* **Every existing account code stops working.** The Argon2id salt changes (§1.1), so the same code
  derives a different `accountId` and a different `authSecret`; the server has no row to match.
* **Every embedded wallet address changes**, and the balance at the old address is unreachable
  forever — no code path can produce the old seed again. Decided 2026-07-29: the testnet
  embedded wallets are abandoned rather than drained.
* **Every uploaded file becomes unopenable**, because `dataKey` changes.
* **Every share address already handed out becomes meaningless.**

⛔ **This paragraph expires at the mainnet cutover.** A later session must not read §0.2 as
permission to break accounts once real ones exist.

### 0.3 Naming

`NCF-3` is the whole format. The stream magic becomes `"NCF3"`, every domain separator carries
`nmts/v3/`, and `account.kdf_version = 3`. There is no mixed state: a build either speaks NCF-3 or
it does not.

---

## 1. Derivation chain

### 1.1 From account code to master

```text
master = Argon2id(pwd = code_bytes(20), salt = "NMTS-KDF-v3-salt",
                  m = 65536 KiB, t = 3, p = 1, out = 32)
```

**The account code is unchanged**: 160 random bits, machine-generated, displayed as 32 Crockford
symbols plus a check symbol. Nothing about the code's length, alphabet, or display form changes in
NCF-3 — changing what a person types is a product decision and no defect asks for it.

**The salt changes and only the salt changes: `NMTS-KDF-v1-salt` → `NMTS-KDF-v3-salt`.**
Be honest about what this buys: **nothing cryptographically.** A fixed salt is safe here because
the input is a 160-bit machine-generated secret — there is no dictionary to precompute and no user
to share a password with. The change is a *version boundary*: it guarantees that an NCF-1 account
and an NCF-3 account created from the same code have no value in common, so no old `authSecret`,
`accountId`, or wrapped key can ever be accepted by a v3 code path. `KdfVersion` already exists in
the crate with a single variant; this is what makes it mean something.

⛔ **The salt is NOT split per purpose.** An earlier audit note proposed one salt per derived key.
That is the wrong prescription: purpose separation is what HKDF's `info` is for, and one Argon2id
pass per purpose would multiply a 64 MiB memory-hard computation by the number of keys for no gain.
One Argon2id pass, many HKDF expansions.

**Argon2id parameters stay at m = 64 MiB, t = 3, p = 1.** Re-examined for NCF-3 (item Ⅰ-3) and
kept. Reasoning: the commonly cited OWASP minimum is m = 19 MiB / t = 2 / p = 1 and we are well
above it on the expensive axis; and against a
160-bit machine-generated input the KDF's cost is close to irrelevant anyway, because there is no
guessing attack for it to slow down. Raising it would cost seconds on a low-end phone and buy a
margin against an attack that cannot be mounted. `p = 1` is correct for a single-threaded WASM
build. The parameters live in the code as named constants and are covered by the test vectors.

### 1.2 From master to keys

One HKDF-Extract (empty salt, per RFC 5869), then one Expand per purpose:

```text
PRK          = HKDF-Extract(salt = "", ikm = master)

accountId    = HKDF-Expand(PRK, "nmts/v3/account-id",   16)   // public — server lookup key
authSecret   = HKDF-Expand(PRK, "nmts/v3/auth-secret",  32)   // sent to the server over TLS
dataKey      = HKDF-Expand(PRK, "nmts/v3/data-key",     32)   // never leaves the browser
fileListKey  = HKDF-Expand(PRK, "nmts/v3/file-list-key",32)   // opens the file list only  (N1)
shareKemSeed = HKDF-Expand(PRK, "nmts/v3/share-kem",    32)   // X-Wing decapsulation seed (§5.1)
shareAuthSk  = HKDF-Expand(PRK, "nmts/v3/share-auth",   32)   // sender-auth scalar        (§5.5)
walletRoot   = HKDF-Expand(PRK, "nmts/v3/wallet-root",  32)   // parent of every wallet
```

### 1.3 Wallets — one rule, no special case

```text
walletSeed(N) = HKDF-Expand(walletRoot, "nmts/v3/wallet/" || dec(N), 32)   // for every N ≥ 0
```

NCF-2 gave wallet 0 a frozen derivation straight off the account PRK (`nmts/v1/wallet-key`) and
derived wallets 1, 2, 3… from a separate root, because wallet 0 already existed and could not move.
NCF-3 has no such constraint, so the special case is deleted: **every wallet, including the first,
comes from `walletRoot` under the same rule.** Holding `walletRoot` grants wallets and nothing else
— never `authSecret`, never `dataKey`.

`dec(N)` is `N` in decimal ASCII with no padding, so wallet 10 is `nmts/v3/wallet/10`. There is no
`nmts/v3/wallet/010`.

### 1.4 The one derivation that does not start from an account code

```text
deviceWrapKey = HKDF-Expand(
                  HKDF-Extract(salt = "", ikm = Argon2id(pwd = passphrase,
                                                          salt = 16 random bytes per record,
                                                          m = 65536 KiB, t = 3, p = 1, out = 32)),
                  "nmts/v3/device-wrap", 32)
```

Unchanged from NCF-2 §7 apart from the label. This is the "remember this device" passphrase branch
Its salt is **random per record and never a constant** — the fixed-salt argument in §1.1
depends on the input being machine-generated, and a passphrase is exactly the case it excludes.
Minimum passphrase length is 8 bytes, enforced in the crate rather than only in the UI.

---

## 2. Domain separator registry

**Every string used as an HKDF `info`, an AEAD AAD, or a hash prefix appears here.** A separator not
in this table does not exist. `web/test/domain-separator-registry.test.ts` cross-checks the code
against this section; adding a separator without adding the row fails that test.

### 2.1 Key derivation (HKDF `info`)

| Label | Length | Purpose |
|---|---|---|
| `nmts/v3/account-id` | 16 | Public server lookup key |
| `nmts/v3/auth-secret` | 32 | Login proof, sent to the server |
| `nmts/v3/data-key` | 32 | Wraps DEKs; seals names, metadata, content hashes |
| `nmts/v3/file-list-key` | 32 | Opens the sealed file list, nothing else |
| `nmts/v3/share-kem` | 32 | X-Wing decapsulation-key seed (§5.1) |
| `nmts/v3/share-auth` | 32 | X25519 sender-authentication scalar (§5.5) |
| `nmts/v3/share-sig` | 32 | ML-DSA-44 signing-key seed ξ for the identity self-signature (§5.1, §5.2a) |
| `nmts/v3/wallet-root` | 32 | Parent of every wallet seed |
| `nmts/v3/wallet/<N>` | 32 | Wallet `N`, expanded from `walletRoot` (§1.3) |
| `nmts/v3/device-wrap` | 32 | "Remember this device" passphrase branch (§1.4) |
| `nmts/v3/share-wrap` | 32 | Wrapping key for one X-Wing encapsulation, bound to the sender, the recipient and the row (§5.3) |
| `nmts/v3/stream-commit` | 32 | Stream key commitment (§4.2) |
| `nmts/v3/envelope-commit` | 32 | Envelope key commitment (§3.2) |

### 2.2 Envelope AAD

| Label | Sealed under | Contents |
|---|---|---|
| `nmts/v3/dek-wrap` | `dataKey` | A file DEK |
| `nmts/v3/name` | `dataKey` | An item name (UTF-8) |
| `nmts/v3/meta` | `dataKey` | Folder-path metadata (JSON) |
| `nmts/v3/content-hash` | `dataKey` | SHA-256 of a whole file's plaintext |
| `nmts/v3/recovery-map` | `dataKey` | The recovery list (**N1**: was `recovery-manifest`) |
| `nmts/v3/file-list` | `fileListKey` | The sealed file list (**N1**: was `manifest`) |
| `nmts/v3/share-wrap` | X-Wing shared secret | A DEK wrapped to one recipient |
| `nmts/v3/share-name` | the file DEK | An item name re-sealed for a recipient |
| `nmts/v3/share-content-hash` | the file DEK | A content hash re-sealed for a recipient |
| `nmts/v3/device-label` | `dataKey` | A device's display name |
| `nmts/v3/device-record` | `deviceWrapKey` | The "remember this device" record |
| `nmts/v3/delegation` | `dataKey` | The standing auto-approve record |
| `nmts/v3/wallet-import` | `dataKey` | An imported (non-derived) wallet's private key |

### 2.3 Hash prefixes

| Label | Purpose |
|---|---|
| `nmts/v3/share-address` | Share address = fingerprint of the identity root (§5.2) |
| `nmts/v3/share-payload` | Commitment over the row a share envelope is stored beside (§5.3, **A6**) |
| `nmts/v3/identity-bundle` | FIPS 204 signature context (`ctx`) of the identity self-signature (§5.2a) |
| `nmts/v3/recovery-name` | The name the recovery manifest is stored under inside a quilt (§2.5) |

### 2.4 What N1 fixed

Three objects were called `manifest`. They are now named for what they are, and the ambiguity is
gone from the code as well as this table:

| Was | Is | What it actually is |
|---|---|---|
| `nmts/v1/recovery-manifest` | `nmts/v3/recovery-map` | The offline recovery list file |
| `nmts/v2/manifest` | `nmts/v3/file-list` | The sealed list of items in the drive |
| `nmts/v2/manifest-key` | `nmts/v3/file-list-key` | The key that opens that list |

### 2.5 The one public name derived from a key (added 2026-08-17)

```text
recovery_patch_name = uuid_form( SHA-256("nmts/v3/recovery-name" || dataKey)[0..16] )
```

**This is not a key and nothing is sealed with it.** It is a public label, and it is here for the
same reason `nmts/v3/share-address` is: a value computed from a secret, published in the clear,
and therefore subject to the same no-reuse rule as everything else in this registry.

**What it is for.** A blob id on Walrus is computed from the blob's own bytes, so nothing predicts
one from an account code. What *is* choosable is the identifier each patch carries inside a quilt.
Deriving that identifier from `dataKey` is what lets a tool holding only an account code compute
the exact name to ask a public aggregator for — the last piece of "recover with the account code
and nothing else". The address that owns the quilt comes from the same code by §1.3.

**Why derived rather than a fixed word.** A constant such as `nmts-recovery-list` would recover
identically and would also let anyone reading public storage pick NMTS accounts out of the crowd:
patch identifiers travel in the clear in a quilt's index. Derived, the name is unguessable to
everyone who does not already hold the key that opens what it points at.

**Why it is rendered as a v4 UUID.** Every other patch in the same quilt is identified by a random
UUID (the upload path's per-item client id). A differently shaped string beside them would mark
which patch is worth attention and undo the previous paragraph, so the fingerprint is rendered in
that same shape, version and variant bits included. The cost is six of the 128 bits; impersonating
a *specific* account's name still means finding a preimage of a 122-bit value.

⛔ **This did not move NCF-3 to a fourth version, and the judgement is recorded rather than
implied.** The frozen surface is the §1 derivation chain and the §5 share identity: no existing
key, envelope or address changes value, no reader of existing data behaves differently, and the
version byte means what it meant before. What was added is a new name for a new object — the case
§2 exists to arbitrate. A change that altered any derivation in §1 would still require NCF-4.

**Limit.** The name hides *which patch is the manifest*. It does not hide that the account exists:
the blob object holding the quilt is owned by the wallet that paid for it, and that wallet comes
from the same account code, so anyone who already knows an account's wallet address can see how
many quilts it holds and when.

---

## 3. Envelope

### 3.1 Format

```text
E(key, aad, plaintext) = nonce(24, random)
                       || commitment(32)
                       || XChaCha20Poly1305(key, nonce, plaintext, aad')   // ct || tag(16)

aad' = aad || commitment
```

A wrapped 32-byte DEK is therefore `24 + 32 + 32 + 16 = 104` bytes (NCF-2: 72).

The cipher is unchanged: **XChaCha20-Poly1305**, 24-byte random nonce, 16-byte tag. It was
re-examined for NCF-3 and there is nothing better to move to — a 24-byte random nonce makes reuse a
non-event (a 1 TiB file's chunk nonces collide with probability on the order of 10⁻³³), and AES-GCM
would trade that away for hardware acceleration we do not need.

### 3.2 Key commitment (fixes A5)

```text
commitment = HKDF(ikm = key, salt = nonce, info = "nmts/v3/envelope-commit" || aad, 32)
```

The reader recomputes it from its own key and compares in **constant time before decrypting**; a
mismatch is the same error as an authentication failure, because telling the two apart tells an
attacker which half of their guess was right.

Poly1305 is not key-committing: given two keys, an attacker can build one ciphertext that
authenticates under both and decrypts to two different plaintexts. The commitment removes that —
a ciphertext now names exactly one key, and because `aad` and `nonce` are part of the derivation it
also names exactly one role and one nonce (CMT-3 in the Bellare–Hoang framework).

**Why one uniform envelope rather than committing only where it matters.** The commitment is only
load-bearing where an outsider supplies the ciphertext: file streams (a public link hands out the
DEK) and share envelopes (the sender builds them). It buys nothing on, say, a name envelope the
same client sealed a moment earlier under its own `dataKey`. Two formats would be the cheaper
choice by bytes and the more expensive choice by everything else — every reader would need to know
which one it was holding, and "which envelopes commit?" is precisely the question nobody wants to
have to answer during an incident. **One format, always committing.**

**The cost, in numbers.** +32 bytes per envelope. The file list carries two envelopes per file
(the wrapped DEK and the sealed content hash), so a 10,000-file drive's sealed list grows by about
860 KB of base64 — against an 8 MiB ceiling, and a normal drive is nowhere near either figure.
Nothing a person can perceive.

**Alternative rejected: CTX** (Chan–Rogaway), which replaces the Poly1305 tag with
`SHA-256(K ‖ N ‖ A ‖ T)` and gives CMT-4. ⚠ **The first draft of this paragraph got the trade
wrong** and the first adversarial review caught it: CTX *truncated to 16 bytes* is not "the same strength for half the
bytes" — committing security is bounded by half the output, so 16 bytes buys ≈2⁶⁴ and 32 bytes
buys ≈2¹²⁸. At the strength this format needs, CTX costs the same 32 bytes as what is built here.

With the size argument gone, the remaining difference is assembly risk, and it points the same
way: CTX requires driving the AEAD in detached-tag mode on both paths, so a mistake shows up as
*a working system with no commitment at all* rather than as a test failure. The HKDF commitment is
a separate value a test can assert on directly, and it is what the AWS Encryption SDK deploys for
the same purpose. **Decision: keep the HKDF commitment. ⛔ Do not "save 16 bytes" by truncating
either scheme — that halves the guarantee permanently.**

---

## 4. Stream

### 4.1 Header

```text
stream = header(72) || C0 || C1 || …

offset  size  field
 0       4    magic = "NCF3"
 4       1    version = 3
 5       1    chunk_size_log2 = 22            // 4 MiB
 6       2    reserved = 0
 8       4    part_index   (u32 LE)           // A4
12       4    part_total   (u32 LE)           // A4
16       8    plaintext_len (u64 LE)          // of THIS part
24      16    nonce_prefix (random)
40      32    key_commitment                  // A5, §4.2

chunk_size  = 1 << chunk_size_log2
chunk_count = max(1, ceil(plaintext_len / chunk_size))     // 0 bytes ⇒ 1 empty chunk
nonce_i(24) = nonce_prefix(16) || i (u64 LE)
aad_i(81)   = header(72) || i (u64 LE) || is_final(1: 0x01 iff i == chunk_count-1)
C_i         = XChaCha20Poly1305(DEK, nonce_i, plaintext_i, aad_i)          // ct || tag(16)
```

The header grows 32 → 72 bytes, once per part. On a 4 MiB part that is one ten-thousandth of the
part.

**`part_index` and `part_total` fix A4.** They are in the header, the header is in every chunk's
AAD, so a part decrypted in a position its header does not claim fails authentication instead of
producing the wrong bytes. A single-blob file is `part_index = 0, part_total = 1`.

**The reader's obligation is positional, not set-based.** ⚠ The first adversarial review found that the first implementation
checking only that every index appeared exactly once — which a **permutation satisfies**. All the
right parts in the wrong order would have passed, and every chunk would still have authenticated,
because each part is internally valid and nothing compared its declared index with the position it
was being used in. The rule is therefore stated as: for the sequence of parts the reader is about
to concatenate, `headers[i].part_index == i` for every `i`, `headers.len() == part_total`, and
every part agrees on `part_total`. **Sorting the parts by `part_index` before checking defeats the
check** — it must run on the order the server actually supplied.

Enforced in two places, both of which must exist because they answer different questions:

- `crypto/src/framing/header.rs::verify_part_set` — for a caller holding every header at once.
  Exposed to the browser as the WASM `verify_part_set`, which the conformance harness exercises.
- `web/src/lib/download/engine.ts` — for the streaming reader, which does **not** hold every header
  at once. It checks each part as it reaches it: the header must declare the position being written
  into and the same total as the set. This is the same rule stated incrementally, and it fails
  **before any byte of a misplaced part reaches the file** rather than after the whole download.
  A short set fails at part 0, whose header names the real total.

The upload side is `web/src/lib/upload/encrypt-part.ts`, where placement is an OPTIONAL input that
defaults to part 0 of 1 — because the overwhelmingly common case is a whole file in one blob, and
making every such caller write `0 of 1` is noise that gets copied wrongly.

⚠ **The default is safe rather than merely convenient, and that is the reason it is allowed.** A
multi-part upload that forgot to pass placement seals N parts each claiming to be the whole file,
and the reader refuses every one of them at position 0. The failure is loud, immediate, and on the
uploader's own next download — not a wrong file assembled quietly months later. A default that
failed the other way would not be acceptable here at any convenience.

`u32` rather than `u16` for both: a `u16` ceiling of 65,535 parts is a limit somebody would
eventually hit, and a format that has to be re-versioned to raise a counter is a format that was
sized wrong. Four bytes each, once per part.

### 4.2 Stream key commitment

```text
key_commitment = HKDF(ikm = DEK, salt = nonce_prefix,
                      info = "nmts/v3/stream-commit" || header[0..40], 32)
```

`header[0..40]` is every byte above the commitment field: magic, version, `chunk_size_log2`, the
reserved pair, both part counters, `plaintext_len`, and the nonce prefix.

⚠ **The first draft bound only the DEK and the nonce prefix, and the first adversarial review showed why that is not
enough.** The other fields are covered by every chunk's AEAD tag, so an edit is *eventually*
caught — but only after a reader has used them to decide how much memory to allocate and how many
chunks to expect. A rewritten `chunk_size_log2` turns a bounded streaming read into an unbounded
one before a single tag is checked. Folding the prefix in moves that refusal to the same
constant-time comparison that catches a wrong key.

Checked in constant time **before any chunk is decrypted — on every path**. `StreamDecryptor::new`
does it at construction, and the random-access `decrypt_chunk` does it per call: that review found the
ranged-read path skipping it entirely, which left A5 unfixed for previews, seeks, and partial
downloads while looking correct for anyone using the right key.

This is the defect (A5) that matters most in practice, because the public-link design deliberately
hands the DEK to the recipient: possession of the link *is* possession of the key. Without a
commitment, "this stored blob is that file" is arguable. With it, it is not.

### 4.3 What is unchanged

Anti-truncation and anti-reorder *within* a part were already correct and stay exactly as they
were: `plaintext_len` in the header and therefore in every AAD, `is_final` on the last chunk only,
the chunk index in both the nonce and the AAD, and a sequential decrypt that verifies the chunk
count, the final flag, the recovered length, and that nothing follows the final chunk.

---

## 5. Share identity

### 5.1 Keys

```text
shareKemSeed     = HKDF-Expand(PRK, "nmts/v3/share-kem",  32)      // §1.2
shareAuthSecret  = HKDF-Expand(PRK, "nmts/v3/share-auth", 32)      // §1.2, §5.5
shareSigSeed     = HKDF-Expand(PRK, "nmts/v3/share-sig",  32)      // added 2026-08-02
(sk_kem, pk_kem) = X-Wing.KeyGenDerand(shareKemSeed)
pk_auth          = X25519(shareAuthSecret)
(sk_sig, pk_sig) = ML-DSA-44.KeyGen_internal(shareSigSeed)         // FIPS 204 Algorithm 6, ξ = seed

pk_kem   = ML-KEM-768 encapsulation key(1184) || X25519 public key(32) = 1216 bytes
pk_auth  = X25519 public key                                           =   32 bytes
pk_sig   = ML-DSA-44 verification key                                  = 1312 bytes

offset  size   field
     0     1   identity_version = 0x01     ← OUTSIDE the fingerprint; fixed offset forever
     1     4   derivation_index (u32 BE)   ← reserved for multiple public codes; always 0 today
     5  1312   pk_sig
  1317     4   key_epoch (u32 BE)          ← reserved for key replacement; always 0 today
  1321  1216   pk_kem
  2537    32   pk_auth
  2569  2420   self_sig = ML-DSA-44.Sign_det(sk_sig, M = bytes[0..2569), ctx = "nmts/v3/identity-bundle")

root     = bytes[1..1317)  = derivation_index || pk_sig            = 1316 bytes — what §5.2 fingerprints
identity = bytes[0..4989)  = the whole table                       = 4989 bytes — published
secrets  = the three 32-byte seeds above; every half is re-expanded =   96 bytes
```

X-Wing expands `shareKemSeed` with SHAKE-256 into the ML-KEM seed and the X25519 scalar, ML-DSA-44
expands `shareSigSeed` the same way (its keygen is deterministic from ξ by definition), and all
three secrets come from the account code, so the whole share identity is reproducible on any device
from the code alone — **including the self-signature**, because only the deterministic FIPS 204
signing variant is ever used (§5.2a). **There is no share key to back up and none to lose** — the
property the rest of NMTS depends on, kept.

**`identity` is the unit the server publishes and a sender fetches.** The address in §5.2
fingerprints only the `root`; the self-signature in §5.2a binds everything else to that root. The
`identity_version` byte sits **in front of** the root at an offset that can never move, so a future
body layout can be introduced without touching the root or the address — that byte is what makes
the whole revision worth its bytes. A value quoting 1248 bytes as the published identity predates
this revision (2026-08-02); 1216 predates the sender authentication in §5.5.

### 5.2 Address = fingerprint of the root (fixes A1 · revised 2026-08-02)

```text
share_address = SHA-256("nmts/v3/share-address" || root)[0..16]      // root = 1316 B, §5.1
```

**The address is no longer derived from the account code.** It is a fingerprint of the identity
**root** — the derivation index and the ML-DSA-44 verification key — so a sender who is handed an
identity by the server checks two things before encrypting anything to it: the root hashes to the
address they were given out-of-band, and the self-signature over the rest of the bundle verifies
under the key that root pins (§5.2a). If the server substitutes any key, one of the two checks
fails. The server cannot lie about which keys belong to an address, so the man-in-the-middle
position closes.

**Until 2026-08-02 the fingerprint covered the whole published bundle.** That made the bundle as
immutable as the address, and closed for good the door NCF-2 had paid server trust to keep open:
no key could ever be added or replaced. The 2026-08-02 revision re-bought that option deliberately and paid for it
with a signature instead of with trust: the address pins one permanent, lattice-based anchor, and
every other key is bound to that anchor by the self-signature rather than by the fingerprint.
NCF-2's price for agility was believing the server's key table; this revision's price is 3,741
bytes, once per account.

**The server enforces the same equation.** `PUT /v1/account/share-identity` recomputes
`SHA-256("nmts/v3/share-address" ‖ root)[0..16]` — and **verifies the self-signature as well**: the
column is first-writer-wins, so an unverifiable bundle would otherwise be stored permanently and
every client would refuse it forever, with no way to repair the address. This is not
redundant with the sender's check, and the review was right to insist on it: the sender's check protects
*confidentiality*, but only the server can stop **address squatting**. The address column is unique
and first-writer-wins, so without this an attacker could publish (their own key, a victim's
address) — learning nothing, but permanently killing an address the victim's account code is the
only thing that can derive, on a value the design says is immutable.

**Length stays 16 bytes** and the display form is unchanged — 27 Crockford symbols in three groups
of nine, the last carrying the check symbol, visibly different from an account code's eight groups
of four. Truncating to 128 bits costs nothing that matters here: impersonating a *specific*
address means finding a preimage (2¹²⁸), not a collision. A birthday attack produces two addresses
that collide with each other, which buys an attacker nothing, because the address they must match
is fixed by their target's account code.

**Alternatives rejected.** ① Publishing address → key on chain, first-writer-wins: costs gas per
account and puts a wallet in the way of receiving a share. ② Users comparing fingerprints out of
band: real defence, but it is advice, not a mechanism, and it cannot be the only one.

### 5.2a The self-signature (new 2026-08-02)

```text
self_sig = ML-DSA-44.Sign_det(sk_sig, M = identity bytes [0..2569), ctx = "nmts/v3/identity-bundle")
```

**What it covers**: everything published except itself — the version byte, the root, `key_epoch`,
`pk_kem`, `pk_auth`. It cannot cover its own 2,420 bytes and does not need to: altering the
signature breaks verification, the verification key sits inside the root, and the root is pinned by
the address. ⛔ **It is the only signature this format ever makes. Envelopes, files and messages
are never signed** — §5.5 chose deniable origin proof on purpose, and a signature over a *public
key bundle* proves only a public fact, so it creates no transferable receipt.

⛔ **Only the deterministic FIPS 204 variant is used** (`rnd = 0³²`, Algorithm 2's deterministic
mode). This is a constraint, not a preference: a hedged signature would give the same account
different identity bytes on every device, which would (a) make the server's first-writer 409 refuse
the account's own second device, (b) make the account screen's server-comparison report a false
mismatch, and (c) make the conformance vectors unpinnable.

**Verification order, binding on every reader** (client before encrypting to an identity, server
before storing one):

1. Exact length for the version it claims (v1 = 4,989 bytes).
2. `identity_version` is known — an unknown version is **refused**, never parsed by an older rule.
3. `SHA-256("nmts/v3/share-address" ‖ root)[0..16]` equals the address the identity was fetched by.
4. `self_sig` verifies under `pk_sig` with `ctx = "nmts/v3/identity-bundle"`.
5. The ML-KEM half decodes; neither X25519 half is a low-order encoding (§5.3).
6. Only then may `pk_kem` and `pk_auth` be used.

**What this buys, precisely.** The root — index and verification key — is immutable forever; that
anchor is lattice-based on purpose, so it survives the adversary that breaks the classical keys.
Everything else can now change under a frozen format and an unchanged address: replacing `pk_kem`
or `pk_auth` is a `key_epoch` bump re-signed by the same root (value agility), and a future body
layout — a new key *type*, §17-style derived identities — is a new `identity_version` under the
same root (structural agility). ⚠ **Neither procedure is implemented today**: `key_epoch` and
`derivation_index` are always 0, the server stores one bundle per account, and a replacement flow
must be specified before any non-zero value is ever published. The reserved label family
`nmts/v3/share-id/<N>` (per-index sub-roots, shaped like `nmts/v3/wallet/<N>`) is named here so a
future revision does not improvise it — it is deliberately **not** in the §2 table, because the
registry test refuses phantom labels and index 0 keeps today's three labels bit-for-bit.

⚠ **What it does not buy: freshness.** The signature proves a bundle is genuine, not that it is the
*latest* — a server can keep serving a stale signed bundle after a future epoch bump (same shape as
the §6.1 rollback). That limit is stated in §9 and its enforcement anchor is backlog, not format.

### 5.3 Wrapping a DEK to a recipient (fixes A2 and A6)

```text
(ct_kem, ss_kem) = X-Wing.Encapsulate(pk_kem_recipient)        // ct_kem = 1120 bytes
ss_auth          = X25519(sk_auth_sender, pk_auth_recipient)   // static-static, §5.5

payload_cmt = SHA-256("nmts/v3/share-payload"
                      || u32be(len(item_id))               || item_id
                      || u32be(len(name_share_ct))         || name_share_ct
                      || u32be(len(content_hash_share_ct)) || content_hash_share_ct)

wrap_key    = HKDF(ikm  = ss_kem || ss_auth, salt = "",
                   info = "nmts/v3/share-wrap" || sender_address || ct_kem
                                               || root_recipient || payload_cmt, 32)
sealed_dek  = E(wrap_key, "nmts/v3/share-wrap", DEK)           // §3 envelope, 104 bytes

share envelope = sender_address(16) || ct_kem(1120) || sealed_dek(104) = 1240 bytes   (NCF-2: 104)
```

`root_recipient` is the recipient's identity **root** — the 1,316 bytes the address fingerprints
(§5.2), not the full published bundle. (Until 2026-08-02 the full 1,248-byte identity stood here;
the root replaced it in the same revision that made the rest of the bundle replaceable, so that a
future `key_epoch` bump does not silently change every wrapping key.) Nothing is lost by the
narrowing: the *exact* KEM key is already bound through `ct_kem` in this same `info` and through
ML-KEM's own derivation, which mixes `H(ek)` into the shared secret; the *exact* auth key is bound
through `ss_auth` itself; and §5.2a has already verified both keys against the root before any wrap
is allowed to happen. `sender_address` is the 16 bytes the envelope carries, and `ss_auth` is what
makes them a fact rather than a label. **§5.5 is where both come from and why the proof of origin
is an agreement rather than a signature**; it is not restated here. The two secrets are
concatenated as HKDF input keying material and mixed by HKDF-Extract, not combined by hand.

X-Wing is X25519 and ML-KEM-768 combined by a fixed rule:
`ss = SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ "\.//^\")`. **Both must be broken to
recover the DEK**, so a quantum computer alone does not open the harvested ciphertext, and a flaw
found later in ML-KEM does not put us below where we are today.

⛔ **The combiner is not ours.** House rule: cryptography is never hand-written, and that rule
covers combining as much as it covers the primitives. X-Wing is used exactly as specified, with the
specification's own test vectors in our conformance set.

**Deviation from the original audit plan, recorded deliberately.** That plan called for a hybrid
combiner must take **both** ciphertexts and **both** public keys. X-Wing takes the X25519 halves
and the ML-KEM *shared secret*, not the ML-KEM ciphertext or encapsulation key. That rule is the
correct generic advice, and X-Wing departs from it on purpose: its security argument accounts for
ML-KEM-768 specifically, and its shared secret already binds the encapsulation key through the FIPS
203 derivation. Following the generic rule here would mean writing a *variant* of X-Wing, which is
the thing the house rule forbids and which would throw away the published test vectors.
**⚠ This was named as the single most important thing for the review to attack.** The hybrid-KEM lens ran
on 2026-07-29 and did not overturn it — none of the findings in §10.1 or §10.2 touch the combiner.
The recorded fallback stands unused: if a later review does reject the argument, the answer is a
standard generic combiner over both KEMs, **not** a modified X-Wing.

**Implementation: the `x-wing` crate (RustCrypto, Apache-2.0/MIT).** Same maintainers as the
`chacha20poly1305`, `hkdf`, `sha2`, and `x25519-dalek` we already depend on, and it exposes
deterministic key generation from a 32-byte seed as a first-class API, which §5.1 requires.

Its description says "draft 06", which raises the obvious question of whether a later draft moved
the wire format. **Measured, 2026-07-29:** the crate ships the draft's own published test vectors
and passes them (`cargo test --all-features` → `rfc_test_vectors ok`; 3 vectors, `pk` 1216 B,
`ct` 1120 B, `sk` 32 B — the sizes this section states). Reading it against the independent
draft-10 implementation (`rxwing`) shows the same label `\.//^\`, the same combiner input order,
and the same 96-byte SHAKE-256 seed expansion split 64/32. That is a source-level comparison plus a
vector check on one of the two, **not** a byte-for-byte run of both against a shared vector set —
`rxwing` does not make its derandomised entry points public, so it cannot be driven from outside.
The conformance vectors in §7 pin our bytes regardless of which implementation produced them.

**The row the envelope is stored beside is bound into the wrapping key (fixes A6).** Authenticating
the sender is not the same as authenticating **what they sent**, and until `payload_cmt` was added
the envelope did only the first. Its plaintext is a DEK and nothing else, so an envelope said "this
key came from Alice" and never "and it belongs to *that* file". The item id, the sealed name and the
sealed content digest sat in server columns beside it.

That gap is reachable rather than theoretical, because a share wraps the file's **own** DEK: every
co-recipient of that file holds it. One such recipient, together with a server willing to rewrite a
row, leaves Alice's genuine envelope untouched and replaces only the two sealed columns with values
they sealed under that same DEK. The victim's screen then shows an attacker-chosen file, attributed
to Alice with the sender check **passing**, and the download's content-digest check passes as well,
because the digest was replaced in the same breath.

Hashing the three fields into the HKDF `info` closes it: change any of them and the wrapping key
changes and the envelope stops opening. Both sides build `payload_cmt` from bytes they already hold
— the sender from what it is about to POST, the recipient from what the inbox returned.

⚠ **Every field is length-prefixed with a big-endian `u32`, and that is load-bearing, not
decoration.** A sealed name has no fixed length, so plain concatenation is ambiguous: `("ab","cd")`
and `("abc","d")` are the same bytes and would commit to the same value — which is precisely a way
to rewrite a name. A field whose length does not fit in a `u32` is refused rather than truncated,
because a truncated length prefix is a collision.

**`item_id` is the ASCII item id lowercased**, exactly as the API serialises it, and lowercasing is
the only normalisation performed. Both sides read the same identifier from the same server, so they
already agree; the fold exists so that a future difference in **case alone** cannot turn every share
into "could not be opened", a failure no screen could explain. **Any other difference is meant to
break the unwrap** — it means the two sides are not talking about the same file.

**`content_hash_share_ct` is mandatory for a share.** It was previously optional. A share without it
leaves the recipient unable to verify the body they downloaded, and leaves nothing binding that body
into the chain at all — which is exactly the share an attacker wants. It is therefore required in
the crate (`ShareError::EmptyPayloadField`) rather than in a screen that could forget it; an empty
item id or name is refused for the same reason.

**The order of operations changes.** The name and the content digest must be sealed **before** the
envelope is wrapped, because they are inputs to the wrapping key. Wrapping first and sealing
afterwards produces an envelope that will not open beside its own row.

**No byte on the wire changes.** The envelope is still 1240 bytes and carries no new field. The
binding is entirely in the derivation, and both sides recompute it from data they already have.

**One failure, not three.** A rewritten row is refused **identically** to a forged envelope and to
an envelope addressed to somebody else: each changes the wrapping key, and the only observable
result is that the §3 envelope does not open. There is deliberately no way for a caller to tell the
cases apart — a caller that could would be telling an attacker which half of their guess was right.

⚠ **Limits, stated rather than implied.** This authenticates the **contents of a row that is
shown**. It does not stop the server **deleting** a share, **replaying** an older share it kept, or
showing the *sender* a "shared with" list that is fiction. It authenticates a row, not the set of
rows.

**Other rules that survive from the plan and are binding here:**

* ⛔ **No algorithm-selection field in the envelope.** One format. A field you can flip is a
  downgrade.
* ⛔ **No fallback to the old wrapping on failure.** ML-KEM does not report failure; it returns a
  random-looking secret (implicit rejection). Code that reacts to "it did not open" by trying the
  classical path is a downgrade oracle.
* ⚠ **Public keys are validated on receipt**, before anything is encrypted to them — the full
  §5.2a order: known version, root-to-address fingerprint, self-signature, and then the halves:
  the ML-KEM half must decode, and neither X25519 half may be one of the low-order encodings. The
  low-order check is not decoration and it is not the KEM crate's job — `x25519-dalek` accepts
  every 32-byte string and its Diffie–Hellman is infallible, so a low-order point agrees to the
  all-zero shared secret with every private key. Inside X-Wing that does not expose the DEK
  (ML-KEM still carries it) but it **silently removes the classical half of the hybrid**, which is
  this section's entire promise. An account that published such a key would degrade every share
  ever sent to it, permanently, with nothing on any screen to say so — the address is a
  fingerprint of the root and addresses are immutable. ⚠ The review found this listed here and
  implemented nowhere; it is now enforced in `SharePublicKey::from_bytes` with a test.

**What it costs, honestly.** The registered public identity goes 32 → 1248 → **4989** bytes
(2026-08-02, §5.2a); the share envelope 104 → 1240 and **unchanged by the revision**; the browser's
crypto module gains ML-KEM, SHA-3 and now ML-DSA (measured ceiling ~29 KB more, shared SHAKE
already on board). The A6 binding adds nothing to either figure — one SHA-256 over three values the
caller is already holding. Against files measured in megabytes none of this is perceptible, and **a person who
never shares pays only the module size.** If the module measurably slows the first screen, it is
split out and loaded on the sharing path — **not** turned into a user-facing choice. Nobody is
asked to pick their own cryptography: the question is unanswerable, and the wrong answer would be
permanent because the address is immutable.

### 5.4 What travels with a shared file

The item name and the whole-file content hash are re-sealed under the **file DEK**
(`nmts/v3/share-name`, `nmts/v3/share-content-hash`), so the recipient can read them once they hold
the DEK, and the server — which stores them — cannot. That much is NCF-2 §2.3 unchanged.

Two things about them are new in NCF-3, both consequences of A6 (§5.3):

* **Both are sealed before the DEK is wrapped.** Their sealed bytes, with the item id, are hashed
  into the wrapping key, so a row is built in one order and only one: seal the name, seal the
  digest, then wrap the DEK beside them.
* **The content hash is no longer optional.** A share without it leaves the recipient unable to
  verify the body they downloaded, and leaves nothing binding that body to the envelope. An empty
  one is refused by the crate, not by a screen.

### 5.5 Sender authentication

An envelope proves who it was **for**. Until this section existed it proved nothing about who it
was **from**: X-Wing is an unauthenticated KEM, so anyone holding a recipient's public key — which
is public by construction — can build a valid envelope for them, and the "from" line in an inbox
was a **server-supplied column**. A hostile server, or an ordinary account with a squatted address,
could place a file in someone's inbox attributed to a contact they trust.

```text
shareAuthSecret  = HKDF-Expand(PRK, "nmts/v3/share-auth", 32)      // §1.2
pk_auth          = X25519(shareAuthSecret)
identity         = the 4989-byte bundle of §5.1 (pk_auth at bytes 2537..2569)
address          = SHA-256("nmts/v3/share-address" || root)[0..16]          // §5.2

ss_auth          = X25519(sk_auth_sender, pk_auth_recipient)       // static-static
wrap_key         = HKDF(ikm = ss_kem || ss_auth,
                        info = "nmts/v3/share-wrap" || sender_address
                                                    || ct_kem || root_recipient
                                                    || payload_cmt, 32)   // payload_cmt: §5.3

share envelope   = sender_address(16) || ct_kem(1120) || sealed_dek(104) = 1240 bytes
```

**The check is that it opens at all.** A wrong sender yields a different `ss_auth`, a different
wrapping key, and an envelope that does not decrypt. There is no separate "is the sender genuine?"
step, so no caller can use the DEK without having performed the check. The row binding of §5.3 is
the same single line: "it opened", "the claimed sender really sent it" and "these are the columns
they sent it with" are one fact, and no caller can take one of them without the others.

**The sender address in the envelope is bound into the wrapping key**, so it cannot be relabelled:
editing those 16 bytes changes the key and the envelope stops opening rather than opening under a
false name. It is there so a reader knows *whose* identity to fetch, and the fetched identity is
checked against it by fingerprint before anything else happens.

**Why static-static rather than a signature.** A signature would prove origin **to anyone,
forever** — a transferable receipt that account X sent file Y to account Z, generated by a product
whose design is about not producing such records. The static-static agreement gives the recipient
the same certainty while giving a third party nothing: the recipient could have computed the
identical value themselves, so a leaked envelope proves nothing about its author. Same construction
as HPKE's `mode_auth`. It also costs 16 bytes instead of ~1300. **The §5.2a self-signature does not
touch this**: it signs the public key bundle — a public fact — and never an envelope, so the
deniability of *what was sent, and to whom*, is intact.

**The self-signature binds BOTH working keys to the root.** Covering only the KEM key would let an
attacker swap the authentication half and impersonate every sender to that address while the
address stayed valid. (Until 2026-08-02 this binding came from the address fingerprinting the whole
bundle; the signature now carries it — §5.2a.)

⚠ **Two limits, stated rather than implied.**
1. **The authentication half is X25519 — classical only.** Confidentiality is hybrid and survives a
   quantum adversary; *origin* does not. This is a deliberate asymmetry: forging a sender requires
   the quantum machine **at the time of forging**, so there is no harvest-now-forge-later, whereas
   confidentiality genuinely is harvested today. Another 1.2 KB per envelope to close a gap with no
   retroactive component was not worth it. **What changed on 2026-08-02**: the identity now carries
   a lattice-based anchor (§5.2a), so a post-quantum origin mechanism can be *added later under the
   same address* if that judgement ever flips — before the revision this limit was permanent, now
   it is revisitable. Today's envelopes remain classical-origin on purpose.
2. **Verification needs the sender's published identity**, fetched by the address the envelope
   claims. A server that refuses to answer blocks the check — and the share then does not open,
   which is the safe direction.

---

## 6. File list

The format is NCF-2 §5 (NMF-1) with two changes. Everything else — one sealed blob per account, the
compression flag inside the sealed plaintext, exact times, optional fields omitted rather than
nulled, `w` and `h` carried verbatim — is unchanged.

### 6.1 The version number moves inside the seal (fixes A3)

```jsonc
{ "v": 1,
  "seq": 41,          // NEW — the version this blob was sealed AT
  "p": "<base64url>", // NEW — SHA-256 of the SEALED blob this one was built on (absent at seq 1)
  "items": [ … ] }
```

```text
body        = 0x00 || utf8(json)  |  0x01 || gzip(utf8(json))
file_list_ct = E(fileListKey, "nmts/v3/file-list", body)      // §3 envelope
```

`"p"` is the SHA-256 of the parent blob's **base64url transport string**, in base64url — not of the
bytes that string encodes. That is sound because the encoding is canonical (fixed alphabet, no
padding, one string per byte sequence), so committing to the string commits to the blob. ⛔ It also
means the column must travel **verbatim**: padding added or the alphabet swapped anywhere on the way
is a silent break that reports a rollback on a perfectly good drive. The value is pinned by
`web/test/manifest-codec.test.ts` — §7's vectors cover the crate, and this function is
TypeScript-only, so nothing else can pin it.

The server still keeps `seq` as a column — it has to, to serialise concurrent writes — but it is no
longer the only copy. On every read the client checks **both**:

1. the `seq` inside the opened blob equals the `seq` the server reported; and
2. that `seq` is **not lower than the highest this device has ever seen**, which the device stores
   **in its own record, separate from the cached blob** (`web/src/lib/drive/manifest-cache.ts`).
   ⚠ It was kept only in memory until 2026-08-01, which meant a cold start re-established it *only*
   as a side effect of the cached blob opening: every way of losing that blob — quota eviction, a
   blob that will not open — took the rollback defence with it silently. The record is a version
   number and a hash, it names no file, and it is versioned so that a change to how the fingerprint
   is computed cannot brick a returning device.

Either check failing is a rollback, reported as one. Without (2) the server could serve a
consistent old *pair* and the first check would pass.

3. and, when this device holds the version being claimed as the parent, `prev` must equal the
   SHA-256 of the exact sealed bytes it opened at that version.

Check (3) is the parent link, added after that review. Checks (1) and (2) both pass for a **fork** the
server grew from an older version, because a fork's numbers only go up too; and (2) is satisfied by
standing still, so a device that is merely *behind* could be pinned there indefinitely and two
devices could be shown two different histories. A list that does not continue the blob a device
actually read is not a newer version of it, and the link is what makes that difference visible.

A writer names the blob **it actually opened** as the parent — never one reconstructed from a
number — and refuses to save at all if it has not read the current version.

**Limit, stated plainly — and it is wider than "a brand new device"** (corrected 2026-08-01 after an
independent review; the earlier wording understated it). Check (3) can only run when this device
**holds the blob being claimed as the parent**, which means it runs on *consecutive* reads. A server
picks the gap: publish version N+2 while the device last opened N, and checks (1) and (2) still pass
while (3) is never reached. Refusing gaps is not available as an answer, because legitimate gaps are
ordinary — another device writing twice while this one was closed is byte-for-byte the same
situation. So what the parent link buys is precisely this: **a drive in active use cannot be forked
or rolled back without the next consecutive read seeing it**, and a device that skipped versions
records that continuity was *not* proved (`chainState().continuityChecked`) rather than implying it
was. Closing the gap needs an anchor the server does not control — the recovery list, or the chain —
and is recorded in our backlog rather than quietly left out.

### 6.2 Renamed key and AAD

`fileListKey` / `nmts/v3/file-list` replace `manifestKey` / `nmts/v2/manifest` (N1). No behavioural
change; the name now says which of the three former "manifests" it is.

---

## 7. Conformance vectors

The vectors are part of this specification, not an afterthought to it. `crypto/tests/vectors/`
gains, all with fixed inputs and committed expected bytes:

1. **Derivation** — one account code → `master`, `accountId`, `authSecret`, `dataKey`,
   `fileListKey`, `shareKemSeed`, `shareAuthSecret`, `shareSigSeed`, `walletRoot`, `walletSeed(0)`,
   `walletSeed(1)`, `walletSeed(10)`.
2. **Envelope** — a sealed DEK with a fixed nonce, including the commitment, and a negative case
   where the commitment is altered and opening must fail.
3. **Stream** — single-chunk, multi-chunk, and empty; plus a multi-part set proving that a header
   with a swapped `part_index` fails to authenticate.
4. **Share** — X-Wing's own published vectors, and a full wrap/unwrap from fixed identity seeds
   with fixed encapsulation randomness and a fixed envelope nonce (an envelope has two random
   inputs, and both must be pinned or the last 104 bytes are not reproducible). The `share` group
   pins the **row** as well as the envelope — `item_id_ascii`, `name_share_ct_hex`,
   `content_hash_share_ct_hex` and `payload_commitment_hex` (§5.3, A6) — so an implementation that
   builds the commitment differently fails on the commitment rather than on 1240 opaque bytes. The
   two sealed columns are opaque stand-ins of deliberately different lengths, because the length
   prefixes are what stop two rows hashing alike.
   `share_negative` holds **seven** cases, every one of which must refuse:
   `wrong_sender_identity`, `restamped_sender_address`, `swapped_name_ct`,
   `swapped_content_hash_ct`, `repointed_item_id`, and — since 2026-08-02 — `bad_self_signature`
   (one flipped bit in the self-signature refuses the whole identity) and
   `root_mismatched_address` (a genuine bundle fetched by an address its root does not hash to).
   The first is refused at the fingerprint check (`AddressMismatch`); the four row cases are
   refused at the envelope (`Auth`) and are deliberately indistinguishable from each other.
5. **Address** — `identity` → `share_address` → display form → parsed back. Since 2026-08-02 each
   vector also pins `root_hex` / `root_len: 1316` beside the full identity, so a mismatch is found
   at the root rather than inside a five-kilobyte blob.
6. **ML-DSA** — key generation is pinned by NIST ACVP known-answer vectors (seed → verification
   key), the same way and for the same reason §5.3 carries X-Wing's published vectors. The
   **signature** vectors are pinned differently, and honestly so: NIST's sigGen cases carry the
   2,560-byte *expanded* signing key, importable only through an API the crate deprecates as
   panic-prone, so our signature cases use a NIST seed with our own message and context and are
   pinned against an independent implementation (`fips204`, dev-dependency only — it ships in
   nothing). Deterministic signing makes that pin exact; the vector file says the same in its own
   comment.

Vectors are generated by the `vectors` cargo feature, which is the only thing in the crate that may
supply a nonce; production constructors never accept one.

---

## 8. What NCF-3 deliberately does not change

| | Why |
|---|---|
| **XChaCha20-Poly1305** for bulk data | Current best practice. Nothing to move to (§3.1) |
| **Argon2id → HKDF-SHA-256** | Current best practice; parameters re-measured and kept (§1.1) |
| **The account code's length and display form** | No defect asks for it; what a person types is a product decision |
| **4 MiB chunks** | Ranged reads and memory ceilings were sized around it; no defect touches it |
| **Server never holds a key** | The product's reason to exist |
| **Share addresses immutable once published** | Still true — the address pins the identity *root*. What changed 2026-08-02: the rest of the bundle is bound by the self-signature instead of the fingerprint, so it *can* be re-published under the same address once a replacement flow is specified (§5.2a) |
| **No file version history** | Decided 2026-07-26 — storage is paid from the user's wallet |

---

## 9. Limits — what this format still does not stop

Written here because a specification that lists only its defences is a marketing document.

* **The code the browser runs.** Everything in this document assumes the delivered JavaScript and
  WASM are what we published. A compromised delivery path defeats all of it. This is the honest
  root of trust for every in-browser E2EE product and NCF-3 does not change it.
* **Sender authentication is classical-only** (§5.5). Confidentiality survives a quantum
  adversary; proof of *origin* does not. Since 2026-08-02 this is a *revisitable* limit rather than
  a permanent one — the identity's lattice anchor (§5.2a) leaves room to add a post-quantum origin
  mechanism under the same address — but today's envelopes are still classical-origin.
* **Identity freshness** (§5.2a). The self-signature proves a bundle is genuine, not that it is the
  latest. Once a replacement flow exists, a server could keep serving a stale signed bundle — the
  same shape as the §6.1 rollback, with the same class of answer (an anchor the server does not
  control) recorded in our backlog, not quietly left out.
* **A timing side channel in the signature crate's keygen sampler.** The released `ml-dsa` 0.1.1
  still branches on secret-derived values in `coeff_from_half_byte` (the branch-free fix was merged
  upstream on 2026-06-24 but is in no released version — measured against the crates.io index,
  last on 2026-08-17). Our structure re-derives the same key from the same seed at every login,
  which is the repeat-measurement shape timing attacks want — but the code runs inside the user's
  own browser, where an observer with a timer that precise is already in the page. Accepted and
  recorded. ⭐ **This sentence cannot quietly rot**: since 2026-08-17 our deploy reads the crates.io
  index for this crate on every release and refuses to ship the day a released version appears,
  pointing at this paragraph. Until then it was a `curl` command in a backlog entry, which is to
  say nobody ran it.
* **Deletion, replay, and the sender's own view of a share** (§5.3). The row binding authenticates
  the contents of a share that is shown. A server can still withhold a share, serve an older one it
  kept, or show the *sender* a "shared with" list that is fiction. It authenticates a row, not the
  set of rows.

* **A file-list rollback across a gap in versions** (§6.1). The parent link is checked on
  consecutive reads; a server that skips a version number is never checked, and a device with no
  history at all has nothing to compare on first contact. Closing either needs an anchor the server
  does not control (the recovery list, or the chain) and is recorded in our backlog rather than
  quietly left out.
* **Availability.** A server that refuses to return a public key, or returns "no such address",
  blocks a share. NCF-3 closes lying, not refusing.
* **Traffic shape.** Sizes, times, and counts are still visible to the server and to Walrus. That is
  covered by the metadata-privacy work, not here.
* **The wallet's signatures.** Sui's Ed25519 is quantum-vulnerable and is not ours to change.
  Removing "X25519 is our only quantum exposure" from the audit plan's wording: it was not true.
* **The login secret in transit.** `authSecret` travels over TLS, so a recorded session opened later
  would hand over an account — and unlike A2 this touches **every account, not only the ones that
  share.** ✅ **MEASURED 2026-08-01, and the answer is good**: the edge negotiates
  **X25519MLKEM768** — a hybrid post-quantum key exchange — with a current Chromium against
  `https://nmts.me` (read from the browser's own security details over CDP, not from a vendor claim).
  ⚠ **The guarantee is PER CLIENT, not absolute.** A client that does not OFFER a hybrid group still
  gets classical X25519 and is harvestable; an OpenSSL 3.0.13 client on the same machine negotiated
  plain X25519 in the same test, because it cannot offer the hybrid at all. So this is not something
  the format fixes or can promise — it is a property of the browser the person happens to use.
* **A stolen unlocked device.** "Remember this device" stores a key the browser can read back
  (§1.4). Clearing it is forward-looking, not at-rest protection.

---

## 10. Adversarial review — outcome and what is still open

### 10.0 The first adversarial review (a five-lens panel)

A five-lens panel ran on 2026-07-29 (hybrid KEM · key commitment · share address · stream and
parts · derivation and registry), each lens followed by a skeptic told to refute its findings.
**15 findings survived refutation; 5 were killed.** The surviving ones are recorded where they
belong rather than in a list here — every fix above that names that review is one of them.

### 10.1 Fixed in this pass

| | What it was |
|---|---|
| **Part reordering** | `verify_part_set` accepted any permutation of the right parts, so A4 did not actually stop reordering (§4.1) |
| **Ranged reads uncommitted** | random-access `decrypt_chunk` never checked the key commitment, leaving A5 unfixed for previews and seeks (§4.2) |
| **Commitment too narrow** | the commitment bound only the DEK and nonce prefix, so a rewritten `chunk_size_log2` sized a reader's buffers before any tag was checked (§4.2) |
| **Address squatting** | the server stored address→key as two unchecked values, so anyone could permanently seize any address (§5.2) |
| **Unvalidated X25519 half** | the promised contributory check existed only in prose; a published key could silently drop every incoming share to ML-KEM alone (§5.3) |
| **The CTX comparison** | §3.2 compared 16-byte CTX against 32-byte HKDF as if the strengths matched; they do not |

### 10.2 The two that were open — both decided, both being implemented

Owner directive 2026-07-29 closed them without a further round of questions: *"this audit is doing
what cannot be done later, so if it is needed, just put it in yourself and report afterwards."*

1. **Sender authentication for shares → BUILT** (§5.5). Static-static X25519 mixed into the
   wrapping key, chosen over a signature so the proof reaches the recipient and nobody else.
   Envelope 1224 → 1240 bytes, identity 1216 → 1248.
2. **A parent link in the sealed file list → BUILT** (§6.1). Each list seals the SHA-256 of the
   blob it was built on, so a fork is visible to the next reader on any device that holds the
   parent.

⚠ Wiring across the browser, the server and the conformance vectors was still in progress when
this line was written; the remaining list was tracked internally until it was done.

### 10.3 The second adversarial review — the share path, once it was wired (found A6)

A second pass ran on 2026-07-29 against the claim *"a recipient's inbox shows a sender's address
only when that sender genuinely produced the envelope."* Its scope was the share path end to end —
the crate, the WASM boundary, the browser and the server — which the first review could not cover because that
wiring was still being written.

It found **A6** (§0.1, §5.3): the envelope authenticated the triple *(sender, recipient, DEK)* and
nothing about the file, so "a file from Alice" was only as authentic as the DEK was secret — and the
DEK is held by every other recipient of that same file, and by anyone holding a public link to it.
That is a format change, so it could only be made before the mainnet cutover. It is built.

### 10.4 Not yet re-attacked

Between them, the two reviews have covered the specification, the Rust crate and the share path. **The
server outside sharing and the embedded-wallet key export have not been through an adversarial
pass.** In particular the wallet-key export path opens a new boundary and
must be reviewed *with* this format, not after it.
