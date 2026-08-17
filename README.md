# nmts-crypto

The end-to-end encryption engine that runs in your browser when you use [NMTS](https://nmts.me).
It turns an account code into keys, encrypts files before they leave the device, and derives
the wallet that pays for storage. It touches no network and no disk.

Published so the format can be checked rather than believed.

**NMTS** ([nmts.me](https://nmts.me)) is end-to-end encrypted file storage built on Walrus: every
file is encrypted in your browser before it is uploaded, and every key comes from an account code
that never leaves your device. This repository is part of what runs there.

The program that gets your files back if NMTS is gone is a separate repository:
[nmts-recovery](https://github.com/needmoretruth/nmts-recovery). It calls this engine.

## What is here

* `crypto/` — the engine.
* `crypto-wasm/` — the boundary that exposes it to a browser.
* `docs/` — the format specification and the recovery-map format.
* `crypto/tests/vectors/` — conformance vectors: fixed inputs, committed expected bytes.

The server, the web interface, and the payment and storage logic are not here and are closed.

The engine assembles published standard algorithms — Argon2id, HKDF-SHA-256,
XChaCha20-Poly1305, X-Wing (X25519 + ML-KEM-768), ML-DSA-44, X25519. It invents no
cryptography.

## The specification is normative

[`docs/CRYPTO-FORMAT-NCF3.md`](docs/CRYPTO-FORMAT-NCF3.md) defines the format; this crate
implements it; the vectors decide. Where they disagree, the specification and the vectors win.

* **§1** — the derivation chain. Every key comes from one 160-bit account code, and which keys
  ever reach the server is stated exactly.
* **§9** — what the format does not stop, including the fact that reading this source tells you
  what a browser *should* receive, not what it did.

## Checking it

```sh
cd crypto && cargo test --features vectors
cd crypto-wasm && wasm-pack build --target web
```

The vectors are plain JSON. Implementing the specification in another language and comparing
is a check that does not require trusting this crate.

## Contributions

**Please send a description, not a patch.** Pull requests are not accepted and are not read:
merging outside code carries its author's copyright with it, and reading a diff makes it hard
to later show that a similar fix was written independently. Describing what is wrong keeps
that clean and loses nothing — the diagnosis is the valuable part.

Bug reports, questions and attacks on the design are wanted. Open an issue or write to
nmts@nmts.me. If something puts users at risk, write first so a fix can ship before it is
public. A report that leads to a change is credited in the commit.

## License

GNU Affero General Public License v3.0 — see [`LICENSE`](LICENSE). NMTS holds the copyright and
also uses this code in its own service under its own terms.
