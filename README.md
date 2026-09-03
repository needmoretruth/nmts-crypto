# nmts-crypto

The end-to-end encryption engine that runs in your browser when you use [NMTS](https://nmts.me),
end-to-end encrypted file storage built on Walrus. It turns an account code into keys, encrypts
files before they leave the device, and derives the wallet that pays for storage. It touches no
network and no disk. Published so the format can be checked rather than believed.

> Talk about NMTS on [Discord](https://discord.gg/pcmRkVmVZk), in English or Korean.

The program that gets your files back if NMTS is gone is a separate repository,
[nmts-recovery](https://github.com/needmoretruth/nmts-recovery). It calls this engine.

## What is here

- `crypto/` — the engine.
- `crypto-wasm/` — the boundary that exposes it to a browser.
- `docs/` — the format specification and the recovery-list format.
- `crypto/tests/vectors/` — conformance vectors: fixed inputs, committed expected bytes.

The server, the web interface, and the payment and storage logic are not here and are closed.

The engine assembles published standard algorithms — Argon2id, HKDF-SHA-256, XChaCha20-Poly1305,
X-Wing (X25519 + ML-KEM-768), ML-DSA-44, X25519 — and invents no cryptography.

## The specification is normative

[`docs/CRYPTO-FORMAT-NCF3.md`](docs/CRYPTO-FORMAT-NCF3.md) defines the format; this crate
implements it; the vectors decide. Where they disagree, the specification and the vectors win.

- **§1** — the derivation chain. Every key comes from one 160-bit account code, and which keys
  ever reach the server is stated exactly.
- **§9** — what the format does not stop, including the fact that reading this source tells you
  what a browser *should* receive, not what it did.

## Checking it

```sh
cd crypto && cargo test --features vectors
cd crypto-wasm && wasm-pack build --target web
```

The vectors are plain JSON. Implementing the specification in another language and comparing is
a check that does not require trusting this crate.

## Contributions

Code is welcome — [CONTRIBUTING.md](CONTRIBUTING.md) says how it reaches here, and the
[Contributor License Agreement](CLA.md) is what lets this code also run in the NMTS service under
separate terms. A description is worth as much as a patch here: the diagnosis is the valuable part.

Bug reports, questions and attacks on the design are wanted. Open an issue or write to
nmts@nmts.me. If something puts users at risk, write first so a fix can ship before it is public.
A report that leads to a change is credited in the commit.

## Built on this?

If you built something on this code — a service, a fork, a port to another language, a lighter
client — you owe us nothing: Apache-2.0 asks for the notices and nothing more. We would still like
to know. Write to **nmts@nmts.me**, or open an issue here if public is fine with you. If you want
it listed, say so: [SHOWCASE.md](SHOWCASE.md) carries a link and up to ten lines about each
project, written by the people who made it. A listing is not an
endorsement, and we may decline or remove one without giving a reason.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). It moved here from AGPL-3.0-only on 2026-08-30; copies
already held under the AGPL stay under it. Build on it, ship it, sell what you build with it. If
you need different terms, write to **nmts@nmts.me** and say why; requests are read on their
merits, and no outcome or response time is promised.

Copyright © 2026 needmoretruth, who also uses this code in the NMTS service under separate terms.
