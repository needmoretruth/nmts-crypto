# Contributing

`nmts-crypto` is the encryption engine that runs in the [NMTS](https://nmts.me) browser app and in
the recovery program, published with the format specification and the conformance vectors so that
the format can be checked rather than believed. This file says what is welcome here and what
cannot be accepted.

**Talk about NMTS — [Discord](https://discord.gg/pcmRkVmVZk).** Questions, ideas, and what
people are building with it. English or Korean; both are read.

## Building it yourself

Rust. The vectors are behind a feature flag because they are the slow part.

```
cd crypto && cargo test --features vectors
cd crypto-wasm && wasm-pack build --target web
```

The conformance vectors are fixed inputs with their expected bytes committed beside them. If a
change ever makes one of them move, that is the format changing — which is the thing they exist
to catch.

## What is welcome

- **Bug reports.** What you did, what happened, how it can be seen again. There is a form for it.
- **Questions** about the format, the code, or a guarantee you are trying to check.
- **Ideas**, including ones that say the current design is wrong.
- **Independent verification.** Build it yourself, run the tests, read the format documents, and
  say where the code and the documents disagree. That is the most useful thing anyone can send.

**Write in English or in Korean.** Both are read.

## What cannot be accepted, and why

**Pull requests are not merged.** A pull request opened here will be read and then closed, and
that is not a judgement about the patch.

The copyright in this program is held in one place, so that different licence terms can be offered
to anyone whose situation Apache-2.0 does not fit. Merging a patch would move part of that
copyright to its author, and the offer would stop being true for the whole program. A contributor
agreement — the document that would make it possible to accept code without that happening — is
being chosen; until one is in place there is no way to take a patch in.

⚠ There is a second, more practical reason. **This repository is an export.** The code is written
somewhere else and copied here in whole files, so a commit made here would be overwritten by the
next export rather than merged into anything.

**If you have already written the fix, paste the diff inside an issue.** It cannot be merged, but
it can be read, and it says exactly what you mean.

## Conduct

Be plain and be accurate. Disagreement about the code is welcome and personal attacks are not.
Comments that abuse someone are removed and the account is blocked; there is no process beyond
that, and pretending otherwise would be a promise nobody here can keep.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). If a term is in the way of what you are building, write to
**nmts@nmts.me** and say why: what you are building, and which part of the licence is the problem.
