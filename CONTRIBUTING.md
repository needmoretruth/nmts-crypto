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

## Sending code

**Code is welcome here.** Open a pull request, and put one line in it — in the description, or in
a comment on it:

> I have read the Contributor License Agreement and I agree to it.

The description is the better place: GitHub has no way to delete a pull request, so a sentence
there stays put. Either is accepted.

That is the whole agreement process — no signature, no legal name, no address, no form. The
agreement is [CLA.md](CLA.md); [the Korean explanation](CLA.ko.md) says what each clause
means, for anyone who would rather read it that way. It is the same agreement for every needmoretruth repository,
so agreeing once is enough.

The short version of what it does: you keep the copyright in what you wrote, and we get a licence
broad enough to keep the whole program under one owner. That matters because different licence
terms are offered to anyone whose situation Apache-2.0 does not fit, and that offer can only be
made by whoever holds all of it.

⚠ **How your change actually arrives, because it is not the usual way. This repository is an
export.** The code is written in another repository and copied here in whole files, so a commit
made *here* would be overwritten by the next export. So the change is taken into the source this is
exported from, and appears here in the next export. The pull request is then closed with a link to
the commit that carries it — closed because it landed, not because it was refused. Your name goes
in [CONTRIBUTORS.md](CONTRIBUTORS.md).

### From a terminal, start to finish

Nothing here needs a browser once you have a GitHub token — no form, no sign-in page, no click.
With [`gh`](https://cli.github.com) installed and authenticated:

```
gh repo fork needmoretruth/nmts-crypto --clone
cd nmts-crypto
git switch -c what-this-fixes
# edit, then:
git commit -am "what you changed and why"
git push -u origin what-this-fixes
gh pr create --repo needmoretruth/nmts-crypto --title "..." --body \
  "What this changes, why, and how to see that it works.

I have read the Contributor License Agreement and I agree to it."
```

⚠ **`gh repo fork` has to come first.** `gh pr create` will offer to fork for you, but only when it
has a terminal to ask on; with no terminal it stops instead. Forking first works either way.

**No `gh`?** Fork and clone with plain `git`, push your branch, and open the pull request in a
browser; or send the change to **nmts@nmts.me** as the output of `git format-patch`. The agreement
line is needed either way, in the pull request or in the mail.

**If you would rather not open a pull request, paste the diff in an issue.** It is read the same
way. The agreement line is still needed before any of it is used.

**A change here is read line by line, and that will be slow.** This is where files are sealed: a
wrong line does not crash, it quietly weakens the sealing, and nobody finds out. Expect questions
about why a change is correct rather than about whether it works. ⛔ The format itself is frozen —
a change to the derivation, the domain separators or the wire layout is a new format version, not a
patch, and it cannot be taken as one.

## What cannot be accepted

- Work that is not yours to give, or that carries a licence you have not told us about.
- A change with no way to tell whether it works. New behaviour comes with a test.
- A rewrite of something that already works, sent without asking first. Say what you want to
  change in an issue before writing it, and you will not waste an afternoon.

## Conduct

Be plain and be accurate. Disagreement about the code is welcome and personal attacks are not.
Comments that abuse someone are removed and the account is blocked; there is no process beyond
that, and pretending otherwise would be a promise nobody here can keep.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). If a term is in the way of what you are building, write to
**nmts@nmts.me** and say why: what you are building, and which part of the licence is the problem.
