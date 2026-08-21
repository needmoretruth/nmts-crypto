//! The guard that stops a bare `cargo test` from LOOKING complete.
//!
//! `tests/vectors.rs` and `tests/vectors_multichunk.rs` are gated whole-file on the `vectors`
//! feature (`#![cfg(feature = "vectors")]`) and the crate's `default` feature set is empty.
//! Without the feature those two binaries compile to nothing and each reports
//! `test result: ok. 0 passed` — the most convincing shape a test run can take while judging
//! nothing at all. The conformance suite over the FROZEN NCF-3 artifact
//! (docs/CRYPTO-FORMAT-NCF3.md §7) silently does not run, and the summary still says `ok`.
//!
//! This file is compiled under the DEFAULT feature set, so it is always there, and it does three
//! things a zero-test binary cannot:
//!
//! 1. It judges the committed fixtures in `tests/vectors/` — every one must parse, must be
//!    non-trivial, and the frozen `ncf3.json` must still carry its cases. It PRINTS how many
//!    files and how many cases it judged and asserts both against a floor, so a run that judged
//!    nothing fails instead of reporting a cheerful zero.
//! 2. It FAILS when the `vectors` feature is off, naming the command that runs the real suite.
//! 3. It counts, from the sibling sources themselves, how many conformance tests a
//!    `--features vectors` run will actually EXECUTE, and holds that number to a floor.
//!    The feature being ON is not the same thing as the suite being THERE: a renamed or
//!    mistyped crate-level gate, a deleted file, or `#[ignore]` on the tests all put the
//!    suite back at `0 passed` with the feature on and the exit code still 0. Measured
//!    2026-08-21: with every conformance test quieted by `#[ignore]`,
//!    `cargo test --features vectors` exited 0 while `tests/vectors.rs` printed
//!    `0 passed; 13 ignored`. Nothing else in the tree can see that number — an integration
//!    test binary cannot observe its siblings' results, and a binary holding zero tests
//!    reports `ok` in exactly the words one holding passing tests uses.
//!
//! ⛔ `vectors` stays OFF by default on purpose, and this test is the reason it can. The crate
//!    is a path dependency of the server, of the standalone recovery tool and of the browser
//!    WASM surface, and none of the three disables default features. Making `vectors` default
//!    would compile the deterministic, caller-supplied-nonce constructors into all three shipped
//!    builds — a nonce the caller chooses is exactly the thing this format must never let a
//!    production build reach. The answer to "a bare run looks complete" is this failing test.
//!
//! ⚠ Presence is not conformance. Nothing here verifies a byte of the format; that is what
//!    `cargo test --features vectors` does. This test only makes the absence of that run loud.

use serde_json::Value;
use std::path::PathBuf;

/// Every committed conformance fixture lives here.
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

/// The frozen NCF-3 conformance artifact. Named explicitly — it is THE file the format document
/// points at, so its disappearance has to be a failure rather than a shorter directory listing.
/// Everything else is discovered from the directory, never from a list someone has to remember
/// to extend.
const FROZEN_ARTIFACT: &str = "ncf3.json";

/// Floors, set a little under the measurement of 2026-08-21 (7 fixture files, 36 cases in the
/// frozen artifact). A floor is what separates "judged everything and it was fine" from
/// "judged nothing and said ok" — the failure this whole file exists to prevent.
const MIN_FIXTURES: usize = 6;
const MIN_CASES: usize = 32;
/// Below this a JSON file cannot be carrying vectors, whatever its name says.
const MIN_FIXTURE_BYTES: u64 = 1024;
/// `ncf3.json` is about 119 KiB. Anything near this floor has been truncated or emptied.
const MIN_FROZEN_BYTES: u64 = 50_000;

/// The crate-level gate the conformance binaries carry. The set of suites is DERIVED by looking
/// for this line, never listed by name: a file that stops carrying it — feature renamed, name
/// mistyped, file deleted — drops out of the set, which is how a silently re-gated suite becomes
/// a failure instead of a shorter run.
///
/// ⚠ Matched as a WHOLE LINE on purpose. This file quotes the same string in its own header, and
/// a substring search would count the guard as one of the suites it is supposed to be guarding.
const SUITE_GATE: &str = "#![cfg(feature = \"vectors\")]";

/// Floors for the gated suites, measured 2026-08-21: 2 files carrying `SUITE_GATE`, 16 `#[test]`
/// functions between them, 2 of which are `#[ignore]`d regenerators — so 14 run.
///
/// `MIN_GATED_SUITES` is NOT set below today's count, and that is deliberate: 2 is not a level
/// the suite happens to have reached, it is what the suite IS (`vectors.rs` for the frozen
/// artifact, `vectors_multichunk.rs` for the multi-chunk fixture). One of them vanishing is the
/// failure this floor exists for; a third one appearing keeps the count above it either way.
const MIN_GATED_SUITES: usize = 2;
/// Set a little under the 14 that run today. Individual vectors get merged and split; losing
/// more than a couple means the suite is being emptied rather than reorganised.
const MIN_RUNNABLE_VECTOR_TESTS: usize = 12;

/// How many gated suites there are, and how many of their tests a run with the feature on will
/// execute (`#[test]` functions minus `#[ignore]`d ones). Both come from the directory and from
/// the sources in it, so a suite added later is counted without anyone editing this file.
fn gated_suites() -> (usize, usize) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("test sources are unreadable: {} ({e})", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    sources.sort();

    let mut suites = 0usize;
    let mut runnable = 0usize;
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("test source is readable");
        if !text.lines().any(|line| line.trim() == SUITE_GATE) {
            continue;
        }
        suites += 1;
        let tests = text.lines().filter(|line| line.trim() == "#[test]").count();
        let ignored = text
            .lines()
            .filter(|line| line.trim_start().starts_with("#[ignore"))
            .count();
        runnable += tests.saturating_sub(ignored);
    }
    (suites, runnable)
}

/// Under `--features vectors` the real suite ran in the sibling binaries; nothing to say.
#[cfg(feature = "vectors")]
fn require_the_suite_ran(_fixtures: usize, _cases: usize, _waiting: usize) {}

/// Without the feature the sibling binaries were empty. Say so, loudly, and name the command.
#[cfg(not(feature = "vectors"))]
fn require_the_suite_ran(fixtures: usize, cases: usize, waiting: usize) {
    panic!(
        "\n\
         The NCF-3 conformance suite did NOT run.\n\
         \n\
         `tests/vectors.rs` and `tests/vectors_multichunk.rs` are gated on the `vectors` feature,\n\
         so without it they compile to nothing and print `test result: ok. 0 passed`. This run\n\
         checked {fixtures} fixture files for presence only ({cases} cases in {FROZEN_ARTIFACT});\n\
         {waiting} conformance tests were left standing behind the feature and not one byte of\n\
         the format was verified.\n\
         \n\
         Run the real gate:   cargo test --features vectors\n"
    );
}

#[test]
fn conformance_vectors_are_present_and_the_suite_actually_ran() {
    let dir = fixtures_dir();

    // Derived from the directory itself: a fixture added later is judged without anyone
    // remembering this file exists.
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| {
            panic!(
                "conformance fixtures are unreadable: {} ({e})",
                dir.display()
            )
        })
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    fixtures.sort();

    let mut frozen_seen = false;
    let mut cases_in_frozen = 0usize;

    for path in &fixtures {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture file name");
        let bytes = std::fs::metadata(path).expect("fixture metadata").len();
        assert!(
            bytes >= MIN_FIXTURE_BYTES,
            "{name}: {bytes} B — too small to be carrying vectors (floor {MIN_FIXTURE_BYTES} B)"
        );

        let text = std::fs::read_to_string(path).expect("fixture is readable");
        let parsed: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not valid JSON ({e})"));
        let object = parsed
            .as_object()
            .unwrap_or_else(|| panic!("{name}: top level is not an object"));
        assert!(!object.is_empty(), "{name}: top-level object is empty");

        if name == FROZEN_ARTIFACT {
            frozen_seen = true;
            assert!(
                bytes >= MIN_FROZEN_BYTES,
                "{name}: {bytes} B — the frozen artifact has been truncated (floor {MIN_FROZEN_BYTES} B)"
            );
            assert_eq!(
                object.get("format").and_then(Value::as_str),
                Some("NCF-3"),
                "{name}: does not declare itself the NCF-3 artifact"
            );
            // Every top-level array is a group of vectors; their lengths are the case count.
            cases_in_frozen = object
                .values()
                .filter_map(Value::as_array)
                .map(Vec::len)
                .sum();
        }
    }

    let (suites, runnable) = gated_suites();

    // The floors, printed as well as asserted — on failure this line is what says how far a
    // count fell, and `--nocapture` shows it on a green run.
    println!(
        "conformance guard: judged {} fixture files, {cases_in_frozen} cases in {FROZEN_ARTIFACT}, \
         {suites} gated suites carrying {runnable} runnable tests",
        fixtures.len()
    );

    assert!(
        frozen_seen,
        "{FROZEN_ARTIFACT} is missing from {}",
        dir.display()
    );
    assert!(
        fixtures.len() >= MIN_FIXTURES,
        "judged only {} fixture files (floor {MIN_FIXTURES})",
        fixtures.len()
    );
    assert!(
        cases_in_frozen >= MIN_CASES,
        "judged only {cases_in_frozen} conformance cases in {FROZEN_ARTIFACT} (floor {MIN_CASES})"
    );

    assert!(
        suites >= MIN_GATED_SUITES,
        "only {suites} test files still carry `{SUITE_GATE}` (floor {MIN_GATED_SUITES}) — a \
         conformance suite has been deleted or its gate renamed, and `cargo test --features \
         vectors` would report `ok` without it"
    );
    assert!(
        runnable >= MIN_RUNNABLE_VECTOR_TESTS,
        "only {runnable} conformance tests would actually run under `--features vectors` (floor \
         {MIN_RUNNABLE_VECTOR_TESTS}) — the suite has been emptied or `#[ignore]`d, which reads \
         as `ok` in the summary line"
    );

    // The artifact is here and intact, and the suite that checks it still has tests in it.
    // Whether the feature was on — whether anything ACTUALLY checked it in this run — is the one
    // question left, and this is the only place a default-feature run can ask it.
    require_the_suite_ran(fixtures.len(), cases_in_frozen, runnable);
}
