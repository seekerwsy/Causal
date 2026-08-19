# Five-CWE independent-validation Gate A

## Purpose and frozen inputs

Gate A freezes the four Prompt arms and complete-block randomization before any independent code
generation or outcome measurement. It consumes the 55 v2 source Prompts, their 55 frozen functional
contracts, and the public selection ledger. The Prompt and selection digests are respectively
`05209e464c002df9ad94f6e40e82a3f2b45561f874ea5caa8f874872b9630a84` and
`dccf573ce538b5998a39d2466bc1a08de43efa13be8bb5ff91f602fb885e5646`.

The four arms are the exact finite catalog variants: target patch, newline no-op rewrite,
length-matched placebo, and generic security reminder. The original Prompt is an exact prefix of
every variant. Each task has one assignment to every arm under four frozen seed slots. Gate A makes
zero model calls and explicitly forbids outcome generation.

## v1 failure and v2 correction

The first run is preserved at
`runs/restricted/five-cwe-independent-validation-gate-a-phi14b-20260819-01`. It stopped before
writing any assignment or observing any outcome because the v1 deterministic Prompt extractor
supports only Python. The 20 Java, Go, and C sources were therefore `unresolved`, not target-present:
Java 11, Go 4, and C 5. All 35 Python sources were target-absent, and none of the 55 sources contained
the exact target intervention clause.

The correction introduces `deterministic_catalog_v2` while retaining v1 unchanged. v2 applies the
same immutable reviewed English Prompt terms to the frozen Python, Java, Go, C, and C++ scopes. It
adds no keyword, matcher rule, or outcome-dependent exception. A pre-run source check resolved all
55 target features as absent: CWE-78/89/502/328/338 = 16/20/17/1/1.

The completed run is preserved at
`runs/restricted/five-cwe-independent-validation-gate-a-phi14b-20260819-02`. It froze 55 tasks,
five candidates, 220 variants, 55 balanced blocks, 220 assignments, 220 extraction proposals, and
220 Prompt TSGs with zero error and zero pending unit. The assignment digest is
`823f61a2565c2bd569bccb5735a16f222253cd7d96b4004bb80e2898b5abd6c9`; the variant digest is
`7d8554ffb13dd06bd4662eacbbf76d2d5a3e513a2663afe99e34fb02ac36d176`; and the v2 extractor-policy
digest is `a9edab980ffc4da3aaad6b6effc0ff8ad65f8fb612c727d722c5bb52f35c2912`.

## Diagnostic boundary

The deterministic Prompt TSG remains a diagnostic. It recognized the target suffix for 7/55 target
arms, all in CWE-89. The other exact target suffixes did not pass the catalog's separate
task-prerequisite phrase matcher. No new terms were added to inflate this number. Independent
validation tests the already-frozen relation
`z.target_mechanism_realized -> y.discovery_functional`; the randomized four-arm context is stored
directly in the assignment ledger and does not depend on this diagnostic recognition rate.

## Verification and operational incidents

The v2 backend and Gate A path passed 153 targeted extractor, proposal-schema, TSG-builder,
factory, pipeline, and canary tests. No full repository suite was run. Ruff passed on the directly
modified extractor and Gate A files; pre-existing broad exception boundaries remain explicitly
documented trust-boundary conversions.

During diagnosis, three read-only repository searches referenced a guessed nonexistent test path,
used one malformed regular expression, and later included another nonexistent canary test name.
One large inspection output was also truncated. None changed files or experimental state. The
diagnostic was rerun with exact paths and compact JSON summaries before implementation.

The next step is to freeze a language-neutral response-extraction policy, the Phi-4-14B generation
coordinates, the existing single-pass functional Judge and v2 mechanism policies, and the exact
FCI/JCI/bootstrap analysis manifest. A small one-per-language/CWE generation canary must pass before
the 220 assignments can run.
