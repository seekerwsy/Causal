# Codex source review and local repair check

This three-case, exposed-source diagnostic continues previously retained Codex
constructions through the existing review and local patch interfaces. It is not
three new independent construction runs or a new default research method.

The plan and reviewer instructions were fixed before responses. Each reviewer
received the source, existing record semantics/schema and deterministic readback,
without references or old audits. The existing `repair_request` function produced
the permitted repair region. Each needed patch used a fresh agent and the existing
patch schema, `apply_record_patch`, `compile_records` and graph compiler. There was
one review per case and at most one patch, with no retry or second reviewer.

| Case | Review / patch | Final compilation | Source-audit result |
| --- | --- | --- | --- |
| Firmware | Review and patch | Passed | Input role clarified; successful-completion return guard made explicit. Frozen reference already allowed the original normal-return boundary, so this is not a critical semantic repair. |
| Pandoc | Review approved; no patch | Passed | Both frozen-reference API predicate mismatches remain, with source ambiguity unacknowledged by the reviewer. |
| Privilege order | Review and patch | Passed | `u1` coverage now matches its already-unresolved impact. Direct-target ambiguity and correct order edges remain unchanged. |

Before and after: 19/23 fixed meanings correct, two reference mismatches, two
unresolved target bindings. Zero critical wrong/unresolved-to-correct transitions
were established. The input-role clarification is outside that requirement count;
no candidate benefit is inferred. All five agent responses and three final graphs
are retained. Model snapshot/seed are unavailable. External API calls/cost: zero;
Codex account usage is separate.

`source-audit.json` is a root author audit, not independent human gold. It reuses
fixed prior judgments for unchanged structures and examines changed fields and
compiled bindings. Candidate assessment, actual prompt edits and formal study
execution did not run. The workflow executed, but reliable semantic repair has not
been demonstrated. No default component was added.

Replay using the parent artifact's existing entry point:

```text
.venv/Scripts/python.exe data/method/tsg-reliable-construction-v1/verify.py
```

This reconstructs review requests, allowed patches and final graphs using the
same archived implementation and compares saved results; it does not call models
or independently certify the author's judgments. The original constructor
inputs/results remain in `../agent-repeatability`; their byte identities are fixed
in `input-identities.json`. Do not overwrite those original runs.
