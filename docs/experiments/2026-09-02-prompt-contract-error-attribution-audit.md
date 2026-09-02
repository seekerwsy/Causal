# Prompt-contract QUAL_DEV error-attribution audit — 2026-09-02

## Decision

The current critical-path failure is localized to the Stage-I method/model
interface. The fresh v5 canary failure is directly expressed as Qwen semantic
test-retest instability, but the disputed archive label also depends on an
under-specified operational bridge from `externally supplied` to `untrusted`.
It is therefore neither evidence that the downstream PHASE causal method is
wrong nor sufficient evidence that model capacity alone is the root cause.

The active extractor remains unqualified. This audit changes no gold label,
Prompt, catalog, consensus rule, role, or provider authorization.

## Scope and evidence boundary

This was a zero-network development audit of:

- all 11 mismatches in the frozen 28-case v1 source-only `QUAL_DEV` run;
- the same three targeted cases across the v3, v4, and v5 canaries;
- archived raw proposer/reviewer responses, compiled contracts, and independent
  qualification replays.

The source gold was completed before extraction by two isolated subagent
reviewers, with a third isolated reviewer deciding four of 56 disagreements.
The archive case was an agreement case. This is useful independent model-review
evidence, but it is not external human gold. The audit's inference-tier labels
are root-agent development attributions and must not be promoted to gold or
formal evidence.

No arm, outcome, Discovery result, confirmation result, or paper-facing effect
claim was read or produced.

## Attribution taxonomy

The highest reasoning tier needed to apply the existing source-gold rationale is
recorded separately from the observed technical failure:

| Tier | Meaning |
|---|---|
| E0 | The source directly names the relevant operation, protocol, type, or exclusion. |
| E1 | A deterministic composition of explicit interface facts is sufficient; no threat-model assumption is needed. |
| E2 | The conclusion depends on a security-domain convention, trust interpretation, or required-versus-possible implementation policy. |
| E3 | The conclusion needs facts outside the Prompt or an unstated deployment/threat model. |

Observed failure signals are multi-label. For example, one task can contain both
proposer/reviewer disagreement and an independent evidence-span demotion.

## Mechanical error decomposition

The v1 independent replay matched 17/28 cases (`0.607143`) and missed 11. Present
recall was 3/7 (`0.428571`), with zero false-positive-present and zero
wrong-realization cases.

Among the 11 mismatches:

| Signal | Cases | Interpretation |
|---|---:|---|
| At least one raw semantic classification disagreement | 8 | The two same-snapshot roles did not resolve a primitive semantic identically. |
| At least one shared raw `unresolved` decision | 3 | Both roles abstained on at least one primitive semantic. |
| Unanimous raw `present` demoted by exact-evidence validation | 4 | Semantic classification and evidence serialization were conflated by the old strict consensus. |
| Unanimous semantic false negative | 1 | Both roles agreed on an incorrect absence under the frozen source gold. |

These counts overlap and must not be added. Independent qualification reproduced
the stored task-level results; no query/binding replay divergence was observed.
This does not prove the query engine correct for every possible input, but it
rules out a replay discrepancy as the cause of these 11 observed failures.

## Case-level attribution

| Task suffix | Expected → observed | Highest tier | Dominant layer | Archived signal |
|---|---|---|---|---|
| `deb850f6` | archive present → absent | E2 | method/model interface | unanimous semantic false negative; cross-run instability; trust-convention boundary |
| `e863417e` | Requests TLS present → unresolved | E1 | model classification | proposer/reviewer disagreement on the TLS sink |
| `a269591d` | YAML present → unresolved | E1 | model + evidence interface | shared abstention plus unanimous-present evidence demotion |
| `521696d2` | fixed SQL values present → unresolved | E1 | evidence interface | unanimous-present evidence demotion |
| `b96c5629` | Paramiko SFTP absent → unresolved | E0 | model classification | cross-protocol disagreement plus shared abstention |
| `6841cc98` | arbitrary request command absent → unresolved | E1 | model classification | disagreement on caller-selected executable semantics |
| `0dca2461` | dynamic Python code absent → unresolved | E0 | model classification | disagreement between code execution and literal deserialization |
| `eb876573` | underspecified SQLite task absent → unresolved | E2 | method/model interface | disagreement, evidence demotion, and fixed-vs-dynamic SQL boundary |
| `57d2f4d6` | filesystem listing absent → unresolved | E2 | method/model interface | disagreement/shared abstention and required-vs-possible process-use boundary |
| `193bb77b` | static `SHOW TABLES` absent → unresolved | E0 | model + evidence interface | disagreement plus evidence demotion |
| `3027f69c` | dynamic Python code absent → unresolved | E0 | model classification | disagreement between code execution and literal deserialization |

The tier distribution is E0: 4, E1: 4, E2: 3, and E3: 0. The dominant-layer
distribution is model semantic classification: 5, method/model interface: 3,
model plus evidence interface: 2, and evidence interface: 1.

## What v5 resolved and what remains

The three canary task states were:

| Case | v3 | v4 | v5 |
|---|---|---|---|
| archive extraction | absent | present | absent |
| YAML deserialization | present | unresolved | present |
| fixed SQL values | unresolved | unresolved | present |

The v4 and v5 frozen task-request files are byte-identical. They also use the
same proposer/reviewer Prompt hashes, fixed model snapshot, response format,
temperature, top-p, and seeds. Nevertheless, both raw archive annotations moved
from `present` in v4 to `absent` in v5. This is direct evidence of model-facing
semantic test-retest instability. Fixed snapshot and temperature zero did not
make this boundary decision reproducible.

The evidence-aware v5 consensus successfully closed the YAML and SQL cases. The
remaining archive error is not an evidence-span failure: both fresh roles claim
that a caller-supplied TAR does not establish an untrusted archive-member source.
The source gold and v4 roles take the opposite interpretation.

## Method versus model finding

The observed response change is a model reliability failure. The fact that this
change can redefine the eligible study population is a method operationalization
failure. The current catalog names `source.untrusted_archive_member` but explains
it as archive member names or paths externally supplied through an archive. The
Prompt explicitly supplies `tar_path`, but does not literally assert a threat or
trust status. The active protocol has not fully specified whether this bridge is
an allowed deterministic inference.

A stronger model might pass this particular gate, but that would not by itself
make the construct model-invariant or reviewable. Conversely, hard-coding the
expected context label would hide rather than solve the measurement problem.

Nothing in this audit implicates the FCI, RD, ranking, randomization, measurement,
or ITT implementation. Those stages remain unexecuted and cannot yet be evaluated
scientifically.

## Constraint on the next redesign

Before changing the active extractor, a new prospective design should freeze an
ontology-boundary protocol with these safeguards:

1. Extract only source-grounded primitive facts with exact evidence.
2. Permit deterministic derivation only from catalog-wide E0/E1 rules written
   without task IDs, dataset IDs, expected contexts, or gold realizations.
3. Keep E2/E3 conclusions unresolved unless a separately frozen expert rule
   defines the convention.
4. Include negative counterexamples for every derivation rule so that
   caller-controlled, external, and untrusted are not silently collapsed.
5. Freeze the rules before opening any new holdout or making provider calls.
6. Continue to report unresolved coverage rather than forcing it into present or
   absent.

This avoids the main new risks of deterministic mapping: qualification-case
overfitting, ontology leakage, false certainty, uneven CWE coverage, and
self-validating gold.

## Reproducibility record

The complete machine-readable attribution, full task IDs, manifest bindings,
request identity, and claim boundary are stored in
`data/method/qwen37flash-prompt-contract-error-attribution-audit-v1.json`.

Key immutable inputs are:

- source-gold manifest: `4854c62c2651001e144b79d547cdac489e9b84d2e84a53ffe277cec19bc5579f`;
- v1 extraction manifest: `04bd573d45353ca601196ec6de408ff2d11b3b7989bc85d4d29f3c67a6e12f4f`;
- v1 independent replay manifest: `8baea1b58c5cec70203fc44402f921ba85593e60efc832656976209d9587bd7b`;
- v5 extraction manifest: `0ee9505b61a4870c7bfcdaaf7db32e3186a040a7f5a9d2535da4706b88efe42c`;
- v5 independent replay manifest: `2dc1d985661a29715d25553e1b149867b49dc0580d4eb7caa80903f5bd8c3dd1`.

The audit consumed zero provider calls and zero additional budget.
