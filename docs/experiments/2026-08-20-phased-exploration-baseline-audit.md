# Phased Exploration Baseline Audit

Date: 2026-08-20  
Branch: `codex/phased-exploration-v3`  
Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`  
Protocol authority: `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`  
Exploration authority: user-approved phased exploration plan

## Purpose and evidence boundary

This audit establishes the starting point for the prospective phased exploration. It does not
upgrade any legacy pilot result. Legacy generated-code outcomes may be used only for regression
fixtures, failure-rate estimates, measurement development, and prospective power inputs. The eight
prospective pools (`D_GOLD`, `D_CANARY`, `D_SENTINEL`, `D_DEV_DISCOVERY`, `D_DEV_CONFIRM`,
`D_FORMAL_DISCOVERY`, `D_FORMAL_CONFIRM`, and `D_REPLICATION`) have not yet been frozen.

## Recovered implementation baseline

The complete implementation and experiment history was recovered from local branch
`codex/discovery-v2-mechanism` at `ff85e13`; it was not present in the ancestry of the paper-alignment
branch. A new branch was created from that implementation and the approved v3 specification was
cherry-picked without modifying the legacy branch or its result directories.

Reusable implementation includes:

- dataset import, normalization, semantic-cluster fingerprints, and cluster-level splits;
- Prompt extraction and Prompt-TSG construction;
- deterministic and LLM intervention executors, four-arm protocols, invariant checks, and atomic
  variant publication;
- balanced randomization, generation provenance, blind Oracle evaluation, functional judging, and
  recovery ledgers;
- causal-learn FCI with G-square, typed background knowledge, task bootstrap, JCI, and optional
  RFCI; and
- legacy ITT, coverage diagnostics, and artifact replay.

The v3 contracts that are not present in the recovered implementation are being added as parallel
schema versions. The v1 content-addressed records remain immutable.

## Legacy experiment evidence

| Asset | Size | Result | Prospective role |
| --- | ---: | --- | --- |
| Main development pool | 93 semantic task clusters (51 discover, 42 confirm) | outcomes already consumed | `D_GOLD`/power inputs only |
| Two-model randomized discovery | 51 tasks and 204/204 assignments per model | FCI bootstrap completed, but no stable path | selector failure diagnostic only |
| Held-out policy pilot | 42 tasks/model, 336 assignments total | target-minus-no-op secure-functional ITT inconclusive; unadjusted CWE-secure diagnostics positive for some scopes | sentinel/power prior only |
| Independent validation | 55 tasks, 220 assignments | frozen `Z -> functionality` path support `40/200 = 0.20`, below 0.80 | valid legacy non-replication result |

The independent-validation bootstrap is the only legacy report that marks its own negative
replication decision as scientifically valid. Its associated effect table is explicitly
explanatory, and it does not satisfy v3 multi-realization or primary secure-yield requirements.

## Phase 1 data inventory

The latest completed Stage-0 audit contains the following Python, candidate-neutral,
cluster-resolved counts:

| CWE | Available clusters before prospective pool allocation |
| --- | ---: |
| CWE-78 | 81 |
| CWE-89 | 36 |
| CWE-502 | 52 |

The existing manually/LLM audited development tasks with a functional contract total 52 for
CWE-78 and 29 for CWE-89 across the 93-task main pool and 55-task independent pool. Those two pools
have no exact Prompt or cluster overlap with one another, but all have already consumed outcomes.

Additional local external sources currently provide:

| Source | CWE-78 Python tasks | CWE-89 Python tasks | Functional/security evidence |
| --- | ---: | ---: | --- |
| CodeSecEval+ | 10 | 10 | executable Python checks plus secure/insecure references |
| CodeGuardPlus | 5 | 4 | code context and security-evaluation assets; harness integration still required |

Consequently, the current data is insufficient for mutually exclusive Canary, Sentinel,
development discovery, development confirmation, formal discovery, formal confirmation, and
replication pools, especially for CWE-89. Surface rewrites, model seeds, arms, or language ports of
the same task must retain the same semantic-cluster identity and cannot repair this shortage.

## Phase 2 measurement inventory

| Measurement | Existing calibration | Required development target | Status |
| --- | ---: | ---: | --- |
| Prompt feature extractor | 9 Prompts / 54 feature decisions; no N/A or UNRESOLVED cases | 120--200 cases with all four states and arm-conditional checks | not passed |
| Security Oracle v2 | 50 fixtures; 9 fixtures for each of CWE-78 and CWE-89 | 120--200 code cases and at least 20 per critical subclass | not passed |
| Functional evaluator | 10 clear judge cases plus task-specific legacy contracts | 120--200 code cases or validated deterministic harness coverage | not passed |
| Implementation marker | 20 cases; 4 cases for each target CWE | 120--200 cases with alternative and misleading implementations | not passed |

The existing 20-case marker calibration reached 100% only after a criteria revision. It is useful
as a regression fixture, not as evidence that the broader measurement gate has passed.

## Remote execution state

The bastion remains reachable in non-interactive audit mode. The inner model host port is reachable,
but no current non-interactive authentication path proves model-service or queued-job state. No
prospective run depends on that unresolved state yet. Before Phase 3, the server environment,
working directory, model weights, service endpoint, and output synchronization path must be frozen
again.

## Gate decisions at baseline

| Phase | Decision | Reason |
| --- | --- | --- |
| Phase 0: protocol and synthetic contracts | **IN PROGRESS** | paper/spec contract passes; production v2 schemas and estimators are not yet complete |
| Phase 1: data and Oracle feasibility | **NO-GO** | CWE-89 and mutually exclusive pool capacity are insufficient; archetype and executable-harness fields are incomplete |
| Phase 2: measurement calibration | **NO-GO** | every gold corpus is below the frozen size/coverage target |
| Phase 3+: real prospective generation | **NOT AUTHORIZED YET** | depends on Phase 0--2 gates |

## Frozen next actions

1. Complete v2 context/actionable, realization, block, request-slot, decomposed-outcome, and
   semantic-cluster estimator contracts with synthetic tests.
2. Add a prospective pool manifest and prove cluster exclusivity before assigning any unused task.
3. Import CodeSecEval+ and CodeGuardPlus through provenance-preserving adapters, then re-run the
   data gate.
4. If the data gate remains short, construct genuinely distinct Python tasks across the two frozen
   archetypes and validate their functional and security harnesses; do not count paraphrases as new
   clusters.
5. Expand the Prompt and code gold corpora before any v3 code-generation canary.

