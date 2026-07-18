# SecAware Prompt-Only FCI/JCI Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved Prompt-only FCI/JCI framework as four independently testable milestones without introducing Code TSG or an extractor benchmark.

**Architecture:** Keep Prompt TSG as the sole feature authority and the independent Oracle as the sole security-outcome authority. Implement extraction, observational discovery, randomized prompt confirmation, and secondary JCI/RFCI analysis as four transactional layers whose artifacts are joined only by strict IDs and digests.

**Tech Stack:** Python 3.12, Pydantic 2, NetworkX 3, causal-learn 0.1.4.7, NumPy/Pandas, Typer, pytest, Ruff; optional py-tetrad at commit `a30707264aa4363a23ac5f136a70bbdd62212f07`, JPype1 1.7.1, and JDK 21+.

---

## Authoritative inputs

- Design: `docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`
- Existing Prompt TSG plan: `docs/superpowers/plans/2026-07-12-prompt-tsg-graph.md`
- Existing independent Oracle plan: `docs/superpowers/plans/2026-07-11-independent-oracle.md`
- Starting commit: `3677da3`
- Starting verification: `1888 passed, 49 skipped`

External API locks used by the plans:

- causal-learn FCI accepts `independence_test_method="gsq"`, `background_knowledge`, and
  `node_names`, and returns a `GeneralGraph` PAG plus edge metadata.
- causal-learn `BackgroundKnowledge` supports node-level forbidden directions and tiers. Two-way
  forbiddance is used for typed adjacency exclusion; candidate path edges are never required.
- py-tetrad `TetradSearch.run_rfci` is an optional sensitivity adapter only. Its selected source
  commit requires Python 3.12 and JDK 21+, so it cannot enter the minimum dependency set.

## Locked vocabulary and IDs

All four plans use these names without aliases:

```text
PromptExtractorBackend =
  LLM_FACTS_V1 | LLM_DIRECT_GRAPH_V1 | DETERMINISTIC_CATALOG_V1

FeatureFamily = TASK_FUNCTION | SAFETY_CONTROL | PRESENTATION_CONTROL
FeatureOperation = ADD | REMOVE
FeatureState = PRESENT | ABSENT | NOT_APPLICABLE | UNRESOLVED

TargetSpecRecord.target_spec_id = target_<sha256>
TargetInstanceRecord.target_instance_id = target_instance_<sha256>
ConfirmationProtocolRecord.arm_protocol_id = arm_protocol_<sha256>
ConfirmationProtocolInstanceRecord.protocol_instance_id = protocol_instance_<sha256>
PromptVariantRecord.variant_id = variant_<sha256>
AssignmentRecord.assignment_id = assignment_<sha256>
FrozenHypothesisRecord.hypothesis_id = hypothesis_<sha256>
PAGRecord.pag_id = pag_<sha256>
```

`task_id` identifies the underlying task. Source prompts and all generated variants have distinct
`prompt_id` values but retain the same `task_id`. `model_id` is always a stratum/provenance
coordinate in the minimum backend, never a causal-table variable.

`target_spec_id` and `arm_protocol_id` are semantic cross-task IDs derived from a frozen hypothesis,
operation, arm/contrast definitions, and outcome contract. Task/prompt coordinates appear only in
`target_instance_id` and `protocol_instance_id`. Randomization blocks are task-specific instances;
ITT, multiplicity families, and JCI strata aggregate by the semantic IDs across independent tasks.

## File responsibility boundary

```text
schema/         strict persisted records and enums only
tsg/            finite feature catalog, canonical graph codec, queries, deterministic builder
extractors/     three run-locked Prompt extraction backends
causal/         local tables, background knowledge, PAG codec, FCI/bootstrap/path logic
intervention/   targets, arm catalog, executors, graph deltas, variant validation
experiments/    deterministic block randomization and exact assignment coverage
outcomes/       assignment/outcome joins and conservative outcome encoding
analysis/       task-clustered ITT, contrasts, multiplicity, sensitivity bounds
discovery/      causal-learn and optional py-tetrad backend adapters
pipeline/stages focused transactional stage entry points
cli.py          Typer registration and thin delegation only
```

Generated code is read only by generation, the independent Oracle, and the independent functional
evaluator. No file under `causal/`, `extractors/`, or `tsg/` may import AST helpers, generated-code
schemas, Oracle finding text, or code-mechanism structures.

## Execution order and milestone gates

### Milestone M4A

Execute:

`docs/superpowers/plans/2026-07-13-m4a-prompt-tsg-extractor-backends.md`

Gate:

- all three backends produce the same strict proposal/graph contracts;
- `LLM_FACTS_V1` is the default, while demo configuration explicitly selects the deterministic
  offline backend;
- one run cannot mix or fall back between backends;
- no benchmark, gold corpus, ranking, or winner-selection code exists.

### Milestone M4B

Execute only after M4A is green:

`docs/superpowers/plans/2026-07-13-m4b-fci-discovery.md`

Gate:

- exact local tables and TSG-derived background knowledge are persisted;
- causal-learn 0.1.4.7 FCI runs with G-square and preserves PAG circles;
- one seed per sampled task occurrence is used in bootstrap;
- stable Prompt-side paths and hypotheses are frozen before confirmation artifacts exist;
- an empty stable set commits PAG/path/failure provenance and then stops before M5;
- heuristic TSG-QCD is no longer the primary or CLI-reachable discovery path.

### Milestone M5

Execute only after M4B is green:

`docs/superpowers/plans/2026-07-13-m5-randomized-prompt-confirmation.md`

Gate:

- family/operation-specific protocols implement exact `AllowedDelta` contracts;
- every protocol binds its outcome and pre-registered contrast IDs, and matched arms pass a
  recomputed changed-span UTF-8 length contract;
- all variants are independently extracted and frozen before assignment;
- semantic target/protocol IDs are reused across task-specific instances;
- ADD and REMOVE use distinct complete blocks;
- assignments map seed-slot units to arm roles with a versioned deterministic RNG;
- assignments are committed before generation, and every execution record has exact assignment
  coverage.

### Milestone M6

Execute only after M5 is green:

`docs/superpowers/plans/2026-07-13-m6-itt-jci-rfci-reporting.md`

Gate:

- task-clustered ITT uses every committed assignment and pre-registered contrast;
- ITT and JCI pool independent task instances by semantic target/protocol IDs;
- complete contrast definitions, not just their IDs, are frozen into each M5 protocol digest;
- raw augmented and JCI-constrained PAGs remain separate;
- orientation deltas record the complete JCI assumption set without single-assumption claims;
- RFCI is capability-gated and its absence cannot affect the minimum backend;
- synthetic SCM tests cover chain, latent confounding, null, and deterministic-context cases;
- reports contain PAG, hypothesis, intervention, assignment, effect, and failure provenance, but no
  code-mechanism artifact.

## Cross-milestone rules

1. Use TDD inside every behavior-changing task: failing focused test, observed RED, minimal
   implementation, observed GREEN, focused regression, commit. Pure synthetic-acceptance or
   documentation-only tasks add and run their gates before committing but do not manufacture a fake
   RED when the already-implemented behavior is correct.
2. Never reuse outcome data while building extractor proposals, Prompt TSGs, feature states,
   `AllowedDelta`, hypotheses, variants, or assignments.
3. Never add a semantic retry. Transport retries must resend identical bytes.
4. Never add per-prompt backend fallback.
5. Never condition the primary ITT denominator on `target_changed` or semantic compliance.
6. Never treat missing/corrupt producers as outcome zero; repair and replay the same manifest.
7. Use the existing `RunStore` lease/seal/transaction contract for every new stage.
8. Keep secrets in environment variables; persist endpoint/template/model/config digests only.
9. Do not create `uv.lock`; this repository continues to test its declared dependency ranges and
   exact causal backend pins directly.
10. Do not begin a later milestone while the current milestone's focused and full gates are red.

## Final verification matrix

Run after M6:

```powershell
uv run --no-project --python 3.12 --with-editable ".[dev,api]" pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not be committed' }
```

Expected:

- all tests pass; only explicitly capability-gated Oracle/RFCI tests skip;
- Ruff, format, compile, CLI registration, and whitespace checks exit zero;
- the minimum test environment starts without Java or py-tetrad;
- `run-all` uses the new M4A → M4B → M5 → M6 order.
