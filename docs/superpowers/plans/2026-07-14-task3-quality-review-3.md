# Task 3 Quality Review 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Task 3 execution provenance, graph-renderer policy, and deterministic matched-length/no-op gaps without implementing Task 4.

**Architecture:** `InterventionExecutionRequest` becomes the complete authenticated execution envelope and `_trusted_request` reconstructs every semantic and prompt/graph artifact from authoritative inputs. Graph-native execution accepts only the two locked renderer classes and binds the renderer policy before and after the call. The immutable FeatureSpec catalog owns finite neutral matched-control length buckets; the deterministic executor chooses the closest feasible clause by a versioned stable rule.

**Tech Stack:** Python 3.11+, Pydantic v2, NetworkX Prompt TSG queries, pytest, Ruff.

---

### Task 1: Close execution provenance

**Files:**
- Modify: `tests/m5_executor_fixtures.py`
- Modify: `tests/test_intervention_executors.py`
- Modify: `tests/test_llm_intervention_security.py`
- Modify: `src/secaware/intervention/executors.py`

- [x] Add fixture-owned `FrozenHypothesisRecord`, complete prompt bundle, optional functional contract, and exact extraction proposal/graph pair.
- [x] Add failing tests for stale/missing hypothesis bindings, contract swaps, ghost peers, same-ID changed content/proposals, graph coordinates, transition current states, and counterpart coordinates.
- [x] Run the focused tests and confirm they fail at execution rather than fixture construction.
- [x] Deep-revalidate all four new fields; reconstruct target, protocol, target instance and protocol instance; validate/rebuild proposal and graph; query every transition's actual state.
- [x] Re-run the focused tests and preserve fatal exceptions while sanitizing ordinary failures.

### Task 2: Lock graph renderers and their policies

**Files:**
- Modify: `tests/test_graph_native_intervention.py`
- Modify: `src/secaware/intervention/executors.py`

- [x] Add failing tests rejecting callback/duck-typed renderers, subclasses, and zero/mutated policy hashes.
- [x] Add failing tests proving renderer and transport mutation rejection, ordinary error sanitization, and fatal passthrough.
- [x] Run the graph-native tests and confirm the attacks currently succeed.
- [x] Remove the public renderer protocol; require exact deterministic or LLM renderer types; expose read-only `policy_sha256`; compare the frozen policy to the candidate after rendering.
- [x] Re-run the graph-native and LLM security tests.

### Task 3: Make deterministic matched lengths feasible

**Files:**
- Modify: `tests/test_prompt_feature_catalog.py`
- Modify: `tests/test_deterministic_catalog_backend.py`
- Modify: `tests/test_intervention_executors.py`
- Modify: `src/secaware/tsg/feature_catalog.py`
- Modify: `src/secaware/intervention/executors.py`

- [x] Add failing catalog tests requiring versioned finite neutral unique clauses for the three matched-control FeatureSpecs and catalog-digest closure.
- [x] Add failing all-target ADD/REMOVE tests using Task 4's canonical UTF-8 changed-span footprint and `max(4, ceil(reference * 0.05))` tolerance.
- [x] Add failing tests for REMOVE sham retention, deterministic no-op rewrite byte change, other no-op byte retention, and no feasible clause fail-closed behavior.
- [x] Run all three RED groups and record the expected failures.
- [x] Add reviewed finite length buckets, bump the catalog version, and implement closest-clause stable selection from the target reference span.
- [x] Implement the versioned one-newline `NOOP_REWRITE` rule and include both rules in the deterministic policy hash.
- [x] Re-run Task 3, Task 1/2, catalog/extractor, M4A/M4B, and pre-Task4 length compatibility suites.

### Task 4: Verify and commit

**Files:**
- Verify all modified files above.

- [x] Run full pytest, Ruff check/format, compileall, diff-check, CLI help, and lockfile checks.
- [ ] Inspect the staged diff and commit only Task 3 review changes as an independent commit.
- [ ] Confirm the worktree is clean and report RED, GREEN, full-suite, and commit-hash evidence.
