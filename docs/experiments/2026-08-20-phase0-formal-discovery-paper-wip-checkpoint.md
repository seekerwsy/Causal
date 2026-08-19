# Phase 0 Formal Discovery and Paper Alignment WIP Checkpoint

Date: 2026-08-20 (Asia/Shanghai)

## Repository state

- Worktree: `D:/MyCode/Causal/.worktrees/dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent commit: `87af75a`
- Purpose: preserve all current local work before continuing Phase 0 closure.
- Status: WIP only. This checkpoint is not a Phase 0 acceptance decision and
  does not authorize Phase 1, paid API calls, remote model runs, or scientific
  claims.

## Saved scope

- Task-by-realization-by-arm variant evidence, including replay of the existing
  graph-delta validator, context and non-target invariants, length-matched
  placebo checks, digest-bound task-arm records, and complete retained support.
- Protocol-freeze integration of the variant-evidence manifest.
- A two-input formal-confirmation implementation boundary that accepts the
  frozen experiment and run evidence, derives contribution artifacts from
  provenance-closed coverage, and prepares the four frozen analysis families.
- Multi-support H-by-model simultaneous inference refinements needed by that
  formal entry point.
- A target-independent observational FCI/background-knowledge implementation
  boundary using authenticated natural tables and explicit raw/minimal/full
  PAG artifacts.
- Partial manuscript alignment to the approved context-conditioned,
  intervention-policy framing. The RQ/evaluation rewrite, paper contract,
  compilation, and visual review are not yet complete.

## Validation performed before checkpoint

All commands used the worktree-local Python 3.12 environment.

- Variant evidence: `11 passed in 73.58s`.
- Minimal protocol-root JSON replay: `1 passed in 48.76s`.
- Variant/protocol slice: Python compilation, Ruff, and diff checks passed.
- Formal-confirmation five-file slice: Python compilation and Ruff passed.
- Observational-discovery three-file slice: Python compilation, Ruff, and diff
  checks passed; a small authenticated FIXED_REFERENCE FCI/BK smoke run
  returned a suite artifact and one deletion delta.
- Repository `git diff --check`: passed, with Windows line-ending warnings only.
- No full repository suite, external API call, remote model run, or paid
  experiment was performed.

## Known incomplete or non-accepting items

- Formal-confirmation end-to-end and adversarial tests have not yet been added.
- An existing run-evidence fixture has not yet been migrated to the new required
  `variant_evidence` protocol-root argument.
- Observational discovery lacks formal pytest coverage for true-chain, latent
  confounding, null, deterministic-JCI appendix behavior, two-level bootstrap,
  JSON replay, and synchronized-substitution attacks.
- Variant evidence has a directed ADD fixture; REMOVE follows the same validator
  path but still needs its own directed test. Failed bundle attempts are not yet
  preserved as fine-grained per-arm receipts.
- The manuscript is deliberately saved mid-revision. Its three-RQ contract,
  stale-term audit, LaTeX build, and rendered-page visual inspection remain
  outstanding.
- None of the saved artifacts may be promoted to formal evidence until the
  missing tests and the independent Phase 0 completion audit pass.
