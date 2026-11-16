# Project-Level Agent Instructions

## Active Scope & Two Core Contributions

Prompt Mechanism Study is an academic research project investigating requirement-level causal effects and guidance for LLM code generation. The active method on `codex/jci-framework` centers on two complementary contributions, normatively specified in [docs/jci-method.md](docs/jci-method.md):

1. **Contribution 1 — Task-Grounded Graph Representation (`Prompt TSG`)**: Scoped representation of `task_operation`, `data_object` (including `part_of` component ownership paths), `condition`, and normative `proposition` nodes with character-verified evidence spans; pre-assignment structural attribute extraction `Z = q(G_P, r)` with graceful local `unresolved` semantics; and clean separation of input semantic representation from deterministic target-unit code splicing.
2. **Contribution 2 — Context-Anchored Directional JCI & Cross-Fitted Effect Learning**: Exogenous-context JCI-12 Partial Ancestral Graph (PAG) discovery over Prompt-TSG attributes, directional PAG role decomposition `(V_root, V_up, V_term, V_other)` with role-grouped finite shrinkage and unstructured fallback, and task-unit K-fold cross-fitted randomized residual scoring (`R_i`).

The single active CLI entry point is `python -m prompt_mechanism_study study` (`smoke`, `run`, `verify`, `inspect-tsg`). Superseded multi-track prototypes remain archived under `archive/legacy_jci_20261116/` and `configs/archive/legacy_jci_20261116/`, and historical experimental records remain read-only under `docs/experiments/`, `data/method/`, and `results/`. Formal natural-task protocol activation remains `SPECIFIED_DRAFT` (`formal_claim_allowed=false`) until prospectively authorized and frozen.

## Scope and Precedence

These instructions apply to the entire repository. Descendant `AGENTS.md` files may add narrowly scoped requirements, but they must not weaken or contradict these repository-wide constraints. Make any conflict explicit before proceeding.

## Core Scientific Invariants

1. **One Active Normative Path**: Maintain `docs/jci-method.md` solely as the normative specification of the active two-stage method. Keep chronological development ledgers, run reports, and historical SHA-256 inventories in `docs/experiments/` rather than appending historical logs to `README.md` or `docs/jci-method.md`.
2. **Semantic Edges vs. Causal Structure**: `Prompt TSG` edges encode task-local semantic scope, not causal edges. Generated code supplies independently measured security and functionality outcomes; it is never a PAG variable or causal mediator.
3. **Assigned-Arm Task-Unit ITT Denominator**: Perform confirmatory and simulation comparisons on independent, deduplicated task units (`task_unit_id`, historically `semantic_cluster_id`) keeping every committed assignment in its assigned arm. Post-assignment fidelity, format compliance, generation success, and non-target drift are diagnostics, never denominator filters.
4. **Endpoint Separation**: Keep the primary safety endpoint, oracle-evaluable secure-code yield (`Y = Y_C * Y_E * I{secure}`), distinct from code validity (`Y_C`), Oracle evaluability (`Y_E`), unknown coverage, local/task functionality, and joint secure-and-functional success. Never coerce `unresolved` or `unknown` into `absent` or `insecure`.
5. **Single-Requirement Scope**: Keep the active path Atomic-only (one requirement intervention `T_r+`, `T_r-`, or explicit policy expression `P0/P1` per policy). Pair interaction research remains on `codex/pair-interaction-research` at `e6833027`, and context-modifier inference stays inactive until prospectively frozen.
6. **Independent Result Verification**: Active simulation and preparation pipelines must retain an independent verifier (`study verify`) that replays RNG streams, CI tests, PAG/role structure, convex KKT / normal-equation solutions, and statistical intervals without sharing production fitting or aggregation logic.

## Formative Engineering vs. Prospective Confirmatory Evaluation

Keep engineering overhead proportional to scientific value by separating two regimes:

- **Formative Engineering & Method Iteration** (within exposed development material, simulations, unit tests, and interface debugging): Iterate directly in Git with focused tests, `study smoke`, and `study verify`. **Do not** mint new SHA-256 freeze packages, `.artifacts/` staging trees, or chronological failure bulletins in `README.md` / `docs/jci-method.md` for local software bugfixes or schema/interface repairs.
- **Prospective Confirmatory Evaluation** (protected or pre-registered natural-task cohorts and formal method benchmarks): Freeze task splits, realizations, candidate nominations, endpoints, comparison families, and budgets before outcome access; preserve full assigned-arm denominators without post-hoc task filtering or replacement; and never overwrite frozen result archives.

## Implementation, Reviewability & Testing

1. **Minimal Linear Implementation**: Keep active scientific code compact, deterministic, and inspectable within `src/`. That tree holds only the two contributions plus the natural-task substrate they need: `tsg/` (Stage I representation, extraction, intervention construction), `discovery/` (Stage II), `experiment/` (fold-nested assignment, generation, endpoint decomposition), `measurement/` (Oracle and functionality), `verification/` (independent replay), and `cli.py`. A module may live in `src/` only if the CLI or the default test suite reaches it. Superseded pipelines go to `archive/` (see `archive/legacy_pipeline_20261116/` for the schema-3 selector pipeline) and are excluded from default imports and tests.
2. **Double-Anonymous Hygiene**: Never hardcode personal filesystem paths or user handles (such as `/home/<user>`). Use `$STUDY_ROOT` (with `inputs`, `results`, `archive` subdirectories) when documenting server execution paths.
3. **Review Guide & Core Reading Order**: Maintain `docs/reviewer-guide.md` identifying the active CLI entry point, stage invariants, reproduction commands, and a reading order of at most ten core files.
4. **Default Test Suite (`tests/jci/`, `tests/substrate/`)**: `tests/jci/` covers the scientific invariants: causal boundaries, PAG orientation and role decomposition, zero-leakage cross-fitting unbiasedness, fold-nested assignment (D1), endpoint separation, TSG scope/attribute extraction, and end-to-end smoke plus independent verification. `tests/substrate/` covers Stage I extraction/qualification and Oracle profiles. Run focused tests during edits, and run full `pytest` plus smoke verification after final changes.

## Research Integrity & Manuscript Alignment

1. Distinguish `specified`, `implemented`, `tested`, `executed`, and `reported`. Simulation, smoke, and canary runs do not constitute natural-task or provider confirmatory claims.
2. Harmonize contribution framing with `paper/AGENTS.md`: when structuring or revising manuscript prose, frame research questions and comparisons around verified core strengths (`Prompt TSG` multi-operation scoping and Directional Cross-Fitted `JCI`) rather than chronological failures. At the same time, for every frozen study or table cited in a paper or report, faithfully report complete ITT denominators, verified artifact bindings, and observed applicability boundaries (including negative or null regimes such as weak context or misspecified roles), using `\textit{TBD}` (`\pendingresult`) wherever formal natural-task experiments have not yet run.
3. Never fabricate or extrapolate unprinted numbers, and compile and visually inspect LaTeX PDFs after any manuscript edit.
