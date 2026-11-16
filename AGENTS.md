# Project-Level Agent Instructions

## Active Scope & Two Core Contributions

Prompt Mechanism Study (`CausalGuide`) is an academic research project investigating task-grounded prompt representations and causal mechanism discovery for secure LLM code generation. The active method on `main` centers on two coupled contributions, normatively specified in [docs/jci-method.md](docs/jci-method.md):

1. **Contribution 1 — Task-Grounded Graph Representation (`Prompt TSG`)**: Scoped representation of `task_operation`, `data_object` (including `part_of` component ownership paths), `condition`, and normative `proposition` nodes with tolerant character-verified span resolution and local `unresolved` degradation; an 8-predicate orthogonal structural mechanism vector `Z = q(G_P, r)` (`TSG_ORTHOGONAL_MECHANISM_NAMES`); scope-bounded prompt intervention rendering (`render_prompt_intervention`: `baseline` vs unscoped `flat` vs `tsg_scoped` preserving sibling contracts); and deterministic AST target-unit code splicing (`splice_target_unit_code`).
2. **Contribution 2 — Joint Causal Mechanism Discovery & Paired Counterfactual Evaluation**: Strict task-unit split isolation between Discovery ($D_{\text{disc}} = D_{\text{obs}} \cup D_{\text{probe}}$) and Held-Out Evaluation ($D_{\text{eval}}$, $D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$). On $D_{\text{disc}}$, native-Python JCI-12 Partial Ancestral Graph (PAG) discovery (`discover_jci_pag(..., sink_vars=...)`) runs over exogenous contexts & intervention probes $C = (C_{\text{env}}, I)$, orthogonal TSG mechanisms $Z$, and post-generation outcome sinks $Y = (Y_{\text{sec}}, Y_{\text{func}})$ with temporal sink orientation, classifying mechanisms into causal security drivers, environment-confounded proxies, latent-confounded proxies, and unscoped functionality scope-bleed hazards. On $D_{\text{eval}}$, matched counterfactual arms (`baseline`, `corr_tsg`, `jci_flat`, `jci_tsg`) are evaluated under Within-Task Paired Counterfactual ITT using local AST security profiles ($Y_{\text{sec}}$) and isolated Python unit tests ($Y_{\text{func}}$).

The single active CLI entry point is `python -m prompt_mechanism_study study` (`smoke`, `natural-smoke`, `run`, `verify`, `inspect-tsg`). Superseded multi-track prototypes, unpaired prognostic shrinkage modules, schema-3 gate modules, and legacy v3 drafts remain read-only under `archive/`, `configs/archive/`, `docs/experiments/`, `data/method/`, and `results/`. Formal natural-task protocol activation remains `SPECIFIED_DRAFT` (`formal_claim_allowed=false`) until prospectively authorized and frozen.

## Scope and Precedence

These instructions apply to the entire repository. Descendant `AGENTS.md` files may add narrowly scoped requirements, but they must not weaken or contradict these repository-wide constraints. Make any conflict explicit before proceeding.

## Core Scientific Invariants

1. **One Active Normative Path**: Maintain `docs/jci-method.md` solely as the normative specification of the active two-stage method. Keep chronological development ledgers, run reports, and historical SHA-256 inventories in `docs/experiments/` rather than appending historical logs to `README.md` or `docs/jci-method.md`.
2. **Semantic Edges vs. Causal Sinks & Strict Split Isolation**: `Prompt TSG` edges encode task-local semantic scope, never causal edges, and raw generated code ASTs never enter a PAG. Independently measured outcomes $(Y_{\text{sec}}, Y_{\text{func}})$ may enter JCI PAG discovery strictly on the disjoint Discovery split ($D_{\text{disc}}$) as post-generation temporal sinks (incoming arrowheads permitted, outgoing tails into pre-generation variables forbidden); $D_{\text{eval}}$ outcomes are never inspected during discovery or policy selection.
3. **Within-Task Paired Counterfactual ITT Denominator**: Perform evaluation on independent, deduplicated task units (`task_unit_id`) keeping every committed task x arm evaluation in its full paired ITT denominator across all declared arms (`baseline`, `corr_tsg`, `jci_flat`, `jci_tsg`). Provider timeouts, format/splicing failures ($Y_C = 0$), and test failures are retained as real zero yields rather than filtered post hoc.
4. **Endpoint Separation**: Keep security yield ($Y_{\text{sec}} = Y_C Y_E \mathbb{I}\{\text{secure}\}$), deterministic unit-test functionality ($Y_{\text{func}}$), code validity ($Y_C$), Oracle evaluability ($Y_E$), unknown security coverage, and confirmed joint success ($Y_{\text{joint}} = Y_C Y_E \mathbb{I}\{\text{sec}\}\mathbb{I}\{\text{func}\}$) explicitly separated. Never coerce `unresolved` or `unknown` into `absent` or `insecure`.
5. **Scope-Bounded Multi-Operation Interventions**: Active interventions operate through graph-scoped bindings $\operatorname{Do}_{\text{TSG}}(G_P, \mathcal{M})$ over multi-operation `task_operation`, `data_object` (`part_of`), and `condition` targets while explicitly protecting sibling operation contracts. Legacy Atomic-only pair research remains archived at tag `archive/pair-interaction-20260916` (commit `e6833027` / `40db3526`).
6. **Independent Result Verification**: Active simulation and natural-task pipelines retain independent verifiers (`study verify`) that replay RNG streams, CI tests, PAGs, mechanism classifications, TSG compilations, AST splices, AST security profiles, isolated unit tests, and paired statistical intervals without sharing production fitting or aggregation logic.

## Formative Engineering vs. Prospective Confirmatory Evaluation

Keep engineering overhead proportional to scientific value by separating two regimes:

- **Formative Engineering & Method Iteration** (within exposed development material, simulations, unit tests, and bounded local pilots): Iterate directly in Git with focused tests, `study smoke`, `study natural-smoke`, and `study verify`. **Do not** mint new SHA-256 freeze packages or chronological failure bulletins in `README.md` / `docs/jci-method.md` for local software edits.
- **Prospective Confirmatory Evaluation** (protected or pre-registered natural-task cohorts and formal method benchmarks): Freeze task splits ($D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$), benchmarks, mechanism policies, endpoints, and comparison families before held-out generation access; preserve full paired ITT denominators without post-hoc task filtering or replacement; and never overwrite frozen archives.

## Implementation, Reviewability & Testing

1. **Minimal Linear Implementation**: Keep active scientific code compact, deterministic, and inspectable within `src/`: `tsg/` (Stage I representation, tolerant contract compilation, orthogonal attributes, scoped intervention rendering), `discovery/` (Stage II JCI PAG with temporal sinks and causal mechanism discovery), `experiment/` (end-to-end natural runner, AST code splicing, outcomes), `measurement/` (AST security profiles, isolated Python unit-test Oracle, optional blinded functional judge), `verification/` (independent replay), and `cli.py` / `llm.py`. Every module in `src/` must be reachable from `cli.py` or default `pytest`.
2. **Double-Anonymous Hygiene**: Never hardcode personal filesystem paths or user handles. Use `$STUDY_ROOT` when documenting server execution paths.
3. **Review Guide & Core Reading Order**: Maintain `docs/reviewer-guide.md` identifying the active CLI entry point, stage invariants, reproduction commands, and a reading order of at most ten core files.
4. **Default Test Suite (`tests/jci/`, `tests/substrate/`)**: Run focused tests during edits, and run full `pytest` plus `smoke` / `natural-smoke` verification after final changes.

## Research Integrity & Manuscript Alignment

1. Distinguish `specified`, `implemented`, `tested`, `executed`, and `reported`. Simulation and offline/pilot runs do not constitute prospective formal confirmatory claims (`formal_claim_allowed=false`).
2. Harmonize contribution framing with `paper/AGENTS.md`: organize research questions and ablations around verified core strengths (`Prompt TSG` anti-bleed operation scoping + JCI causal deconfounding over paired counterfactual evaluation), faithfully reporting complete ITT denominators, verified artifact digests, and negative controls (`null_spurious_only`) using `\textit{TBD}` (`\pendingresult`) wherever prospective experiments have not yet run.
3. Never fabricate or extrapolate unprinted numbers, and compile and visually inspect LaTeX PDFs after any manuscript edit.
