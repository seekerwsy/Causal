# Active Method Specification: Scoped Prompt TSG and Joint Causal Mechanism Discovery

This document is the single normative specification of the active two-stage method on `main`. Chronological pre-consolidation run logs are preserved in [the historical development ledger](experiments/historical-development-ledger-202610-202611.md).

---

## 1. Overview & Scientific Boundaries

`CausalGuide` couples task-grounded semantic graph interventions with Joint Causal Inference (JCI) mechanism discovery and within-task paired counterfactual evaluation:

1. **Stage I — Task-Grounded Graph Representation (`Prompt TSG`)**: Maps source task prompts into a typed semantic graph $G_P$ over operations, shared `data_object` ownership paths (`part_of`), logical conditions, and propositions with tolerant span resolution and local `unresolved` degradation; extracts an 8-bit orthogonal structural mechanism vector $Z = q(G_P, r)$; renders operation-scoped directives $\operatorname{Do}_{\text{TSG}}(G_P, \mathcal{M})$ that protect sibling operation contracts; and splices generated blocks deterministically by AST symbol.
2. **Stage II — Joint Causal Mechanism Discovery & Paired Evaluation**: Under strict task-unit split isolation ($D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$), runs native-Python JCI-12 PAG discovery (`discover_jci_pag(..., context_vars, sink_vars)`) over $(C_{\text{env}}, I, Z, Y_{\text{sec}}, Y_{\text{func}})$ on $D_{\text{disc}} = D_{\text{obs}} \cup D_{\text{probe}}$ to separate genuine causal security drivers from environment/latent-confounded proxies and unscoped scope-bleed hazards, then evaluates all 4 counterfactual arms (`baseline`, `corr_tsg`, `jci_flat`, `jci_tsg`) per held-out task unit on $D_{\text{eval}}$.

### Core Invariants

- **Strict Split Isolation & Temporal Sinks**: `Prompt TSG` edges encode source semantic scope, never causal edges, and raw code ASTs never enter a PAG. Post-generation outcomes $(Y_{\text{sec}}, Y_{\text{func}})$ enter JCI discovery strictly on the disjoint $D_{\text{disc}}$ split as temporal sinks (incoming arrowheads allowed, sink-to-pre-generation tails forbidden). $D_{\text{eval}}$ is never accessed during discovery or policy selection.
- **Within-Task Paired Counterfactual ITT Denominator**: Stateless LLM generation enables matched counterfactual execution of all declared arms on every deduplicated held-out `task_unit_id`. Every committed task $\times$ arm call remains in the ITT denominator (provider errors, code/splice failures $Y_C = 0$, and test failures score as real zero yields).
- **Endpoint Separation**: Security yield $Y_{\text{sec}} = Y_C Y_E \mathbb{I}\{\text{secure}\}$ (evaluated on `target_function` plus intra-module helpers it calls via `evaluate_security_profile(..., target_function=...)`, never penalizing unreferenced sibling operations), deterministic full-module unit-test functionality $Y_{\text{func}}$, code validity $Y_C$, Oracle evaluability $Y_E$, unknown security rate, and confirmed joint yield $Y_{\text{joint}} = Y_C Y_E \mathbb{I}\{\text{sec}\}\mathbb{I}\{\text{func}\}$ are reported separately; `unresolved` or `unknown` is never coerced into `insecure` or `absent`.

---

## 2. Stage I: Prompt TSG, Orthogonal Mechanisms, and Scoped Interventions

1. **Tolerant Span Grounding (`src/tsg/prompt_contract.py`)**: `resolve_evidence_span` matches exact occurrences first, falling back when `tolerant=True` to whitespace-normalized and stripped-backtick matching, rewriting anchored coordinates to exact substrings of $P$. Unanchorable facts and their incident edges degrade locally into `unresolved_semantics` and `unresolved_relations` without aborting valid local bindings.
2. **Orthogonal Structural Mechanism Vector (`src/tsg/source_representation.py`)**: `TSG_ORTHOGONAL_MECHANISM_NAMES` replaces threshold-nested integer cutoffs with eight orthogonal binary mechanisms: `untrusted_input_to_sink`, `shared_object_multi_op`, `component_ownership_chain`, `missing_containment_or_allowlist_guard`, `sibling_format_or_return_contract`, `unscoped_global_restriction`, `ambiguous_or_unresolved_scope`, and `explicit_exception_or_fallback_branch`. Prior-to-Stage-II stability is audited outcome-blindly by `evaluate_binary_attribute_reliability` (`median_flip_rate <= 0.05`).
3. **Scope-Bounded Directive Rendering (`src/tsg/scoped_intervention.py`) & AST Splicing (`src/experiment/code_generation.py`)**: `render_prompt_intervention` renders `baseline` (unchanged prompt), unscoped `flat` ("apply uniformly across the entire module"), and `tsg_scoped` (binding each mechanism strictly to its target `task_operation` and resolved `part_of` ownership path while enumerating sibling operations whose contracts must stay intact). `splice_target_unit_code` extracts one fenced Python code block (no diff/patch arrays) and splices by AST symbol when `target_symbol` is declared.

---

## 3. Stage II: Joint Causal Discovery & Paired Counterfactual Statistics

### Discovery over Observational + Probe Environments

On $D_{\text{disc}}$, context roots combine exogenous environment indicators and intervention probes $C = (C_{\text{env}}, I_1, \dots, I_K, I_{\text{flat}})$ (`context_vars`), while post-generation security and unit-test outcomes act as `sink_vars = (Y_sec, Y_func)`. Inside `discover_jci_pag`, edges incident to $C$ carry root tails $c \to u$ and edges incident to sinks $s \in \text{sink\_vars}$ initialize arrowheads at $s$ ($u *- > s$) while blocking tails from sinks to pre-generation variables (`pag[u, s] = 3` forbidden) and skipping post-generation sinks when d-separating pre-generation pairs.

`classify_jci_mechanisms` checks PAG DAG/context/sink validity and classifies each mechanism $Z_m$:
- **`causal_security_driver`**: definite directed path $Z_m \to^+ Y_{\text{sec}}$ (e.g., via Zhang R1 on $I_m \to Z_m - Y_{\text{sec}}$ when $I_m \perp Y_{\text{sec}} \mid Z_m$) with positive interventional shift $\Delta_{\text{sec}}(I_m) > 0$;
- **`latent_confounded_proxy`**: bidirected collider $Z_k \leftrightarrow Y_{\text{sec}}$ (`pag[Z_k, Y_sec] == 2` and `pag[Y_sec, Z_k] == 2`) arising from $I_k \to Z_k \leftarrow U \to Y_{\text{sec}}$ with $I_k \perp Y_{\text{sec}}$;
- **`environment_confounded_proxy`**: observational association with $Y_{\text{sec}}$ on $D_{\text{obs}}$, separated from $Y_{\text{sec}}$ conditioned on $C_{\text{env}}$;
- **`scope_bleed_hazard`**: directed path or significant negative shift from $I_{\text{flat}}$ / `Z_bleed` onto $Y_{\text{func}}$.

Matched policies compare `jci_policy` (confirmed causal drivers; empty abstention under `null_spurious_only`; `tsg_scoped` mode when scope bleed is detected) against `corr_policy` (top observational correlates).

### Paired Evaluation on Held-Out Tasks

For every held-out task $i \in D_{\text{eval}}$ and comparison $(a, b)$ on endpoint $Y$, unit-level counterfactual differences $d_i = Y_i(a) - Y_i(b)$ cancel baseline task difficulty exactly. `evaluate_paired_counterfactuals` reports full-denominator per-arm ITT rates alongside Student-$t$ intervals, Bonferroni simultaneous intervals across the three primary joint comparisons (`jci_tsg` vs `baseline`, `corr_tsg`, `jci_flat`), exact two-sided binomial sign/McNemar $p$-values, and pairing variance reduction relative to an unpaired equivalent SE.

---

## 4. Independent Verification & Empirical Status

All saved bundles are verified bit-by-bit by `study verify` (`src/verification/mechanism_discovery.py` and `src/verification/natural_study.py`) without importing production experiment or discovery modules:

- **48-Cell Mechanism & Paired Validation (`results/jci-mechanism-paired-validation-20261116`)**: `VERIFIED` across 48 cells (`4,538` CI queries, `summary_sha256: 22320497a4a3894d3601087176449e30340e5abba43c9218851deb4cee0645bb`) in [2026-11-16-jci-mechanism-paired-validation.md](experiments/2026-11-16-jci-mechanism-paired-validation.md). `jci_tsg` outperforms both `corr_tsg` (`+0.127` to `+0.147` joint yield, `9/12`–`11/12` cells significant, `corr` false-discovery `12/12`) and `jci_flat` (`+0.095` to `+0.283` joint yield), achieves `100%` abstention (`0/12` false positives) on `null_spurious_only`, and reduces unpaired variance by `56.5%`–`82.9%`.
- **24-Task Multi-Operation Natural Benchmark Smoke (`configs/jci-natural-task-smoke.json`)**: Offline end-to-end 96-evaluation smoke (`baseline = 0.0`, `corr_tsg = 0.0`, `jci_flat = 0.0`, `jci_tsg = 1.0` joint yield across 6 pure-stdlib `LOCAL_PROFILE_IDS` CWE families + isolated Python unit tests, using target-function-scoped security profiles and operation-agnostic mechanism instructions) passes independent verification (`VERIFIED`); live `local_vllm` pilot config (`configs/jci-local-vllm-pilot.json` + `scripts/run_local_vllm_pilot.sh`) is tested under mocked error/ITT retention and ready for GPU server execution (`formal_claim_allowed = false`).
