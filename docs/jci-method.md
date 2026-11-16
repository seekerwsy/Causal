# Active Method Specification: Task-Grounded Prompt TSG and Directional Cross-Fitted JCI

This document is the single normative specification of the active two-stage method on `codex/jci-framework`. Chronological development records and pre-consolidation run logs are archived in [the historical development ledger](experiments/historical-development-ledger-202610-202611.md).

---

## 1. Overview & Scientific Boundaries

The active framework estimates the causal effect of an explicit, single-requirement prompt intervention on LLM code security while controlling estimation variance across limited target task budgets:

1. **Stage I — Task-Grounded Graph Representation (`Prompt TSG`)**: Maps source inputs and code context into an evidence-verified semantic graph $G_P$, binds candidate requirements to exact operations, objects (including `part_of` ownership paths), and conditions, constructs matched target/reference interventions, and extracts pre-assignment structural attributes $Z = q(G_P, r)$ with graceful local `unresolved` semantics.
2. **Stage II — Context-Anchored Directional JCI & Cross-Fitted Effect Learning**: Runs exogenous-context JCI-12 Partial Ancestral Graph (PAG) discovery over $(C, Z)$, decomposes attributes into directional roles $(V_{\text{root}}, V_{\text{up}}, V_{\text{term}}, V_{\text{other}})$ with role-grouped finite shrinkage and unstructured fallback, and estimates unbiased target effects via task-unit $K$-fold cross-fitted randomized residual scoring.

### Core Invariants

- **Semantic Edges vs. Causal Structure**: `Prompt TSG` edges encode task-local semantic scope, never causal edges. Generated code supplies independently measured outcomes and is never a PAG variable or causal mediator.
- **Assigned-Arm Task-Unit ITT Denominator**: All evaluations operate on independent, deduplicated task units (`task_unit_id`). Every committed assignment remains in its assigned arm; format compliance, generation failure, fidelity, and non-target drift are diagnostics, never denominator filters.
- **Endpoint Separation**: Primary safety yield is $Y = Y_C Y_E\,\mathbb{I}\{\text{Oracle is secure}\}$, where $Y_C$ denotes code validity and $Y_E$ denotes Oracle evaluability. Local functionality, `unknown` outcomes, and joint secure-and-functional success are recorded separately; `unresolved` or `unknown` is never coerced into `absent` or `insecure`.
- **Single-Requirement Scope**: Interventions are Atomic-only (introducing an unexpressed requirement $\mathcal{T}_r^+$, withdrawing an expressed requirement $\mathcal{T}_r^-$, or testing explicit policy restatement `P0/P1`).

---

## 2. Stage I: Task-Grounded Graph Representation (`Prompt TSG`)

For a complete model-visible task input $P$, define the typed semantic graph:

$$G_P = (V, E, \tau_V, \alpha, \epsilon), \qquad E \subseteq V \times \mathcal{R} \times V$$

where $V$ partitions into `task`, `task_operation`, `data_object`, `condition`, and normative proposition nodes (`task_requirement`, `safety_requirement`, `constraint`, `presentation_control`), and $\epsilon$ binds every source-grounded node to character-verified substring spans in $P$.

### Operation Queries, Ownership Paths, and Local Unresolved Preservation

For a proposition $r \in V_{\text{prop}}$, its complete binding readout is:

$$B_G(r) = (\psi_r, \mathcal{O}_r, \mathcal{D}_r, \mathcal{C}_r, \mathcal{S}_r, \epsilon_r)$$

preserving full expression structure $\psi_r$ (negation, disjunctions $c \Rightarrow (q_1 \lor q_2)$, quantifiers), governed operations $\mathcal{O}_r$, subject objects $\mathcal{D}_r$, conditions $\mathcal{C}_r$, scope $\mathcal{S}_r$, and evidence spans $\epsilon_r$. Component ownership paths `(part_of)` connect sub-fields to the actual `used_by` / `produces` participants of an operation $o$ without collapsing distinct subjects across operations. Unbound propositions $\mathcal{U}_G$ remain explicitly separate rather than acquiring an unsupported global scope.

### Stage I $\to$ Stage II Structural Attribute Bridge

Implemented in [source_representation.py](../src/tsg/source_representation.py) (`extract_tsg_structural_attributes`), Stage I extracts task-grounded relational attributes $Z = q(G_P, r)$ prior to assignment $A$:
- `operation_count` and `multi_operation_shared_object` (whether $\ge 2$ operations touch a shared `data_object` or `part_of` chain);
- `max_component_path_depth` (longest `part_of` ownership depth);
- `conditional_or_composite_guard` (presence of explicit condition attachments or composite logical structures);
- `unbound_proposition_count`, `local_binding_complete`, and `local_unresolved_count` (preserving unrelated `unresolved_semantics` / `unresolved_relations` without failing valid local bindings).

Input semantic representation is strictly separated from deterministic target-unit code splicing (`src/tsg/`), preventing fragile output serialization contracts from masking semantic binding effects.

---

## 3. Stage II: Directional JCI & Cross-Fitted Effect Learning

### Target Causal Estimand & Randomized Residual Score

For a fixed generator, target population $T$, and randomized assignment $A_i \in \{0, 1\}$ with $P(A_i = 1) = 1/2$, the target average treatment effect is:

$$\tau_T = \mathbb{E}_T[Y_i(1) - Y_i(0)]$$

**Design condition (D1).** Assignment is either independent Bernoulli$(1/2)$ or completely randomized *within* each cross-fitting fold, and the fold partition is fixed (by task-unit index) before assignment. Completely randomizing across all $n_T$ units without nesting makes $A_i$ weakly dependent on out-of-fold outcomes ($O(1/n_T)$) and voids the exactness claim below; the natural-task assignment protocol must therefore nest randomization blocks inside folds. Implemented in [assignment.py](../src/experiment/assignment.py) (`assign_fold_nested`, sharing `task_unit_folds` with cross-fitting) and replayed independently by [verification/assignment.py](../src/verification/assignment.py).

Given an out-of-fold outcome predictor $\widehat{g}_T^{(-k(i))}(X_i)$ trained without using $A_i$ or any data from fold $I_k$, define the signed randomized residual score:

$$R_i = 2(2A_i - 1)\bigl[Y_i - \widehat{g}_T^{(-k(i))}(X_i)\bigr]$$

Under (D1), $A_i \perp (X_i, Y_i(0), Y_i(1), \widehat{g}_T^{(-k(i))})$ for every $i \in I_k$, so finite-sample unbiasedness holds for any predictor specification and any source/target distribution shift:

$$\mathbb{E}_T[R_i \mid X_i, \widehat{g}_T^{(-k(i))}] = \mathbb{E}_T[Y_i(1) - Y_i(0) \mid X_i], \qquad \operatorname{Var}_T(R_i \mid \widehat{g}_T^{(-k)}) = 4\,\mathbb{E}_T\!\left[(Y - \widehat{g}_T^{(-k)}(X))^2 \mid \widehat{g}_T^{(-k)}\right] - \tau_T^2$$

**Validity–efficiency separation.** Effect validity (unbiasedness, interval coverage) is design-based and never depends on the PAG being correct. The PAG, the role menu, and every source learner act only through the out-of-fold squared error in the variance term. A wrong structure can cost precision; it cannot bias $\widehat{\tau}$. Accordingly, Stage II efficiency claims must include a negative control in which no structural role carries the outcome signal (`misaligned_signal`, §4).

### Operational Variables on Natural Tasks

- **Context $C$**: exogenous, pre-assignment regime indicators that are not caused by any attribute (for example source benchmark family, CWE family, or language), declared before structure learning. JCI-12 requires that $C$ has no ancestors in $Z$; variables that may be affected by prompt content (such as prompt length) are attributes, not contexts.
- **Attributes $Z$**: the Stage I bridge vector `structural_vector` (7 coordinates, including counts). Natural-task structure learning must declare in advance how counts are discretized for the conditional-independence test. The 64-attribute binary simulation is a stress test of the Stage II machinery. It is not a model of the 7-dimensional TSG attribute space, and its results do not transfer to natural tasks.

### Exogenous-Context JCI-12 PAG Discovery & Role Decomposition

Implemented in [jci_structure.py](../src/discovery/jci_structure.py) (`discover_jci_pag`, native Python default with optional `--rscript` R `pcalg 2.7.12` backend), conservative/majority-rule FCI with JCI-12 exogenous context orientation ($C_m \to Z_j$, zero arrowheads into $C$, Zhang 2008 rules R1–R4 and R8–R10) estimates a PAG $\widehat{H}$ over $(C, Z)$ on outcome-free auxiliary observations.

After checking acyclicity, arrowhead-ancestry consistency, and context-exogeneity (`attribute_direction_checks`), definite directed edges $u \to v$ ($\widehat{H}[u, v] = 2 \land \widehat{H}[v, u] = 3$) define the context-reachable cone $\mathcal{R} = \operatorname{Desc}_{G_{\text{dir}}}(C) \setminus C$ and partition attributes $Z$ into four canonical structural roles:

- $V_{\text{root}} = \operatorname{Ch}_{G_{\text{dir}}}(C) \setminus C$: immediate targets of exogenous context variation;
- $V_{\text{term}} = \{v \in \mathcal{R} : \operatorname{Succ}_{G_{\text{dir}}}(v) \cap \mathcal{R} = \emptyset\}$: downstream confluence sinks;
- $V_{\text{up}} = \mathcal{R} \setminus V_{\text{term}}$: context-reachable upstream ancestors;
- $V_{\text{other}} = Z \setminus \mathcal{R}$: latent-confounded or unreached leaves blocked by collider arrowheads.

If $\widehat{H}$ fails direction validity checks, the learner falls back to $V_{\text{other}} = Z$ (uniform weights).

**Status of the roles.** Because $\widehat{H}$ is learned without $Y$, no theorem links a role to prognostic relevance for $Y$. The roles are a small, structure-derived hypothesis menu, and source cross-validation plus target inner cross-validation (with `full_logit` fallback) choose among them. The menu is fixed in this document. Adding a role after observing a simulation failure, as happened with $V_{\text{root}}$ on 2026-11-16, is formative iteration, and any later confirmatory evaluation must freeze the menu beforehand.

### Role-Grouped Finite Shrinkage & Task-Unit $K$-Fold Cross-Fitting

Implemented in [prognostic_learning.py](../src/discovery/prognostic_learning.py):

1. **Source Role-Grouped Shrinkage**: On source data $D_S$, 3-fold stratified cross-validation selects among finite L2-weighted logistic profiles covering `uniform` ($w \equiv 1$, $\gamma = 0$) and `(downstream: V_term, root: V_root, upstream: V_up, reachable: V_term ∪ V_up)` across finite strengths $\gamma \in \{8, 100, 10^6\}$ and inverse penalties $C$:
   $$\min_{\beta_0, \beta} -\ell_{D_S}(\beta_0, \beta) + \frac{1}{2C}\sum_j w_j \beta_j^2, \qquad w_j = \begin{cases} 1, & j \in C \cup V_{\text{active}} \\ 1 + \gamma, & \text{otherwise.} \end{cases}$$
2. **Task-Unit $K$-Fold Cross-Fitting**: Target tasks $D_T$ are partitioned deterministically by index into $K$ folds $I_0, \dots, I_{K-1}$ (never stratified on $A$ or $Y$). On each training complement $D_T^{(-k)}$, deterministic $(K-1)$-fold inner CV chooses between the JCI source predictor and an unweighted `full_logit` fallback along with target Ridge deviation penalty $\eta > 0$:
   $$\widehat{\delta}_k = \arg\min_{\delta} \sum_{i \in D_T^{(-k)}} \bigl[Y_i - \widehat{m}_k(X_i) - \tilde{X}_i^\top \delta\bigr]^2 + \eta \|\delta\|_2^2, \qquad \widehat{g}_T^{(-k)}(x) = \operatorname{clip}_{[0, 1]}\bigl(\widehat{m}_k(x) + \tilde{x}^\top \widehat{\delta}_k\bigr)$$
3. **Scoped Evidence Output**: Confirmed effects (simultaneous intervals evaluated relative to practical margin $m_h > 0$), functionality measurements, Oracle support coverage, and `unknown` rates map directly to scoped guidance distinguishing unconfirmed options, supported findings, endpoint-specific warnings, and adoption recommendations.

---

## 4. Independent Verification & Empirical Status

Every active execution is audited by [src/verification/prognostic_learning.py](../src/verification/prognostic_learning.py) (`study verify`) without sharing production fitting or aggregation helpers, replaying RNG streams, CI permutation queries, PAG role partitions, logistic KKT residuals, Ridge normal equations, Monte Carlo risk integration, and Bonferroni comparisons.

- **Latest Bounded Simulation Validation (`jci-directional-grouped-validation-20261116`)**: Independently verified across 48 cells (`227,250` CI queries, `51` comparisons) in [2026-11-16-jci-grouped-crossfit-results.md](experiments/2026-11-16-jci-grouped-crossfit-results.md). JCI passed `10/10` comparisons in `downstream_signal` (`+13.06%` to `+17.57%` variance reduction), had no supported harm in `upstream_control` (`upstream_harm_count = 0`, `+2.53%` to `+16.79%`, passing `7/10`; this followed the post-hoc addition of $V_{\text{root}}$ and is formative), and remained positive across all `target_new_attribute` baselines (`+2.25%` to `+5.33%`).
- **Formative Stress Tests (`jci-directional-negative-control-20261116`, `jci-directional-measurement-noise-20261116`)**: 64 verified cells each, reported in [2026-11-16-negative-control-and-measurement-noise.md](experiments/2026-11-16-negative-control-and-measurement-noise.md). On the `misaligned_signal` negative control, JCI reduces to `full_logit` (`0/10` supported, `0` harms). At 10% attribute flips, `primary_passed = 0/28` and `downstream_gate_passed = false`, with `0` supported harms. The advantage over the undirected skeleton is supported only in `downstream_signal`. Stage I attribute reliability is therefore a precondition for Stage II efficiency claims.
- **Prior Frozen Round 1 Baseline (`jci-robustness-round1-20261103`)**: 384 frozen simulation units retained read-only under [2026-11-05-graph-jci-joint-results.md](experiments/2026-11-05-graph-jci-joint-results.md) (`reference` `downstream_signal` `+12.51%` to `+18.38%`, `upstream_control` negative transfer prior to `2026-11-16` role-grouped upgrade).
- **Local-Model Execution Status**: Bounded natural-task model runs (`2026-11-05` 240-call unified-diff evaluation and `2026-11-08`/`2026-11-10` 6-call qualification gates) remain frozen under [historical-development-ledger-202610-202611.md](experiments/historical-development-ledger-202610-202611.md) with `formal_claim_allowed = false`.
