# Next-Phase Implementation & Empirical Validation Task Specification (DeepSeek Handoff)

> **Baseline Checkpoint**: `main` at commit `3678a7d3`  
> **Normative Method Spec**: [docs/jci-method.md](../jci-method.md)  
> **Governance & Invariants**: [AGENTS.md](../../AGENTS.md) · [paper/AGENTS.md](../../paper/AGENTS.md) · [paper/fse2027/AGENTS.md](../../paper/fse2027/AGENTS.md)

---

## 0. Current Baseline & Non-Negotiable Scientific Invariants

### 0.1 Verified Baseline State (`3678a7d3`)

| Artifact / Suite | Status / Metric | Key Pointer |
| --- | --- | --- |
| Default Test Suite (`pytest -q`) | `48 passed` | `tests/jci/`, `tests/substrate/` |
| Single CLI Entry Point | `python -m prompt_mechanism_study study` (`smoke`, `natural-smoke`, `run`, `verify`, `inspect-tsg`) | [src/cli.py](../../src/cli.py) |
| Stage I: Prompt TSG & Target-Scoped Oracles | Tolerant `compile_source_propositions(..., tolerant=True)`, 8-bit `TSG_ORTHOGONAL_MECHANISM_NAMES`, `render_prompt_intervention` (`baseline` / `flat` / `tsg_scoped`), `splice_target_unit_code`, target-scoped `evaluate_security_profile(..., target_function=...)`, isolated `evaluate_python_unit_tests` (`python -I`) | [src/tsg/](../../src/tsg/scoped_intervention.py), [src/measurement/](../../src/measurement/security_profiles.py) |
| Stage II: Temporal-Sink JCI & Paired ITT | `discover_jci_pag(..., context_vars, sink_vars)`, `classify_jci_mechanisms`, `evaluate_paired_counterfactuals` | [src/discovery/](../../src/discovery/mechanism_discovery.py) |
| Verified 48-Cell Validation | `VERIFIED` (`48/48` cells, `4,538` CI queries, `summary_sha256: 22320497a4a3894d3601087176449e30340e5abba43c9218851deb4cee0645bb`) | [configs/jci-mechanism-validation.json](../../configs/jci-mechanism-validation.json) |
| Verified 24-Task / 96-Call 32B Evaluation | `VERIFIED` (`n_eval_tasks=24`, `96` live calls, `jci_tsg=0.917` vs `baseline=0.292`, `corr_tsg=0.000`, `jci_flat=0.125`, `summary_sha256: acffe592bf0d9cc171000fc22488f29b21ad7b8b71e7efb3934b2f1215afa870`, `formal_claim_allowed=false`) | [configs/jci-local-vllm-pilot.json](../../configs/jci-local-vllm-pilot.json) |
| ACM TOSEM Manuscript Draft | 12-page PDF (`latexmk`) synchronized to Direction 1; prospective multi-model / external repo cells marked `\pendingresult` | [paper/fse2027/main.tex](../../paper/fse2027/main.tex) |

### 0.2 Hard Scientific & Engineering Constraints (Must Not Violate)

1. **Strict Split Isolation ($D_{\text{disc}} \cap D_{\text{eval}} = \emptyset$)**: Every discovery task unit must be strictly disjoint from every held-out evaluation task unit; $D_{\text{eval}}$ outcomes must never inform mechanism selection or policy synthesis.
2. **Full Paired ITT Denominator**: Retain 100% of committed `(task_unit_id, arm)` assignments across all arms. `ProviderError`, extraction/AST splicing errors ($Y_C = 0$), timeouts, and unit-test failures remain real zero yields—never drop or replace failed tasks post hoc.
3. **Endpoint Separation & No Coercion**: Keep $Y_C$ (`code_valid`), $Y_E$ (`oracle_evaluable`), `unknown` security rate, $Y_{\text{sec}}$, $Y_{\text{func}}$, and $Y_{\text{joint}}$ separated; never coerce `unresolved` or `unknown` into `insecure` or `absent`.
4. **Target-Scoped Security + Module Functional Checks**: Security AST auditing uses `evaluate_security_profile(..., target_function=...)` (target function + intra-module call/load closure); unit tests run full-module behavior in `python -I`.
5. **Independent Bit-Exact Verification (`study verify`)**: Every new mechanism, baseline arm, benchmark cohort, or empirical $D_{\text{disc}}$ bundle must be independently replayed by `src/verification/` without importing production discovery/experiment modules.
6. **Double-Anonymous & Environment Hygiene**: Never write personal filesystem paths, server hostnames, or user handles into tracked files; always write `$STUDY_ROOT` and pass endpoints via `LOCAL_VLLM_BASE_URL` / `LOCAL_VLLM_MODEL_ID`. Never overwrite existing `results/` directories or interfere with active GPU jobs belonging to other processes.

---

## 1. Objective of This Phase

While `baseline`, `corr_tsg`, `jci_flat`, and `jci_tsg` already establish the primary leave-one-out ablation of both core contributions, three targeted upgrades will elevate the empirical evaluation to review-proof journal strength:

1. **Zero-GPU Sub-Ablations (`WP1`)**: Prove within Stage II why *full* JCI-12 PAG discovery (rather than environment stratification or no-latent-confounder PC DAG discovery) is needed to defeat $Z_{\text{lat}}$, and prove within Stage I why `Prompt TSG`'s full binding (`part_of` ownership + sibling exemptions) outperforms bare function-name binding (`op_only`).
2. **Empirical LLM-Generated Discovery Cohort (`WP2`)**: Replace synthetic $D_{\text{disc}}$ binary rows with genuine LLM-generated $(C_{\text{env}}, I, Z, Y_{\text{sec}}, Y_{\text{func}})$ trajectories from 36 disjoint multi-operation Discovery tasks, plus an automated Stage I raw-prompt proposition extraction audit.
3. **Multi-Model Held-Out Generalization & Manuscript Sync (`WP3`–`WP4`)**: Evaluate across at least two generator scales/families (`7B`/`14B` + `32B`) on verified 5-arm cohorts, independently verify every bundle, and update [sections/04-evaluation.tex](../../paper/fse2027/sections/04-evaluation.tex) and PDF compilation.

---

## 2. Work Package 1 (`WP1`): Sub-Component & Causal-Baseline Ablations (Zero GPU Cost)

### 2.1 `WP1.1` — Stage II Causal Discovery Sub-Ablation (`env_adj_policy` & `pc_dag_policy`)

**Goal**: Show cleanly in the 48-cell benchmark why neither environment covariate adjustment alone nor standard causal-sufficiency DAG discovery (PC) suffices once unobserved task confounding ($U \to Y_{\text{sec}}, U \to Z_{\text{lat}}$) is present.

**Files to Edit**:
- [src/discovery/mechanism_discovery.py](../../src/discovery/mechanism_discovery.py)
- [src/verification/mechanism_discovery.py](../../src/verification/mechanism_discovery.py)
- [tests/jci/test_mechanism_discovery.py](../../tests/jci/test_mechanism_discovery.py)

**Concrete Implementation Requirements**:
1. Inside `classify_jci_mechanisms` (keeping all existing keys untouched for backward compatibility), compute two additional comparison policies on `data`:
   - `env_adj_policy`: Estimate the `C_env`-stratified observational association on `obs_data` for each `mech in mechanism_vars` (weighted risk difference across `C_env=0` and `C_env=1` strata using inverse-variance / Mantel–Haenszel weighting and exact combined stratum variance test). Select the top-ranked positive mechanism passing the adjusted threshold (same `corr_budget = max(1, len(jci_selected))`), abstaining only when no adjusted association reaches `abs(adj_delta) >= min_corr or adj_p <= alpha`.
   - `pc_dag_policy`: Treat observational/interventional correlations without bidirected collider rejection—i.e., retain any mechanism associated with `Y_sec` conditioned on `C_env` that lacks an observed decoupling separator, matching what a non-latent DAG learner fails to isolate under `Z_lat <-> Y_sec` when probe invariance (`I_lat -> Z_lat <- U -> Y_sec`) is ignored. Record both `env_adj_policy` and `pc_dag_policy` selected mechanisms, plus paired counterfactual evaluation arms (`env_adj_tsg`, `pc_tsg`) behind an optional plan flag `"include_causal_subablations": true`.
2. Mirror exact independent recomputation of `env_adj_policy` / `pc_dag_policy` inside [src/verification/mechanism_discovery.py](../../src/verification/mechanism_discovery.py) (zero shared imports with `src/discovery/mechanism_discovery.py`).
3. Create config `configs/jci-mechanism-subablation.json` enabling `"include_causal_subablations": true` across all 4 scenarios (`confounded_and_scoped`, `pure_latent_trap`, `multi_op_high_interference`, `null_spurious_only`).

**Expected Empirical Signature & Verification**:
- In `null_spurious_only` and `pure_latent_trap`, `env_adj_policy` rejects $Z_{\text{env}}$ yet still falsely selects latent-confounded $Z_{\text{lat}}$ (`> 80%` false-discovery cells), while `jci_policy` maintains **`0/12`** false discoveries and **`100%`** null abstention.
- Run and verify:
  ```bash
  export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
  python -m prompt_mechanism_study study run results/jci-mechanism-subablation-YYYYMMDD --plan configs/jci-mechanism-subablation.json --workers 4
  python -m prompt_mechanism_study study verify results/jci-mechanism-subablation-YYYYMMDD --workers 4
  ```

### 2.2 `WP1.2` — Stage I `Prompt TSG` `op_only` Sub-Ablation & Import/Path Prompt Fixes

**Goal**: Isolate the marginal contribution of `Prompt TSG`'s full scoping (`part_of` component paths + explicit sibling exemption clauses) relative to bare function-name binding (`op_only`), and eliminate the two minor generation/test edge cases observed on `jci_tsg` (`22/24` in the 32B run).

**Files to Edit**:
- [src/tsg/scoped_intervention.py](../../src/tsg/scoped_intervention.py)
- [src/experiment/natural_study.py](../../src/experiment/natural_study.py)
- [src/verification/natural_study.py](../../src/verification/natural_study.py)
- [tests/jci/test_mechanism_discovery.py](../../tests/jci/test_mechanism_discovery.py)
- [tests/jci/test_natural_study.py](../../tests/jci/test_natural_study.py)

**Concrete Implementation Requirements**:
1. Extend `VALID_INTERVENTION_MODES` in `src/tsg/scoped_intervention.py` to `("baseline", "flat", "op_only", "tsg_scoped")`:
   - When `mode == "op_only"`, resolve `op_local = mech.get("operation_local_id")` and render only the bare function-level line `- Target function {op_local}: {instruction}.` **without** appending `part_of` ownership chains, condition labels, or protected sibling contract bullets (`"protected_siblings": []`, `"scope_boundary": "operation_name_only"`).
2. In `tsg_scoped` rendering, add one explicit import-hygiene sentence alongside sibling preservation:
   `"Retain all top-level module imports still referenced by preserved sibling operations (for example, keep `import random` when a sibling deterministic function uses `random.Random`)."`
3. In `src/experiment/natural_study.py` and `src/verification/natural_study.py`, support optional `"include_op_only_arm": true` in natural-task plans (default `false` so existing 4-arm smoke/contracts remain 100% backward compatible). When `true`, evaluate the 5th arm `jci_op_only` (`mode="op_only"`, `jci_selected`) and add paired comparison `jci_tsg_vs_jci_op_only` on `joint` and `functionality`.

---

## 3. Work Package 2 (`WP2`): Empirical LLM-Generated Discovery Cohort ($D_{\text{disc}}$) & Extraction Audit

**Goal**: Replace synthetic discovery sampling rows with **real LLM-generated Stage II discovery trajectories**, eliminating any concern that Stage II was tested only on structural-equation samples.

### 3.1 `WP2.1` — 36-Task Disjoint Empirical Discovery Benchmark

**Files to Create / Edit**:
- New benchmark fixture: `src/fixtures/natural-empirical-jci-benchmark.json` (plus generator script if kept outside `src/` or tested deterministically)
- New plan config: `configs/jci-empirical-discovery-pilot.json`
- Runner & verifier extensions: [src/experiment/natural_study.py](../../src/experiment/natural_study.py), [src/verification/natural_study.py](../../src/verification/natural_study.py), [src/measurement/unit_test_oracle.py](../../src/measurement/unit_test_oracle.py)

**Benchmark Design Specifications**:
1. **Strict Split Disjointness**: Author **36 legacy multi-operation Python tasks** (`disc_real_01`..`disc_real_36`, 6 tasks per CWE across `CWE-89`, `CWE-22` [refine `CWE22_ARC_RULE` to check archive member names / `member.name` rather than caller filesystem `/tmp/...` paths], `CWE-78`, `CWE-502`, `CWE-328`, `CWE-338`) strictly disjoint from all 24 `eval_*` tasks (`set(disc_ids) & set(eval_ids) == set()`).
2. **Real Observational + Intervention-Probe Data Collection ($144$ calls)**:
   - Partition the 36 discovery tasks across two natural observational styles ($C_{\text{env}} \in \{0, 1\}$, e.g., legacy prototype style vs. strict production docstring/refactor style where latent quality proxy `Z_lat` co-occurs with safer baseline generation via unobserved task difficulty, inducing genuine empirical confounding between `Z_lat` and `Y_sec`!).
   - On each discovery unit `i`, generate randomized counterfactual probes recorded as Stage II observations:
     - Observational realization (`I_lat=0, I_cau=0, I_flat=0`) yielding empirical `(Z_env, Z_lat, Z_cau, Y_sec, Y_func)`;
     - `I_lat=1` probe (applying `Z_lat` via `tsg_scoped`);
     - `I_cau=1` probe (applying `Z_cau` via `tsg_scoped`);
     - `I_flat=1` probe (applying `Z_cau` via `flat`).
   - Run real AST security auditing (`target_function`) and isolated Python unit tests (`python -I`) on every generated discovery completion to obtain **144 empirical binary rows** `(C_env, I_lat, I_cau, I_flat, Z_env, Z_lat, Z_cau, Z_bleed, Y_sec, Y_func)`—where `Z_*` variables are measured directly from deterministic pre/post prompt-intervention TSG checks or AST static presence checks strictly mapped to pre-generation prompt factors (remember: raw code ASTs never become PAG nodes; $Z$ are prompt/structural mechanism indicators and $Y_{\text{sec}}, Y_{\text{func}}$ are temporal sinks!).
3. **End-to-End Empirical Discovery + Replay**:
   - Feed the 144 empirical LLM-measured Stage II rows into `StructureBackend.search(..., "python-jci12", ..., context_vars=["C_env", "I_lat", "I_cau", "I_flat"], sink_vars=["Y_sec", "Y_func"])` -> `classify_jci_mechanisms(...)`.
   - Extend `natural_study.py` and `verification/natural_study.py` so `discovery_cohort` can optionally carry `"mode": "live_probe_matrix"` (generating and archiving full `discovery_details.json` + `discovery_wire_traces.json` during `study run`, then deterministically replaying all 144 splices, Oracles, unit tests, Stage II matrix assembly, CI permutation tests, PAG discovery, and classifications inside `study verify`).

### 3.2 `WP2.2` — Stage I Automated Raw-Prompt Extraction Stability Audit

**Goal**: Measure Stage I reliability not only on curated calibration JSON records, but also on **LLM-extracted semantic graphs** from raw natural-language prompts (`compile_source_propositions(..., tolerant=True)` vs `tolerant=False`).

**Requirements**:
- Run 2 seeded extraction passes (or paraphrased prompt formatting perturbations) on raw prompts across the 24 held-out tasks using deterministic schema-guided extraction (`temperature=0.0`).
- Measure and report: (i) valid graph compilation yield with `tolerant=False` vs `tolerant=True`, (ii) local `unresolved` containment rate (cases resolved locally without dropping valid `operation` / `part_of` bindings), and (iii) `evaluate_binary_attribute_reliability` over the 8 `TSG_ORTHOGONAL_MECHANISM_NAMES` (`median_flip_rate <= 0.05` target).

---

## 4. Work Package 3 (`WP3`): Multi-Model Held-Out 5-Arm Evaluation

**Goal**: Demonstrate external validity across at least **two distinct model sizes or families** on $D_{\text{eval}}$ using the exact empirical policy learned in `WP2` across all 5 arms (`baseline`, `corr_tsg`, `jci_flat`, `jci_op_only`, `jci_tsg`), reporting full paired ITT denominators.

**Execution Protocol on Compute Server (`$STUDY_ROOT`)**:
1. Check GPU availability first and never disturb other running vLLM endpoints.
2. Run Model 1 (`Qwen2.5-Coder-32B-Instruct`) and Model 2 (e.g., `Qwen2.5-Coder-7B-Instruct` or `Qwen2.5-Coder-14B-Instruct` or another open-weight coder model available in local model storage):
   ```bash
   export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
   export LOCAL_VLLM_BASE_URL=http://127.0.0.1:<PORT>/v1
   export LOCAL_VLLM_MODEL_ID="<MODEL_ID>"
   python -m prompt_mechanism_study study run \
     "$STUDY_ROOT/results/local-vllm-<model-tag>-empirical-5arm-YYYYMMDD" \
     --plan configs/jci-empirical-discovery-pilot.json
   python -m prompt_mechanism_study study verify \
     "$STUDY_ROOT/results/local-vllm-<model-tag>-empirical-5arm-YYYYMMDD"
   ```
3. Retain **every single call** (`144` discovery probe calls + `24 * 5 = 120` held-out paired evaluation calls = `264` calls per model) in its full ITT denominator and archive the `summary_sha256` output of `study verify`.

---

## 5. Work Package 4 (`WP4`): Manuscript & Documentation Synchronization

1. **Experiment Ledger**: Create `docs/experiments/YYYY-MM-DD-empirical-jci-multimodel-validation.md` recording:
   - Exact commands (with `$STUDY_ROOT`), Python/NumPy/SciPy versions, and `VERIFIED` `summary_sha256` digests.
   - Zero-GPU sub-ablation table (`env_adj_policy`, `pc_dag_policy`, `jci_policy`).
   - Empirical 36-task Stage II discovery PAG summary (`pag_valid`, classifications, `scope_bleed_detected`).
   - Multi-model 5-arm ITT comparison tables (`baseline`, `corr_tsg`, `jci_flat`, `jci_op_only`, `jci_tsg`) with $Y_C, Y_E, \text{unknown}, Y_{\text{sec}}, Y_{\text{func}}, Y_{\text{joint}}$, Bonferroni CIs, and honest failure audit.
2. **ACM TOSEM Manuscript Update**:
   - Follow [paper/AGENTS.md](../../paper/AGENTS.md) and [paper/fse2027/AGENTS.md](../../paper/fse2027/AGENTS.md).
   - Update [paper/fse2027/sections/04-evaluation.tex](../../paper/fse2027/sections/04-evaluation.tex) Table 5 and RQ1–RQ3 prose/tables with verified multi-model, `op_only`, `env_adj`/`pc_dag`, and empirical-$D_{\text{disc}}$ metrics (keeping any unexecuted human adjudication or external repository rows as `\pendingresult`).
   - Compile via `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out main.tex`, render pages with `pdftoppm`, and visually inspect all modified pages for zero table overflow or missing citations.

---

## 6. Final Acceptance Checklist Before Completion

- [ ] `pytest -q` passes 100% with zero skipped assertions on new Stage I (`op_only`) and Stage II (`env_adj_policy`, `pc_dag_policy`, empirical discovery replay) tests.
- [ ] `study smoke` + `study verify` -> `VERIFIED`.
- [ ] `study natural-smoke` + `study verify` -> `VERIFIED`.
- [ ] Sub-ablation 48-cell run + `study verify` -> `VERIFIED`.
- [ ] Empirical-$D_{\text{disc}}$ + 5-arm multi-model runs on `$STUDY_ROOT` all return `study verify` -> `VERIFIED` with full ITT denominators and `0` hidden filtering.
- [ ] Double-anonymous hygiene scan across `src/`, `configs/`, `docs/` (excluding legacy pre-2026-11-16 ledgers), `scripts/`, `tests/`, `README.md`, `AGENTS.md`, and `paper/fse2027/` returns `0` personal path or handle matches.
- [ ] `paper/fse2027/out/main.pdf` compiles cleanly with zero Overfull `\hbox` errors and passes visual PNG inspection.
