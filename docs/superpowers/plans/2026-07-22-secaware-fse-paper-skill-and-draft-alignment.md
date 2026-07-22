# SecAware FSE Paper Skill and Draft Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add project-scoped, evidence-constrained paper-writing guidance and revise the FSE 2027 manuscript to match the approved Prompt-only FCI/JCI and randomized ITT specifications.

**Architecture:** Keep short, always-on invariants in `paper/AGENTS.md`; put the conditional writing workflow in `.agents/skills/secaware-fse-paper/`; keep detailed causal and venue checks in one-level skill references. Use one deterministic contract test to guard skill discovery metadata and manuscript-level causal boundaries. Treat approved specifications as authoritative and leave quantitative results as placeholders until frozen artifacts exist.

**Tech Stack:** Markdown Agent Skills, Codex `AGENTS.md`, Python 3.12 standard-library `unittest`, LaTeX `acmart`, PowerShell/latexmk where available.

---

### Task 1: Establish the failing paper contract

**Files:**
- Create: `tests/paper/test_secaware_fse_paper_contract.py`
- Inspect: `paper/fse2027/secaware-fse2027-draft.tex`

- [ ] **Step 1: Write contract tests for the missing guidance and stale manuscript language**

Assert the existence and key metadata of `paper/AGENTS.md` and `.agents/skills/secaware-fse-paper/SKILL.md`. Assert exact RQ wording, randomized ITT terminology, FCI/JCI/RFCI coverage, four safety-ADD arms, `Data Availability`, and absence of known stale per-protocol, Bandit-default, paired-confirmation, and opportunity-filter phrases.

- [ ] **Step 2: Run the contract test to verify RED**

Run: `.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v`

Expected: FAIL because the guidance files do not exist and the manuscript contains stale causal language.

### Task 2: Create the project-local paper skill

**Files:**
- Create: `.agents/skills/secaware-fse-paper/SKILL.md`
- Create: `.agents/skills/secaware-fse-paper/agents/openai.yaml`
- Create: `.agents/skills/secaware-fse-paper/references/causal-boundaries.md`
- Create: `.agents/skills/secaware-fse-paper/references/fse-2027-checklist.md`
- Create: `paper/AGENTS.md`

- [ ] **Step 1: Scaffold the skill with the official initializer**

Run the system `skill-creator/scripts/init_skill.py` with the skill name, repository `.agents/skills` destination, `references` resource, and UI interface values.

- [ ] **Step 2: Replace the scaffold with the minimal evidence-constrained workflow**

Define `audit`, `revise`, `results-backfill`, and `presubmit` modes; source authority; pre-edit conflict/evidence ledger; minimal editing; verified-result rules; compilation; and final reporting. Route detailed causal and FSE constraints to the two references.

- [ ] **Step 3: Add paper-scoped persistent guidance**

Keep `paper/AGENTS.md` short. Require approved-spec authority, Prompt-only TSG, randomized task-clustered ITT, diagnostic-only treatment fidelity, no invented evidence, and use of the project skill.

- [ ] **Step 4: Validate the skill**

Run the system `skill-creator/scripts/quick_validate.py` against `.agents/skills/secaware-fse-paper` and inspect `agents/openai.yaml` for consistency.

### Task 3: Align the manuscript methodology

**Files:**
- Modify: `paper/fse2027/secaware-fse2027-draft.tex`

- [ ] **Step 1: Replace the stale problem and variable formulation**

Define task/model/seed coordinates; restrict causal variables to pre-treatment metadata, Prompt TSG features/motifs, outcomes, and JCI arm context; state that generated code is only Oracle/functional-evaluator input.

- [ ] **Step 2: Replace heuristic discovery with the approved FCI pipeline**

Describe local CWE/model tables, TSG-derived background knowledge, causal-learn FCI with G-square, one-seed-per-task task-cluster bootstrap, stable possible paths, pre-confirmation freeze, and optional RFCI sensitivity.

- [ ] **Step 3: Replace graph-patch-only and paired confirmation language**

Describe run-locked text-native or graph-native execution, pre-randomization hard gates, family-specific arms, frozen balanced assignments, and diagnostic-only realized target change.

- [ ] **Step 4: Replace per-protocol effects and evidence levels**

Make task-clustered assigned-arm ITT primary; keep hypothesis/target/operation/model/CWE strata separate; add direct specificity contrasts, JCI secondary analysis, and the approved evidence taxonomy.

### Task 4: Align RQ1--RQ4 and paper status

**Files:**
- Modify: `paper/fse2027/secaware-fse2027-draft.tex`

- [ ] **Step 1: Replace all RQ sentences and operationalizations**

Use the approved concise RQ text. Add the fixed-`K` RQ1 funnel, 2-by-2 RQ2 ablation, ADD/REMOVE RQ3 effects, and conditional perceived-utility RQ4 study.

- [ ] **Step 2: Replace stale tables**

Use placeholder-safe RQ1 funnel, RQ2 2-by-2, RQ3 intervention, and RQ4 ordinal-rating table skeletons without fabricated values.

- [ ] **Step 3: Correct status, threats, reproducibility, and conclusion**

State which paper-evaluation layers remain future work, make post-treatment selection a diagnostic concern rather than the primary analysis, enumerate required provenance artifacts, add `Data Availability`, and avoid claiming completed external baselines, ablations, or human studies.

### Task 5: Verify and review

**Files:**
- Test: `tests/paper/test_secaware_fse_paper_contract.py`
- Validate: `.agents/skills/secaware-fse-paper/`
- Compile: `paper/fse2027/secaware-fse2027-draft.tex`

- [ ] **Step 1: Run the focused contract test to verify GREEN**

Run: `.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v`

Expected: PASS.

- [ ] **Step 2: Run skill validation and manuscript scans**

Run `quick_validate.py`, search for stale phrases, check TODO/result placeholders, and inspect the exact diff.

- [ ] **Step 3: Compile LaTeX**

Run `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex` from `paper/fse2027` when `latexmk` is available. If it is unavailable, report the environmental blocker and preserve the existing source-level verification result.

- [ ] **Step 4: Review the compiled PDF or build log**

Check page count, undefined references, overfull boxes, anonymous front matter, and placement of `Data Availability`. Do not claim layout verification when compilation is unavailable.
