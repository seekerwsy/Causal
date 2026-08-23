# Prompt Mechanism Study FSE Revision Evidence Ledger

- **Revision:** 2026-08-22 related-work coverage revision
- **Primary manuscript:** [`paper/fse2027/prompt-mechanism-study-fse2027-draft.tex`](prompt-mechanism-study-fse2027-draft.tex)

| Claim or manuscript element | Highest authority | Artifact path and field | Status | Revision action |
| --- | --- | --- | --- | --- |
| Prompt TSG supplies prompt semantics and variables, not causal edges | Approved causal design Sections 2–5 | [Causal design Sections 2–5](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#2-non-negotiable-boundaries), contracts `Prompt TSG` and local-table variables `W`, `X`, `Y`, and JCI-only `C`; specification-only; no execution evidence | Approved design | State once in setup and once in the figure caption |
| Stable possible paths are discovered with causal-learn FCI and task-cluster bootstrap | Approved causal design Section 6 | [Causal design Sections 6.1–6.3](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#6-observational-fci-discovery) and the root [research-integrity boundary](../../AGENTS.md#research-and-reporting-integrity); implementations [`run_causal_learn_fci`](../../src/secaware/discovery/causal_learn_backend.py#L242), [`run_task_cluster_fci_bootstrap`](../../src/secaware/causal/bootstrap.py#L648), and [`enumerate_possible_prompt_paths`](../../src/secaware/causal/paths.py#L109); tests [`test_fci_adapter_calls_exact_gsq_configuration`](../../tests/test_causal_learn_fci_backend.py#L178), [`test_bootstrap_is_clustered_not_row_wise_on_adversarial_rows`](../../tests/test_task_cluster_fci_bootstrap.py#L317), and [`test_enumerates_sorted_direct_mediated_and_long_prompt_paths`](../../tests/test_possible_pag_paths.py#L191); no final paper-run artifact | Implemented core; final run absent | Describe the method; retain result slots |
| Hypotheses are frozen before confirm variants, assignments, code, and outcomes | Approved causal design Sections 6.3 and 10 | [Causal design Section 6.3](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#63-stable-possible-paths-and-hypothesis-freeze), [Section 10](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#10-randomized-held-out-confirmation), and the root [research-integrity boundary](../../AGENTS.md#research-and-reporting-integrity); type [`FrozenHypothesisRecord`](../../src/secaware/schema/causal.py#L1309), fields `hypothesis_sha256`, `freeze_batch_sha256`, and `frozen_at_utc`; implementation [`freeze_hypotheses`](../../src/secaware/causal/freeze.py#L441); test [`test_freeze_guard_rejects_any_m5_m6_manifest_or_artifact_before_output`](../../tests/test_hypothesis_freeze.py#L371); no final manifest | Implemented contract; final run absent | Use as the discovery/confirmation boundary |
| Primary confirmation is task-clustered assigned-arm ITT | Approved causal design Section 11 and RQ design Section 6 | [Causal design Sections 11.1–11.4](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#11-outcomes-and-primary-itt) and [RQ design Section 6](../../docs/superpowers/specs/2026-07-22-paper-research-questions-design.md#6-primary-itt-and-evidence-levels), exact contract `assigned-arm ITT` with task-cluster uncertainty and no diagnostic denominator filter; specification-only; no execution evidence; no final effect artifact | Approved estimand; final run absent | Preserve exact denominator and retain `--` results |
| JCI uses one categorical `C_arm` column | Approved causal design Section 12 | [Causal design Section 12](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#12-jci-analysis), exact JCI context-column contract `C_arm`; specification-only; no execution evidence | Aligned with approved design | Keep one categorical context column and preserve JCI as secondary analysis |
| Deterministic extraction is an explicit run-locked backend | Approved causal design Sections 3.2 and 14 | [Causal design Section 3.2](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#32-extractor-backends) and [Section 14](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#14-configuration), exact backend contract `DETERMINISTIC_CATALOG_V1` and run-locked extractor selection; specification-only; no execution evidence | Aligned with approved design | Keep deterministic extraction as an explicit backend, never a fallback |
| Four arms apply to Safety ADD and Safety REMOVE | Approved causal design Section 8 | [Causal design Sections 8.1–8.2](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#8-family-specific-arm-protocols), exact Safety ADD roles `TARGET_PATCH`, `NOOP_REWRITE`, `LENGTH_MATCHED_PLACEBO`, `GENERIC_SECURITY_REMINDER` and Safety REMOVE roles `TARGET_REMOVE`, `NOOP_RETAIN`, `LENGTH_MATCHED_SHAM_EDIT`, `GENERIC_SECURITY_REPLACEMENT`; specification-only; no execution evidence | Aligned with approved design | Keep four-arm language scoped to Safety ADD and Safety REMOVE |
| Valid terminal non-success differs from missing or corrupt producer evidence | Approved causal design Sections 4.2, 11.1, and 15 | [Causal design Section 4.2](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#42-outcome-encoding), [Section 11.1](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#111-assignment-principle), and [Section 15](../../docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md#15-failure-semantics), exact valid-terminal outcome encoding versus missing/corrupt producer replay contract; specification-only; no execution evidence; no final result artifact | Aligned with approved design | Retain the assigned-arm non-success versus blocked-publication replay boundary |
| External adapters, RQ2 runs, RQ4 study, and final paper run are incomplete | Approved RQ design Section 12 and research-integrity boundary | [RQ design Section 12](../../docs/superpowers/specs/2026-07-22-paper-research-questions-design.md#12-required-new-evaluation-work) and the root [research-integrity boundary](../../AGENTS.md#research-and-reporting-integrity): computational work lacks a frozen paper-run manifest and table-builder provenance; [RQ4 Sections 10 and 12](../../docs/superpowers/specs/2026-07-22-paper-research-questions-design.md#10-rq4-operationalization) separately lack frozen protocol, participant-data, randomization, and analysis provenance; specification-only; no execution evidence | Planned, not executed | Use future tense and keep result slots |
| RQ1–RQ4 quantitative findings | Frozen computational run manifest and table builders; or frozen RQ4 protocol, participant-data, randomization, and analysis artifacts plus an analysis/table builder | [RQ1–RQ3 operationalization, Sections 5–9](../../docs/superpowers/specs/2026-07-22-paper-research-questions-design.md#5-rq1-operationalization) requires a frozen computational run manifest, dataset/model provenance, and exact table-builder field mapping; [RQ4 Section 10](../../docs/superpowers/specs/2026-07-22-paper-research-questions-design.md#10-rq4-operationalization) separately requires frozen protocol, participant data, randomization, and analysis provenance; specification-only; no execution evidence; no qualifying artifact identified | Blocked by evidence | Keep every result cell as `--` |
| FCI handles latent-variable and selection-bias settings through PAG output | Spirtes et al. 1995; Zhang 2008 | [references.bib](references.bib): `spirtes1995fci`, `zhang2008ancestral` | Verified literature | Cite in discovery background without claiming unique DAG recovery |
| JCI combines context variables with causal discovery under explicit assumptions | Mooij et al. 2020 | [references.bib](references.bib): `mooij2020jci` | Verified literature | Cite in secondary-analysis subsection |
| causal-learn provides the FCI implementation used by the discovery pipeline | Zheng et al. 2024 | [references.bib](references.bib): `zheng2024causallearn` | Verified literature; implementation citation, not execution evidence | Cite in method implementation/background for software attribution; do not use as final-run evidence |
| Attribution, concept, and rationale methods provide complementary explanation evidence | Sundararajan et al. 2017; Lundberg and Lee 2017; Kim et al. 2018; DeYoung et al. 2020 | [references.bib](references.bib): `sundararajan2017integrated`, `lundberg2017shap`, `kim2018tcav`, `deyoung2020eraser` | Verified literature; baseline execution absent | Cite only as related work |
| AI-generated code can contain security weaknesses, motivating secure-and-functional evaluation | Pearce et al. 2022; Perry et al. 2023 | [references.bib](references.bib): `pearce2022copilot`, `perry2023assistants` | Verified literature | Use in Introduction motivation |
| Secure-generation methods optimize or retrieve for secure outputs | He et al. 2024; Zhang et al. 2024 | [references.bib](references.bib): `he2024safecoder`, `zhang2024seccoder` | Verified literature; not executed baselines by default | Contrast with prompt-side hypothesis confirmation |
| CodeQ aggregates token-level rationales into global, programming-category explanations for code and test generation | Khati et al. 2026 | [references.bib](references.bib): `khati2026codeq`; DOI `10.1145/3744916.3787764` | Verified literature; baseline execution absent | Cite as directly related code-generation explanation work; do not imply confirmatory intervention evidence |
| Thea repairs vulnerable code generation by identifying vulnerability-associated internal representations and intervening during inference | El Husseini et al. 2026 | [references.bib](references.bib): `elhusseini2026thea`; DOI `10.1145/3744916.3773210` | Verified literature; external security-hardening method, not execution evidence for this paper | Contrast inference-time execution repair with locked-generator prompt-policy evaluation |
| CAM ranks intermediate features in multi-agent code-generation systems using simulated realistic errors and applies the ranking to repair and pruning | Lyu et al. 2026 | [references.bib](references.bib): `lyu2026cam`; DOI `10.1145/3832238` | Verified literature; external causality-analysis method, not execution evidence for this paper | Contrast intermediate-output correctness analysis with input-prompt security-policy effects |
| Direct secure-prompt studies compare predefined reminders, CWE-specific instructions, reasoning, persona, prefixes, and iterative repair | Tony et al. 2025; Bruni et al. 2025 | [references.bib](references.bib): `tony2025prompting`, `bruni2025promptbenchmark` | Verified literature; external prompt-strategy evaluations, not execution evidence for this paper | Establish the closest comparison, then distinguish prospectively frozen context-conditioned policies and assigned-arm ITT |
| Security hardening also operates through learned steering, analyzer-guided prompt optimization, constrained decoding, and inference-time representation intervention | He and Vechev 2023; Nazzal et al. 2024; Fu et al. 2024; El Husseini et al. 2026 | [references.bib](references.bib): `he2023sven`, `nazzal2024promsec`, `fu2024codeguard`, `elhusseini2026thea` | Verified literature; external methods, not executed baselines by default | Position prompt-policy confirmation within the wider security-hardening design space |
| SecurityEval and LLMSecEval provide CWE-indexed prompt suites for secure-code evaluation | Siddiq and Santos 2022; Tony et al. 2023 | [references.bib](references.bib): `siddiq2022securityeval`, `tony2023llmseceval` | Verified literature; external benchmarks, not final-run evidence for this paper | Describe the early prompt-suite and static-analysis evaluation lineage |
| Secure-code benchmarks increasingly combine functionality, executable security checks, end-to-end exploits, and multilingual dynamic evaluation | Siddiq et al. 2024; Peng et al. 2025; Vero et al. 2025; Nie et al. 2025 | [references.bib](references.bib): `siddiq2024sallm`, `peng2025cweval`, `vero2025baxbench`, `nie2025secodeplt` | Verified literature; external benchmarks, not final-run evidence for this paper | Motivate separate measurement of functionality, security, Oracle support, unknowns, and joint success |
| Secure-code evaluation can overstate gains when functionality degrades or a static analyzer misses vulnerabilities | Dai et al. 2026 | [references.bib](references.bib): `dai2026rethinking` | Verified literature; external evaluation study, not final-run evidence for this paper | Support independent outcome measurement without using diagnostics as denominator filters |

## Baseline Verification (2026-07-30)

- **Recorded versions:** The pre-revision baseline source is revision
  `a88e81c`. Task 1 revision content and its recorded contract-regression state
  correspond to content state `f9773fa`. This ledger is the saved execution
  record; no separate raw-log path is claimed. The present documentation-only
  consistency repair is followed by a fresh contract rerun before its commit.
- **Environment and working directories:** Windows PowerShell; repository
  virtual environment at `D:\MyCode\Causal\.venv`; repository root
  `D:\MyCode\Causal`; LaTeX build directory
  `D:\MyCode\Causal\paper\fse2027`; TeX Live 2026.
- **Paper contract:** From the repository root,
  `.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v`
  passed 4/4 tests. The unittest-reported time was 0.004s; observed command
  wall-clock time was approximately 0.8s.
- **LaTeX baseline:** From `paper\fse2027`,
  `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex`
  exited 0.
- **PDF metadata:** `pdfinfo out\secaware-fse2027-draft.pdf` reported 9 pages.
- **Visual baseline:** `pdftoppm -png -r 120 out\secaware-fse2027-draft.pdf ..\tmp\pdfs\current-draft\page`
  generated 9 PNG files in `paper/tmp/pdfs/current-draft`. These are
  uncommitted temporary visual artifacts.
- **Conflict scan (run from `D:\MyCode\Causal\paper`, i.e. `paper`):**
  `rg -n -S "one-hot|fallback|four-arm|After assignment, re-extraction|design-stage|skeleton|placeholder outcomes|no quantitative findings" fse2027\secaware-fse2027-draft.tex`
  matched 12 lines: `four-arm` 4, `design-stage` 2, `fallback` 1,
  `After assignment, re-extraction` 1, `one-hot` 1,
  `placeholder outcomes` 1, `skeleton` 2, and
  `no quantitative findings` 0.

## Final Pre-Results Verification (2026-08-04)

- **Tracked source:** branch `codex/fse-paper-alignment`, manuscript state after
  Task 6 commit `f7c9169`; final verification corrections are recorded by the
  subsequent verification commit when present.
- **Paper contract:** from `D:\MyCode\Causal`,
  `.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v`
  passed 4/4 tests in 0.003 seconds.
- **Locked-boundary scans:** the forbidden phrase scan was empty. Required-term
  scans found assigned-arm ITT, task clustering, the secure-and-functional
  outcome, diagnostic/non-filter language, the single categorical `C_arm`, and
  Safety ADD/REMOVE-specific four-arm protocols.
- **LaTeX build:** from `paper\fse2027`, forced `latexmk -g -pdf` completed and
  produced `out\secaware-fse2027-draft.pdf`; the final log scan found no
  unresolved citation/reference, overfull box, LaTeX error, or missing glyph.
- **Handoff rerun note:** an initial final-rerun command was launched from the
  repository root, so LaTeX could not resolve the manuscript-relative
  `figures/secaware-overview.tex` path and left an incomplete auxiliary file.
  No source changed. After removing only the affected manuscript auxiliary
  files, a clean build from `paper\fse2027` succeeded and restored the 12-page
  PDF. Future builds must use the manuscript directory as the working directory.
- **PDF and visual review:** `pdfinfo` reported 12 anonymous ACM review pages.
  All 12 pages were rendered at 150 dpi and inspected for hierarchy, figure and
  table legibility, clipping, overlap, glyph defects, anonymity, and abnormal
  whitespace; no blocking visual defect was found.
- **Evidence reconciliation:** no frozen computational paper-run manifest or
  frozen human-study result package was identified. All RQ1--RQ4 quantitative
  result rows remain explicit `--`/manifest-bound placeholders, and the abstract
  retains `Frozen-run results pending.` No result cell was backfilled.
