# SecAware FSE Revision Evidence Ledger

**Revision:** 2026-07-29 narrative revision
**Primary manuscript:** `paper/fse2027/secaware-fse2027-draft.tex`

| Claim or manuscript element | Highest authority | Artifact path and field | Status | Revision action |
| --- | --- | --- | --- | --- |
| Prompt TSG supplies prompt semantics and variables, not causal edges | Approved causal design Sections 2–5 | Specification text; no quantitative artifact | Approved design | State once in setup and once in the figure caption |
| Stable possible paths are discovered with causal-learn FCI and task-cluster bootstrap | Approved causal design Section 6 | Implementation status supported by causal-boundary reference; paper-run evidence unavailable | Implemented core; final run absent | Describe the method; retain result slots |
| Hypotheses are frozen before confirm variants, assignments, code, and outcomes | Approved causal design Sections 6.3 and 10 | FrozenHypothesisRecord contract; final manifest absent | Implemented contract; final run absent | Use as the discovery/confirmation boundary |
| Primary confirmation is task-clustered assigned-arm ITT | Approved causal design Section 11 and RQ design Section 6 | Final effect artifact absent | Approved estimand; final run absent | Preserve exact denominator and retain `--` results |
| JCI uses one categorical `C_arm` column | Approved causal design Section 12 | JCI table contract | Current prose conflicts | Remove one-hot language |
| Deterministic extraction is an explicit run-locked backend | Approved causal design Sections 3.2 and 14 | Extractor policy contract | Current prose conflicts | Remove fallback language |
| Four arms apply to Safety ADD and Safety REMOVE | Approved causal design Section 8 | ArmProtocol contract | Current prose overgeneralizes | Qualify abstract, contribution, and figure language |
| Valid terminal non-success differs from missing or corrupt producer evidence | Approved causal design Sections 4.2, 11.1, and 15 | Outcome contract; final result artifact absent | Current prose is ambiguous | State zero versus replay boundary exactly |
| External adapters, RQ2 runs, RQ4 study, and final paper run are incomplete | Approved RQ design Section 12 and causal-boundary reference | No frozen final manifest | Planned, not executed | Use future tense and keep result slots |
| RQ1–RQ4 quantitative findings | Frozen final run and table builders required | No qualifying artifact identified | Blocked by evidence | Keep every result cell as `--` |
