# Two-model main-prompt Gate C canary summary

This directory freezes the completed Qwen2.5-Coder-7B-Instruct and Phi-4-14B engineering canaries.
Both model strata contain five independent tasks, one per CWE, and four randomized Prompt arms per
task. All 40 assigned units completed generation, a single functional-Judge attempt, and a
profile-scoped security-Oracle decision with no failed or pending unit.

The Qwen stratum produced 15 secure outcomes, 12 functional passes, and 12 secure-and-functional
outcomes. The Phi stratum produced 16 secure outcomes, 13 functional passes, 2 conservative
functional-unknown outcomes from schema-invalid single Judge responses, and 11
secure-and-functional outcomes. Security had no unknown outcomes in either stratum.

These are pipeline-validation observations only. One task per CWE cannot estimate a task-clustered
intervention effect, support significance testing, or rank the four arms. The observed differences
are retained to verify outcome variation and to inform the separately frozen scale-up design; they
are not confirmation results.

`summary.json` records the archive hashes, local and server provenance, cumulative report selected
for each run, aggregate counts, recovery diagnostics, and all model-by-CWE-by-arm outcomes. The Phi
cumulative report is `report-remaining-004.json`; lexicographic filename order must not be used to
select a final report because immutable recovery reports coexist in the same run directory.
