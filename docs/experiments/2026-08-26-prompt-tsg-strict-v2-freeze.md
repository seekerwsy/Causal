# Prompt TSG strict four-arm freeze (v2)

This freeze supersedes the stopped 55-task census. The earlier run exposed outcomes for five pilot tasks and then stopped during intervention realization because one SQL-identifier task had been represented as a SQL-value task. No remaining-task code generation or outcome measurement occurred.

The repair is representation-only and was completed before this study's code generation:

- remove 14 prompts that explicitly require Java, Bash, or shell output from the Python candidate population;
- re-extract 119 fresh candidate prompts with Qwen3.7 Max using one source-only `LLM_FACTS` call per task;
- deterministically require exact evidence spans, catalog semantics, and valid edge types;
- retain 31 TSG-applicable tasks, then exclude 10 tasks whose editable unit, input format, language, or SQL roles do not share the registered intervention contract;
- exclude two further tasks solely because the superseded pilot had already generated and measured code for them; their outcome values were not used;
- freeze the remaining 19 semantic clusters as a census, not a sample selected for expected effect.

The final population has 19 tasks and 76 assignments: CWE-22 (7), CWE-502 (6), CWE-78 (1), and CWE-89 (5). The source lineages are CyberSecEval Instruct Prime (6), CodeSecEval/SecurityEval (9), SALLM (2), and SeCodePLT (2).

The four arms remain Absent, Specific, Generic, and Placebo. Source Prompt TSGs were extracted once before arm construction. Absent is the identity graph; the other arms are deterministic typed patches over the frozen source graph. Prompt TSG edges are semantic, not causal edges.

The primary estimand is paired semantic-task-clustered ITT for Specific minus Placebo on secure-code yield. Code validity, Oracle evaluability, functionality, joint secure-and-functional success, unknown bounds, semantic compliance, and non-target drift remain separate outcomes or diagnostics. No assignment may be removed from the ITT denominator after randomization.

The five-task pilot gate checks only protocol integrity. Pilot outcome direction cannot determine scaling, and pilot assignments remain in the final ITT if the gate passes.
