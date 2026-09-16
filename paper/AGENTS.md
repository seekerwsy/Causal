# Paper-Specific Instructions

The repository-root `AGENTS.md` applies throughout `paper/`. This file adds
only manuscript-local rules.

- Describe legacy results only under their original frozen protocol and
  evidence boundary; never reinterpret them under the active schema.
- Preserve the four author-approved RQ sentences. The main study is Atomic-only;
  RQ2 isolates FCI admission through Full versus RD-only, not a representation
  or readability comparison. RQ1 and RQ4 use the same approved five-method set:
  CausalGuide, Prompt Attribution, Causal Prompt Concepts, Prompt Perturbation,
  and LLM-Judge Explanation. The separately governed RQ4 human study cannot
  validate causal discovery or objective repair accuracy.
- Call the independent analysis unit a **task unit**. Mention
  `semantic_cluster_id` only when identifying an immutable legacy field.
- Keep Prompt TSG semantics separate from causal edges, assigned-arm ITT
  primary, and post-assignment fidelity or drift strictly diagnostic.
- Every quantitative claim must trace to a frozen result field and table
  builder. Report material null, harmful, unknown, failed, or non-evaluable
  outcomes required by the governing protocol.
- After changing LaTeX, tables, or figures, compile and visually inspect the
  rendered PDF.
