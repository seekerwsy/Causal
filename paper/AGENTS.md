# Paper-Specific Instructions

The repository-root `AGENTS.md` applies throughout `paper/`. This file adds
only manuscript-local rules.

- Describe legacy results only under their original frozen protocol and
  evidence boundary; never reinterpret them under the active schema.
- Use the exact RQ wording and scope from the active protocol. RQ2 tests the
  frozen structural Gates through Atomic Full versus RD-only and Pair Full
  versus No-Relation; it is not the legacy representation comparison. Keep the
  RQ1 selector Expert baseline distinct from the separately governed RQ4 human
  study, which cannot validate causal discovery or objective repair accuracy.
- Call the independent analysis unit a **task unit**. Mention
  `semantic_cluster_id` only when identifying an immutable legacy field.
- Keep Prompt TSG semantics separate from causal edges, assigned-arm ITT
  primary, and post-assignment fidelity or drift strictly diagnostic.
- Every quantitative claim must trace to a frozen result field and table
  builder. Report material null, harmful, unknown, failed, or non-evaluable
  outcomes required by the governing protocol.
- After changing LaTeX, tables, or figures, compile and visually inspect the
  rendered PDF.
