# Paper-Specific Instructions

The repository-root `AGENTS.md` applies throughout `paper/`. This file adds
only manuscript-local rules.

- Use
  `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
  for new-protocol prose. Describe a legacy result only under its frozen
  protocol and evidence boundary.
- Keep the four RQs aligned with the active method: outcome-blind
  prioritization, representation/prioritization contribution, randomized
  intervention effects, and the separately governed expert study. The expert
  study cannot validate causal discovery or objective repair accuracy.
- Call the independent analysis unit a **task unit**. Mention
  `semantic_cluster_id` only when identifying an immutable legacy field.
- Keep Prompt TSG semantics separate from causal edges, assigned-arm ITT
  primary, and post-assignment fidelity or drift strictly diagnostic.
- Every quantitative claim must trace to a frozen result field and table
  builder. Report material null, harmful, unknown, failed, or non-evaluable
  outcomes required by the governing protocol.
- Preserve double-anonymous review and place Data Availability after the
  Conclusion.
- After changing LaTeX, tables, or figures, compile and visually inspect the
  rendered PDF.
