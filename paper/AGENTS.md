# Prompt Mechanism Study Paper-Specific Instructions

The repository-root `AGENTS.md` applies to every file under `paper/`. This file
adds only paper-local requirements and must remain concise.

- Use the prospective successor specification at
  `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
  for new-protocol manuscript content. A legacy run remains governed by the
  exact protocol named by its frozen manifest.
- Keep the manuscript's three RQs aligned with the single active artifact path:
  held-out intervention prioritization, representation/prioritization
  contribution, and randomized security-intervention effects.
- Keep Prompt TSG semantics separate from causal edges, preserve natural
  variables `X^0`, randomized arm `A`, and post-intervention diagnostics
  `X^{A,R}`, and use `semantic_task_cluster_id` as the highest resampling unit.
- Keep assigned-arm ITT primary. Fidelity and target-change measures are
  diagnostics, not post-assignment filters. JCI, RFCI, and other optional
  analyses cannot promote or replace the primary result.
- Do not invent results or silently fill placeholders. Every quantitative cell
  must trace to a frozen artifact, exact result field, and table builder.
- State null, harmful, conflicting, unknown, failed, and non-evaluable results
  accurately when required by the frozen protocol. Narrative emphasis cannot
  override research integrity.
- Preserve double-anonymous review and keep Data Availability after Conclusion.
- After manuscript, table, or figure changes, compile the LaTeX source and
  visually inspect the rendered PDF.
