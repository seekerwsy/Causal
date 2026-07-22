# SecAware Paper Guidance

These instructions apply to all files under `paper/`.

- Use the project skill `.agents/skills/secaware-fse-paper/SKILL.md` for paper
  audits, revisions, result backfilling, and submission checks.
- Treat the approved dated specifications in `docs/superpowers/specs/` as more
  authoritative than existing manuscript prose.
- Keep the causal representation Prompt-only: Prompt TSG structure is not a
  causal graph, and generated code is only Oracle/functional-evaluator input.
- Keep task-clustered assigned-arm ITT as the primary confirmatory analysis.
  `target_changed`, semantic compliance, and non-target drift are diagnostics,
  not filters for the primary denominator.
- Do not invent quantitative results, citations, completed experiments, or
  implementation status. Trace inserted results to frozen artifacts and leave
  unsupported cells as explicit placeholders.
- Preserve double-anonymous review and place Data Availability after
  Conclusion.
