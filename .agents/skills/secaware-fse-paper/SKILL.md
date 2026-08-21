---
name: secaware-fse-paper
description: Use only when the requested deliverable directly writes, edits, reviews, backfills, compiles, or prepares the SecAware FSE manuscript or its LaTeX submission artifacts. Do not use for experiment implementation, execution, debugging, planning, result analysis, evidence auditing, or progress reporting unless the user also asks to change or verify manuscript content.
---

# SecAware FSE Paper

## Overview

Keep the SecAware paper aligned with approved causal-design specifications and
traceable experiment artifacts. Specifications and frozen evidence outrank
existing prose; no polished sentence justifies changing an estimand or
inventing a result.

## Trigger Boundary

Trigger this skill only when the current request directly works on the manuscript,
its paper-facing tables or figures, or its LaTeX submission package. The fact that
an experiment may eventually support the paper is not sufficient.

Do not trigger this skill for standalone experiment implementation, execution,
debugging, protocol or sample-size planning, runtime/Oracle/Judge work, artifact
verification, result analysis, or progress reporting. If a later request asks to
translate verified evidence into manuscript prose or tables, trigger the skill at
that point and verify the evidence before writing.

## Choose a Mode

| Mode | Use for | Default action |
|---|---|---|
| `audit` | Checking manuscript claims, prose consistency, or submission readiness | Report evidence-backed manuscript findings; do not edit |
| `revise` | Changing framing, methods, RQs, or prose | Edit only the requested scope, then verify |
| `results-backfill` | Replacing placeholders with frozen results | Require artifact provenance before every quantitative claim |
| `presubmit` | Venue, anonymity, compilation, and package checks | Run the complete manuscript and FSE checklist |

If the request spans modes, apply them in this order: `audit`, `revise`,
`results-backfill`, `presubmit`.

## Read Before Acting

Read these files completely before changing Methods, Evaluation, Results,
Threats, or Conclusion:

- `paper/AGENTS.md`
- `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
- `docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`
- `docs/superpowers/specs/2026-07-22-paper-research-questions-design.md`
- `references/causal-boundaries.md`

For `presubmit`, also read `references/fse-2027-checklist.md`. Read the
specific frozen run manifest and table-building code before `results-backfill`.

## Source Authority

Resolve contradictions in this order:

1. The user's current explicit instruction.
2. The 2026-08-20 prospective successor specification for new-protocol work; legacy dated design
   and RQ specifications remain authoritative for runs produced under their manifests.
3. Frozen run manifests, immutable artifacts, and table builders.
4. Current implementation and tests.
5. Existing manuscript prose and comments.

Never silently reconcile a conflict by choosing the more publishable claim.
Record it and either use the higher-authority source or ask for a decision when
the conflict would change the approved study.

## Workflow

1. **Define scope.** Name the mode, manuscript section, authoritative specs,
   and whether writes are authorized.
2. **Build a conflict-and-evidence ledger.** For each material claim, record
   `claim`, `authority`, `artifact path/field`, `status`, and `action`.
3. **Plan the smallest coherent edit.** Preserve unrelated text and all
   honest placeholders. Do not broaden the approved causal model.
4. **Edit.** Keep Prompt TSG structure distinct from causal edges; keep
   discovery, intervention, outcome construction, and confirmation distinct.
5. **Verify.** Run the paper contract test, search for stale terminology, and
   compile LaTeX when the toolchain is available.
6. **Report.** State changed files, verified checks, unresolved placeholders,
   and any claim that remains blocked by absent evidence.

## Evidence Rules

- A quantitative result requires a frozen artifact path, exact field or table
  builder, run/config identity, and enough provenance to reproduce it.
- Never infer a missing number from prose, plots, exploratory runs, or nearby
  rows. Never replace `--` or a TODO with a plausible value.
- Preserve null, conflicting, failed-backend, and non-evaluable outcomes.
- Distinguish `implemented`, `planned`, `executed`, and `reported`. Passing a
  component test is not evidence that a paper experiment was run.
- Do not claim objective human-study accuracy when RQ4 measures perceived
  quality and usefulness.
- Do not change an approved RQ, arm family, primary estimand, denominator, or
  evidence level during prose editing. Propose such a change separately.

## Stop Conditions

Stop result backfilling and report the blocker if any of these holds:

- the run is not frozen or its identity is ambiguous;
- the manuscript table cannot be traced to artifact fields;
- the requested aggregation pools across a locked estimand boundary;
- the available artifact disagrees with the approved design;
- only a post-treatment-filtered denominator is available for a primary ITT
  claim.

## Verification Commands

From the repository root:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
python "$env:CODEX_HOME\skills\.system\skill-creator\scripts\quick_validate.py" .agents\skills\secaware-fse-paper
```

From `paper/fse2027`, when `latexmk` is installed:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
```

## Example Invocation

> Use `$secaware-fse-paper` in `results-backfill` mode. Audit the frozen run
> manifest first, fill only RQ1's fixed-$K$ funnel table, retain unresolved
> cells as placeholders, run the paper contract test, compile the PDF, and
> report the artifact path and field supporting each inserted value.
