# CausalGuide FSE 2027 Draft

This directory contains the FSE 2027 paper draft for Prompt Mechanism Study.

## Template

- Official FSE 2027 Research Track instructions point to ACM's `acmart`
  template and request the `acmsmall` conference sample style.
- The draft compiles against the `acmart` package provided by TeX Live or
  Overleaf. A locally unpacked CTAN copy may be kept under `acmart-template/`
  for reference, but that vendor cache is intentionally excluded from Git.

## Main Files

- `main.tex`: current anonymous manuscript entry point.
- `sections/`: one file per top-level manuscript section, imported by
  `main.tex` in reading order.
- `sections/03-method.tex`: the canonical Method, also read by
  `method-concise-preview.tex`; there is no separate Method text to maintain.
- The preview filename is retained for continuity; the author has lifted its
  former three-page target in favor of a clearer explanation of the method.
- `references.bib`: bibliography shared by the section files.
- `tables/cwe-inventory/`: the selected 20-CWE table and full 117-label
  appendix, stored for later use and **not included in the manuscript**.
  See its [preview and provenance instructions](tables/cwe-inventory/README.md).

## Compile

The draft is verified with TeX Live 2026. From this directory, compile with:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out main.tex
```

The generated manuscript is `out/main.pdf`. The source can also be uploaded to
Overleaf and compiled with `main.tex` as the main file.

The connected Overleaf Git project is
`https://git.overleaf.com/6a8c0a50bbdf197f5de0d0ae`. Its separate local checkout
is under `paper/tmp/overleaf-sync/`; the research repository's `origin` points
to GitHub. Fetch the Overleaf project's latest revision before syncing, and
preserve any uncommitted manuscript edits in an existing sync checkout.

## Current Scope

The draft intentionally focuses on method and research-question design.
Computational result tables must be populated only from frozen artifacts
through a traceable table builder. Follow the repository-root `AGENTS.md` and
the concise paper-local `paper/AGENTS.md` for research-integrity and manuscript
requirements.

The title is **CausalGuide: Causal Analysis for Explainable Security Guidance in
LLM Code Generation**. The narrative asks how changing a task-bound security
requirement affects generated outcomes and what explanation or modification
advice the evidence supports. Its two contributions are task-grounded
requirement-level causal analysis and evidence-grounded explanations/security
guidance. Fixed-budget selection and randomized confirmation support these outputs.

The reader-facing stages are Structured Graph Representation, Requirement-Level
Causal Analysis, and Evidence-Grounded Explanations and Guidance. They retain
the seven scientific operations: Stage III presents the human-facing reporting
output of the same path, not another experiment or analysis. RQ4 evaluates the
perceived utility of complete explanation products under common presentation;
it does not isolate graph readability or measure actual adoption/repair success.

The [writing and evidence notes](method-concise-notes.md) identify the section
contracts, protocol/implementation evidence hooks, verified key literature,
remaining scientific gaps, and build checks. Implementation identifiers, status
notes, hashes, and development chronology remain outside the paper narrative.

Working-draft completion status and missing-evidence notes belong in this README
or the writing notes rather than in manuscript prose. Quantitative manuscript claims
still require a frozen artifact and traceable table builder; until those exist,
the document remains an internal draft and must not present planned work as
completed. A submission-ready build must contain neither backfill commentary
nor unexplained result placeholders.

Introduction through Conclusion now follow this shared narrative and the current
specified method. The four RQ sentences retain the main
manuscript wording at the author's explicit request; their broad framing does
not activate additional experiments. The protocol remains `SPECIFIED_DRAFT`.
The exact RQ1 comparator envelope, optional Expert/Random inclusion, task/model
counts and budgets, and the separately governed RQ4 design still need a
prospective freeze. Representation and Oracle qualification also remain
scientific prerequisites, not established by this prose revision. No formal
computational result is reported. Protocol Section 15.1 now specifies explanation
content and evidence-dependent withholding rules. Existing result fields support
that design, but no complete explanation-composition implementation or sufficient
adoption predicate is claimed. Exact secondary criteria and RQ4 materials/design
remain prospective. The abstract remains unfilled pending formal evidence; its
provisional argument outline is in the writing notes, not presented as an abstract.
Data Availability is included after Conclusion and describes intended replication
materials without a fabricated release link.

The 2026-09-13 revision is local only. It updates the paper-facing name and protocol
positioning, not immutable protocol IDs, experimental rules, implementation code,
or frozen inputs/results. Overleaf has not been synchronized with this revision.

## Reviewer Reading Guide

The single manuscript entry point is `main.tex`. The active path reads natural
prompts, produces Prompt TSG requirement templates, freezes a budgeted
requirement-hypothesis set, constructs and randomizes matched prompt policies, measures
security and functionality independently, assembles outcomes, and reports
task-unit assigned-arm ITT evidence and its scoped explanation. The key invariants are: Prompt
TSG edges are semantic rather than causal; held-out outcomes cannot alter
selection; assigned arm, not realized fidelity, defines the primary contrast;
and Oracle coverage, functionality, and joint success remain separate from the
primary secure-code-yield outcome.

Recommended reading order (six files):

1. `main.tex`
2. `sections/01-introduction.tex`
3. `sections/02-problem-formulation.tex`
4. `sections/03-method.tex`
5. `sections/04-evaluation.tex`
6. `sections/06-conclusion.tex`
