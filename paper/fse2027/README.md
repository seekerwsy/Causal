# PHASE FSE 2027 Draft

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
- `references.bib`: bibliography shared by the section files.

## Compile

The draft is verified with TeX Live 2026. From this directory, compile with:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out main.tex
```

The generated manuscript is `out/main.pdf`. The source can also be uploaded to
Overleaf and compiled with `main.tex` as the main file.

## Current Scope

The draft intentionally focuses on method and research-question design.
Computational result tables must be populated only from frozen artifacts
through a traceable table builder. Follow the repository-root `AGENTS.md` and
the concise paper-local `paper/AGENTS.md` for research-integrity and manuscript
requirements.

The current narrative answers which prompt-side security requirements matter
through one route from structured representation to usable evidence: Typed
Prompt Representation, Requirement Hypothesis Discovery and Selection,
Evaluation of Requirement Effects, and the resulting Requirement Evidence
Record. The expert-perceived utility study is a separately governed
downstream evaluation, not a fourth computational stage. Earlier commands and identifiers are preserved in the
[historical revision evidence ledger](revision-evidence-ledger.md); they are
not current project names, invocation instructions, or manuscript prose
templates. The ledger is used only to verify support and locate evidence;
implementation identifiers, status notes, hashes, revision actions, and
incident chronology remain outside the paper narrative.

Working-draft completion status and missing-evidence notes belong in this README
or the ledger rather than in manuscript prose. Quantitative manuscript claims
still require a frozen artifact and traceable table builder; until those exist,
the document remains an internal draft and must not present planned work as
completed. A submission-ready build must contain neither backfill commentary
nor unexplained result placeholders.

## Reviewer Reading Guide

The single manuscript entry point is `main.tex`. The active path reads natural
prompts, produces Prompt TSG requirement templates, freezes a budgeted
requirement-hypothesis set, constructs and randomizes matched prompt policies, measures
security and functionality independently, assembles outcomes, and reports
semantic-clustered assigned-arm ITT evidence. The key invariants are: Prompt
TSG edges are semantic rather than causal; held-out outcomes cannot alter
selection; assigned arm, not realized fidelity, defines the primary contrast;
and Oracle coverage, functionality, and joint success remain separate from the
primary secure-code-yield outcome.

Recommended reading order (seven files):

1. `main.tex`
2. `sections/01-introduction.tex`
3. `sections/02-problem-formulation.tex`
4. `sections/03-method.tex`
5. `figures/prompt-mechanism-study-overview.tex`
6. `sections/04-evaluation.tex`
7. `sections/06-conclusion.tex`
