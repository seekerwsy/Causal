# FSE 2027 Draft

This directory contains the FSE 2027 paper draft for Prompt Mechanism Study.

## Template

- Official FSE 2027 Research Track instructions point to ACM's `acmart`
  template and request the `acmsmall` conference sample style.
- The draft compiles against the `acmart` package provided by TeX Live or
  Overleaf. A locally unpacked CTAN copy may be kept under `acmart-template/`
  for reference, but that vendor cache is intentionally excluded from Git.

## Main Files

- `prompt-mechanism-study-fse2027-draft.tex`: current anonymous manuscript draft.

## Compile

The draft is verified with TeX Live 2026. From this directory, compile with:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out prompt-mechanism-study-fse2027-draft.tex
```

The generated manuscript is `out/prompt-mechanism-study-fse2027-draft.pdf`. The source can
also be uploaded to Overleaf and compiled with `prompt-mechanism-study-fse2027-draft.tex` as
the main file.

## Current Scope

The draft intentionally focuses on method and research-question design.
Computational result tables must be populated only from frozen artifacts
through a traceable table builder. Follow the repository-root `AGENTS.md` and
the concise paper-local `paper/AGENTS.md` for research-integrity and manuscript
requirements.

The current narrative organizes the computational method as Security-Aware
Prompt Representation, Stability-Guided Observational Prioritization, and
Randomized Policy Confirmation. Earlier commands and identifiers are preserved in the
[historical revision evidence ledger](revision-evidence-ledger.md); they are
not current project names or invocation instructions.

The manuscript may describe verified core capabilities in the present tense,
but unfinished RQ1--RQ4 studies and the frozen final paper evidence remain
future work. Every numerical result stays `--` until a frozen manifest and
table builder supply exact provenance.
