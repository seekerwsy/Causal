# FSE 2027 Draft

This directory contains the FSE 2027 paper draft for SecAware-Causal.

## Template

- Official FSE 2027 Research Track instructions point to ACM's `acmart`
  template and request the `acmsmall` conference sample style.
- The draft compiles against the `acmart` package provided by TeX Live or
  Overleaf. A locally unpacked CTAN copy may be kept under `acmart-template/`
  for reference, but that vendor cache is intentionally excluded from Git.

## Main Files

- `secaware-fse2027-draft.tex`: current anonymous manuscript draft.

## Compile

The draft is verified with TeX Live 2026. From this directory, compile with:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
```

The generated manuscript is `out/secaware-fse2027-draft.pdf`. The source can
also be uploaded to Overleaf and compiled with `secaware-fse2027-draft.tex` as
the main file.

From the repository root, run the project paper contract with:

```powershell
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
```

## Current Scope

The draft intentionally focuses on method and research-question design. Result
tables are skeletons and must be filled only from one frozen final run directory.
Use the project-local `secaware-fse-paper` skill for manuscript audits,
revisions, verified result backfilling, and pre-submission checks.

The 2026-07-29 narrative revision organizes the method as Security-Aware
Prompt Representation, Stability-Guided Causal Discovery, and Causal Effect
Confirmation. Its evidence ledger is `revision-evidence-ledger.md`.

The manuscript may describe verified core capabilities in the present tense,
but external RQ1 adapters, paper RQ2 runs, the RQ4 study, and the frozen final
paper run remain future work. Every numerical result stays `--` until a frozen
manifest and table builder supply exact provenance.
