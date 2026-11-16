# CausalGuide ACM TOSEM Manuscript

This directory contains the anonymous **ACM TOSEM** manuscript draft (`\acmJournal{TOSEM}`, Direction 1 revision; prospective multi-model confirmatory cells remain `\pendingresult`).

## Main Files

- `main.tex`: Anonymous manuscript entry point (`acmart`, `manuscript,screen,review,anonymous`) with synchronized title and abstract.
- `sections/01-introduction.tex`: Problem framing around multi-operation compositional scope bleed and confounded observational prompt signals, plus twofold contributions (`Prompt TSG` + Temporal-Sink JCI discovery & paired ITT evaluation).
- `sections/02-problem-formulation.tex`: Multi-operation scope disambiguation, strict split isolation ($D_{\mathrm{disc}} \cap D_{\mathrm{eval}} = \emptyset$), endpoint separation ($Y_C, Y_E, Y_{\mathrm{sec}}, Y_{\mathrm{func}}, Y_{\mathrm{joint}}$), and within-task paired counterfactual ITT contrasts.
- `sections/03-method.tex`: Two-stage normative specification (`Stage I: Tolerant Prompt TSG, Orthogonal Mechanisms, and Scoped Realization` + `Stage II: Temporal-Sink JCI Discovery and Paired Counterfactual Evaluation`) paired with target-operation-scoped AST security auditing.
- `sections/04-evaluation.tex`: Verified 3-RQ empirical evaluation (`RQ1`: 24-task / 96-generation live `Qwen2.5-Coder-32B-Instruct` scope protection vs.\ unscoped `flat`; `RQ2`: 48-cell multi-regime JCI deconfounding, `100%` null-control abstention, and `56.5%–82.9%` variance reduction; `RQ3`: 6-CWE endpoint decomposition and `\pendingresult` prospective confirmatory cells).
- `figures/method-overview.tex`: Two-stage three-column TikZ architecture diagram and core scientific operations table.
- `figures/method-example.tex`: Multi-operation scoping illustration (`fig2-task-grounded-intervention.png`).

## Compile

Verified with TeX Live 2026:

```powershell
$env:PATH = "C:\texlive\2026\bin\windows;" + $env:PATH
Push-Location paper\fse2027
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out main.tex
Pop-Location
```

The compiled output is `out/main.pdf`.

## Reviewer Reading Order (6 Files)

1. `main.tex`
2. `sections/01-introduction.tex`
3. `sections/02-problem-formulation.tex`
4. `sections/03-method.tex`
5. `sections/04-evaluation.tex`
6. `sections/06-conclusion.tex`
