# CausalGuide ACM TOSEM Manuscript

This directory contains the anonymous **ACM TOSEM** manuscript draft (`\acmJournal{TOSEM}`, `SPECIFIED_DRAFT`).

## Main Files

- `main.tex`: Anonymous manuscript entry point (`acmart`, `manuscript,screen,review,anonymous`).
- `sections/01-introduction.tex`: Problem framing around multi-operation scope ambiguity and confounded structural attributes, plus twofold contributions (`Prompt TSG` + Directional Cross-Fitted `JCI`).
- `sections/02-problem-formulation.tex`: Motivating multi-operation example, task-unit ITT estimand, and endpoint separation (`Y = Y_C Y_E I{secure}`).
- `sections/03-method.tex`: Two-stage normative specification (`Stage I: Task-Grounded Graph Representation` + `Stage II: Directional JCI Discovery and Cross-Fitted Effect Learning`, including `Scoped Evidence Output`).
- `sections/04-evaluation.tex`: Focused 3-RQ evaluation design (RQ1: `Prompt TSG` representation & binding; RQ2: Directional JCI & cross-fitting precision; RQ3: End-to-end positive security hardening vs. adverse warnings). Formal natural-task tables remain `\pendingresult` (`\textit{TBD}`) until prospectively frozen and executed.
- `figures/method-overview.tex`: Two-stage TikZ architecture diagram and core scientific operations table.
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
