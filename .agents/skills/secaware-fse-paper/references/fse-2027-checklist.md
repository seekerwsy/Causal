# FSE 2027 Submission Checklist

This checklist records the venue-facing assumptions used for the current
draft. Confirm them against the official call immediately before submission;
venue rules can change. Last checked: 2026-07-22.

Official source: <https://conf.researchr.org/track/fse-2027/fse-2027-research-papers>

## Source Contract

- Use ACM `acmart` with `acmsmall`, `screen`, `review`, and `anonymous`.
- Keep the review draft single-column.
- The research-paper limit is 18 pages of main text plus up to 4 pages of
  references under the current call.
- Preserve double-anonymous review: remove identifying authors, affiliations,
  acknowledgments, repository URLs, and self-identifying artifact metadata.
- Place a Data Availability statement after Conclusion.
- Maintain a private generative-AI use ledger so the final submission can make
  any disclosure required by the venue without exposing author identity in the
  anonymous draft.

## Content Checks

- The abstract states the problem, approved method, primary experimental
  design, and honest result status without invented numbers.
- RQ1--RQ4 match the approved sentences exactly.
- Every results table is generated from one frozen run or visibly retains
  placeholders.
- Statistical claims name the estimand, unit, contrast, clustered uncertainty,
  multiplicity handling, and denominator.
- Failure, null, conflict, and non-evaluable categories remain visible.
- Current implementation status is separated from planned paper evaluation.
- Threats cover Oracle validity, latent confounding/PAG ambiguity,
  intervention noncompliance, multiplicity, external validity, and subjective
  human ratings.

## Anonymous Artifact Checks

- No author names, institutions, emails, local usernames, private URLs, or Git
  remote identities appear in TeX, PDF metadata, supplemental files, logs, or
  screenshots.
- Artifact identifiers are opaque and do not reveal organization names.
- Frozen manifests include model/config identifiers, seeds, task splits,
  Oracle versions, hypothesis freezes, assignments, and artifact digests.
- Exploratory runs and mock/demo artifacts are excluded from paper tables.

## Build and Layout Checks

Run from `paper/fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out secaware-fse2027-draft.tex
```

Then check:

- compilation exits successfully;
- no undefined references or citations;
- no missing glyphs or accidental raw underscores;
- no material overfull boxes;
- tables and figures remain readable in single column;
- page count stays within the venue limit;
- front matter is anonymous;
- Data Availability follows Conclusion;
- the PDF contains no stale results or TODOs that look like findings.
