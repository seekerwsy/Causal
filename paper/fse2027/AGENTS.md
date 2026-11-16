# ACM TOSEM Manuscript Instructions

The repository-root `AGENTS.md` and `paper/AGENTS.md` instructions apply throughout this manuscript directory (retained under `paper/fse2027/` for path continuity while targeting **ACM Transactions on Software Engineering and Methodology (TOSEM)** via `\acmJournal{TOSEM}`). This file adds venue-specific rules only:

- Preserve double-anonymous review (`\documentclass[manuscript,screen,review,anonymous]{acmart}` and zero personal paths or user handles such as `/home/<user>`).
- Keep `Data Availability` placed immediately after `Conclusion`.
- Compile with `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out main.tex` and visually inspect rendered pages after manuscript edits.
