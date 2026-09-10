# CWE inventory tables (stored for later inclusion)

These tables are available in the Overleaf-ready paper project but are **not
included in `main.tex` or any manuscript section**.

- `cwe-main.tex`: the 20 most frequent source CWE labels, grouped into six
  display categories; 1,333 of 1,992 independent task units (66.9%).
- `cwe-appendix.tex`: all 117 source labels, comprising 116 weakness entries
  and the historical CWE-730 category.
- `preview.tex`: a standalone preview of both tables, using the manuscript's
  `acmart` class and options. It is not the manuscript entry point.

The last column counts task units carrying each source label. Task forms are
illustrations derived from 214 inspected source examples, not an exhaustive
pattern taxonomy or per-pattern counts. The source labels do not establish
validated vulnerabilities or intervention eligibility. One task has both
CWE-120 and CWE-121; totals count it once. Selecting 20 labels for display does
not change the study scope or authorize formal use.

## Preview

From the paper project root (`paper/fse2027`):

```text
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out/cwe-inventory tables/cwe-inventory/preview.tex
```

The result is `out/cwe-inventory/preview.pdf` (one page for the main table and
six for the full appendix). In Overleaf, temporarily select
`tables/cwe-inventory/preview.tex` as the main document to inspect the tables;
use `main.tex` for the manuscript.

The main table needs `booktabs`, `multirow`, and `tabularx`, which the current
manuscript already loads. The appendix additionally needs `longtable`; it
must not be nested inside a `table` float. No inclusion commands or packages
have been added to the manuscript.

## Source and reproduction

The table bodies are byte-identical copies of the reviewed 2026-09-11
descriptive inventory outputs. The single generation path remains in the
research repository:

`docs/experiments/cwe-pattern-inventory-20260911/paper-tables/build.py`

That builder checks the candidate-pool snapshot against `inventory.json`,
recounts the task identities for every CWE, applies the explicit top-20
selection rule, and renders `display.tsv` with its `row(cwe, category)` function.
The original directory contains the complete data report, Chinese workbook,
example identities, and layout verification. This paper directory stores
the resulting tables; it does not introduce another builder.

SHA-256 identities:

| Artifact (repository-relative path) | SHA-256 |
|---|---|
| `data/dataset-curation/research-candidate-pool-v2/tasks.json` | `8fe351cf97c55686252ed88cdf14c77ae268633ad2a8e52db8d73b3bd00497c7` |
| `docs/experiments/cwe-pattern-inventory-20260911/inventory.json` | `579034233cda8c4a66439eff8102f9745d64d46e74763d4a802bf978c2156b67` |
| `docs/experiments/cwe-pattern-inventory-20260911/paper-tables/build.py` | `61ea2c6a332e914a8a858dadff963a4f970473c10141a8566bf103feeeb26c05` |
| `docs/experiments/cwe-pattern-inventory-20260911/paper-tables/display.tsv` | `1f1cb5797e0eb747f8dbf3d05e5c46ad63213407df7161357855321ded4f1af3` |
| `cwe-main.tex` (this directory) | `a41fc266a88cf21c5c865f131ae70cb41e3a249f99462e2b4bd8aaad0682e86c` |
| `cwe-appendix.tex` (this directory) | `87949cfa04ac5b44ff54a4f612f6f589763637dd693b14a6802182701a352f80` |

The wrapper was compiled and the rendered output checked in this paper
location with TeX Live 2026. The tables preserve their previously verified
counts and layout. The standalone preview has no paper front matter, so
acmart may report missing metadata for a document longer than two pages.
