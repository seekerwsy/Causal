# Paper Contract Successor Audit

**Date:** 2026-08-20  
**Mode:** `audit` followed by authorized `revise`  
**Workspace:** `D:\MyCode\Causal\.worktrees\dataset-availability-audit`  
**Branch:** `codex/phased-exploration-v3`

## Authority and scope

The prospective paper contract is governed by, in descending authority:

1. the user's instruction for this revision;
2. `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`;
3. `paper/AGENTS.md` and
   `.agents/skills/secaware-fse-paper/references/causal-boundaries.md`;
4. the legacy 2026-07-13 method and 2026-07-22 RQ specifications only for
   runs whose immutable manifests declare those protocols; and
5. the current manuscript and paper contract test.

The authorized write scope is limited to the manuscript, its overview figure,
the paper contract test, and this ledger. No quantitative result is inserted:
all `--` and `\resultslot` placeholders remain unresolved until a frozen run
artifact and table builder provide traceable evidence.

## Baseline audit evidence

Before revision, the existing paper contract reported four passing tests:

```text
.venv\Scripts\python.exe -m unittest tests.paper.test_secaware_fse_paper_contract -v
Ran 4 tests ... OK
```

That green result was not successor evidence. The test explicitly required the
three obsolete RQ sentences plus main-paper RQ4, accepted `task-cluster` rather
than the highest `semantic_task_cluster_id`, and required only that JCI/RFCI
appear somewhere. It therefore positively enforced the legacy contract that
the successor specification supersedes.

The project paper skill itself passed its structural validation before edits:

```text
.venv\Scripts\python.exe C:\Users\WuSiyu\.codex\skills\.system\skill-creator\scripts\quick_validate.py .agents\skills\secaware-fse-paper
Skill is valid!
```

## Conflict-and-evidence ledger

| Claim or contract | Higher-authority evidence | Baseline manuscript/test evidence | Status before revision | Required action / acceptance evidence |
| --- | --- | --- | --- | --- |
| Main paper has exactly three RQs | Successor Sections 16--17; causal-boundaries `Research Questions` | Manuscript and test require RQ1--RQ4 | Contradicted | Use the three successor sentences exactly; remove the RQ4 subsection and table; make the contract reject any main-paper RQ4 |
| RQ1 is budgeted selector prioritization on one shared candidate universe | Successor Sections 2 and 8.1--8.2 | RQ1 foregrounds method-native discovery and confirmation | Contradicted | Make FCI, association, regularized prediction, expert, and random selectors consume the same frozen universe and information budget |
| RQ1 primary metric is strict confirmed yield at `K` with paired selector utility differences | Successor Sections 8.2 and 12 | Manuscript uses a native funnel as the main track and says only “confirmed yield” | Contradicted | Put strict confirmed yield@`K` and paired differences in the primary table; keep failed/empty slots in denominator `K` |
| Native-system funnel is secondary end-to-end evidence | Successor Sections 8.4 and 16 | Native `K -> native -> mapped -> ...` funnel is primary RQ1 design | Contradicted | Retain the funnel as a secondary compatibility track and label mapping coverage a bridge diagnostic |
| RQ2 separates selector-only and representation experiments | Successor Sections 8.2--8.3 and 16 | Manuscript uses the legacy two-by-two ablation | Contradicted | Hold the universe fixed for selector-only comparison; compare direct versus direct+context universes end-to-end and do not call that pure selector superiority |
| RQ3 asks which interventions reliably improve secure code generation | Successor Section 16 | Manuscript says defensive interventions “reduce insecure code generation” | Contradicted | Use the exact successor RQ3 and report model-specific context-conditioned policies |
| Primary safety outcome is oracle-evaluable secure-code yield | Successor Section 11.1 | Earlier RQ3 text/table calls secure-and-functional the primary outcome | Partially aligned elsewhere, contradicted in RQ3 | Make `Y_C Y_E I(secure)` primary; keep `Y_joint` as key practical secondary and report validity/support/unknown/bounds separately |
| ADD and REMOVE are atomic, separately selected and tested policies | Successor Sections 6, 9.2, and 12 | General methods separate them, but RQ3 lacks the successor source-state and result structure | Incomplete | State separate candidate slots, hypotheses, protocols, contrasts, multiplicity coordinates, and bidirectional evidence only after both independent tests |
| `X^0`, randomized arm `A`, and diagnostic `X^{A,R}` are distinct | Successor Sections 4 and 22.1 | Problem formulation has the distinction, but the legacy RQ/contract does not enforce it | Incomplete contract | Add positive and negative contract checks; never let fidelity/PP determine ITT evidence |
| Hypothesis is context-conditioned with one non-actionable `C_q` and exactly one actionable feature | Successor Sections 5.4 and 6 | Manuscript still uses broad “mechanism” and older target language in evaluation | Incomplete | Define and use `h=(C_q,f,a,Q_h,Y)`; remove unique-mechanism claims |
| Highest independent/resampling unit is `semantic_task_cluster_id` | Successor Sections 10 and 12 | Manuscript prose mixes `task cluster`, `task_id`, and semantic clusters; overview says task bootstrap | Partially aligned | Name `semantic_task_cluster_id` explicitly and update overview to semantic-cluster bootstrap |
| JCI and RFCI are appendix-only and non-promoting | Successor Sections 15 and 17 | Main methods include a “Secondary Structural Analysis” subsection and synthetic section foregrounds JCI | Contradicted in placement | Remove substantive JCI/RFCI analysis from the main method/evaluation; add a clearly optional appendix scope; contract must reject promotion |
| Implementation markers, fidelity, and PP analyses are diagnostics only | Successor Sections 14--15 | Main methods state non-promotion, but the contract does not enforce it | Incomplete contract | Preserve diagnostic wording and add contract assertions against evidence promotion |
| Human expert-perception study is separately versioned optional work, not main RQ | Successor Section 17 | Manuscript contains RQ4 tables, threats, human-study reproducibility, and data-availability promises | Contradicted | Delete the main RQ and human-study mainline promises; mention only an optional separately governed study in the appendix |
| Main claims do not assert unique Prompt mechanisms, code mediation, or individual causal flips | Successor Sections 7.1, 14, and 16 | RQ1/RQ2 and conclusion repeatedly call candidates mechanisms | Contradicted | Reframe as prioritization and randomized policy effects; retain Prompt TSG/causal-graph separation |
| Unsupported results remain placeholders | Skill Evidence Rules | Manuscript contains `--` and `\resultslot` | Aligned | Preserve every placeholder; contract guards the placeholder count against accidental result fabrication |
| Data Availability follows Conclusion and anonymity is preserved | `paper/AGENTS.md` and skill | Existing ordering and document class satisfy this | Aligned | Preserve ordering and anonymous review class |

## Revision evidence to collect

Revision is accepted only when all of the following evidence exists:

1. the successor paper contract test passes and actively rejects the legacy
   RQs, main-paper RQ4, the legacy two-by-two design, secure-and-functional as
   primary, task-level highest-cluster wording, and diagnostic evidence
   promotion;
2. stale-term searches show no main-paper legacy RQ, RQ4 subsection, human-
   study result table, or unique-mechanism claim;
3. the project paper skill remains structurally valid;
4. LaTeX compiles when the local toolchain is available; and
5. rendered pages are visually inspected for overflow, unreadable tables,
   clipping, spacing, and figure placement.

This audit concerns prospective paper alignment only. It is not evidence that
the prospective computational experiments have run or that any hypothesis has
been confirmed.

## Final revision verification

The successor-aligned revision satisfies the planned acceptance evidence:

1. `python -m unittest tests.paper.test_secaware_fse_paper_contract -v`
   passed all 7 contract tests. The contract now requires exactly the three
   successor RQs, the shared-universe selector design, strict confirmed yield
   at `K`, the selector/representation separation, the primary secure-code
   yield, atomic ADD/REMOVE evidence, diagnostic non-promotion, placeholder
   preservation, and the required section ordering.
2. `quick_validate.py .agents/skills/secaware-fse-paper` returned
   `Skill is valid!`.
3. The frozen stale-term search returned no match in the manuscript or overview
   figure. A main-text/appendix split check found no JCI, RFCI, implementation-
   marker, treatment-fidelity, per-protocol, human-study, or expert-perception
   term before `\appendix`; the required optional terms occur only after it.
4. `git diff --check` reported no whitespace error in the four authorized
   files. Its only output was Git's Windows LF-to-CRLF advisory.
5. `latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out
   secaware-fse2027-draft.tex` completed successfully and produced a 13-page
   PDF. The log contains no overfull box, undefined citation, or undefined
   reference. The remaining non-blocking diagnostics are one underfull
   bibliography line, the pre-existing anonymous-review ACM-reference-format
   warning, and the local Windows Perl locale fallback.
6. All 13 rendered pages were visually inspected. The overview, equations,
   tables, RQ headings, appendix boundary, references, margins, and page breaks
   show no clipping, overlap, unreadable type, or misplaced result table.

All numeric cells remain `--`/`\resultslot` placeholders. Consequently, this
verification establishes a prospective manuscript and executable paper
contract aligned with the successor protocol; it does not manufacture or
promote experimental findings.
