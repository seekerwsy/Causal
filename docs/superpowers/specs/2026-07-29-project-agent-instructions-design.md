# Project-Level Agent Instructions Design

**Date:** 2026-07-29  
**Status:** Approved design awaiting implementation  
**Scope:** Repository-wide implementation discipline and SecAware paper-writing discipline

## 1. Objective

Create a root-level `AGENTS.md` that applies to the entire repository and
strengthen `paper/AGENTS.md` with the approved academic-launch narrative
principle. The instructions must make future implementation and manuscript
work reproducible, traceable, evidence-based, and narratively focused.

## 2. Instruction Placement

### Root `AGENTS.md`

The new root file will contain two sections:

1. **Code implementation requirements:** the fourteen user-approved rules on
   requirement alignment, explicit implementation explanations, small-scale
   validation before scale-up, complete artifact retention, immutable history,
   environment and output-path control, failure recovery, safe concurrency,
   complete progress reporting, anomaly investigation, reuse of existing
   implementations, error-learning records, and end-to-end reproducibility.
2. **General paper-writing requirements:** the thirteen user-approved rules on
   research-question-first storytelling, separation of engineering history
   from research narrative, stable terminology, coherent abstract and
   introduction structure, reference-paper-guided writing, informative
   experiments, claim-oriented interpretation, figure placement and visual
   quality, appendix boundaries, preservation of prior writing requirements,
   compile-and-render verification, and research-goal authority over reviewer
   suggestions.

These are repository-wide defaults. More specific descendant `AGENTS.md`
files may add constraints but must not silently weaken them.

### `paper/AGENTS.md`

The existing SecAware paper rules remain in place. The file will additionally
contain the complete user-provided **Academic Launch Principle**, including:

- organize the paper around its strongest defensible value;
- avoid project-report and experiment-log narration;
- state supported advantages explicitly;
- choose comparisons and experiments that serve the central claim;
- keep the abstract, introduction, figures, experiments, and conclusion
  focused on the paper's strongest evidence-backed contribution;
- permit substantial narrative restructuring when the original story is not
  supported;
- avoid unnecessary self-weakening language and gratuitous expansion of the
  paper's attack surface.

The supplied Chinese wording will be retained so that its intended force is
not lost through summarization.

## 3. Scientific-Integrity Boundary

The Academic Launch Principle controls narrative emphasis, organization,
framing, and allocation of main-text space. It does not authorize evidence
suppression or post-outcome redesign.

The following constraints will be placed immediately after that principle:

1. Approved RQs, preregistered hypotheses, primary estimands, assigned-arm ITT
   denominators, multiplicity families, evidence levels, and frozen manifests
   cannot be changed because results are unfavorable.
2. Null, conflicting, harmful, backend-failure, and non-evaluable results that
   the approved protocol requires must remain in the paper or traceable
   supplementary artifacts. Moving detail to an appendix is allowed only when
   the main text remains accurate about the result.
3. Evaluation dimensions, datasets, scopes, models, baselines, and comparison
   rules may be redesigned prospectively before outcome unblinding. After
   unblinding, a changed design is a separately labeled exploratory analysis
   or new experiment, not a replacement for the frozen primary analysis.
4. Claims may be narrowed and prose may avoid inflammatory or self-attacking
   language, but an unfavorable result must not be described as favorable or
   omitted in a way that makes the reported evidence misleading.
5. Threats to validity must be accurate, proportionate, and tied to claim
   boundaries. They should not invent weaknesses, but they also cannot conceal
   limitations that materially affect the central conclusion.
6. When narrative optimization conflicts with the approved causal design,
   frozen evidence, provenance requirements, or publication ethics, scientific
   integrity takes precedence.

## 4. Maintenance and Verification

- The root and paper instructions will use clear headings and numbered rules so
  later edits can preserve individual requirements.
- Existing `paper/AGENTS.md` content will be preserved.
- No causal-design specification, RQ definition, manuscript claim, code, or
  experiment configuration is changed by this work.
- Verification will confirm that all fourteen implementation rules, thirteen
  general writing rules, the complete launch principle, and all six integrity
  safeguards are present.
- A diff review will check that no unrelated files or instructions changed.

## 5. Acceptance Criteria

The change is complete when:

1. root `AGENTS.md` exists and contains all approved repository-wide rules;
2. `paper/AGENTS.md` contains the complete Academic Launch Principle;
3. the scientific-integrity boundary explicitly resolves conflicts with
   preregistration and evidence preservation;
4. existing SecAware-specific paper guidance remains intact;
5. the two instruction files contain no placeholder, ambiguous precedence, or
   contradictory requirement; and
6. repository checks show only the intended documentation changes.
