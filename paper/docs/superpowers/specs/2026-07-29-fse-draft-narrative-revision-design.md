# FSE Draft Narrative Revision Design

**Date:** 2026-07-29  
**Status:** Approved in conversation; awaiting written-spec review  
**Scope:** Results-free narrative, structure, terminology, citations, figures,
tables, and layout revision of
`paper/fse2027/secaware-fse2027-draft.tex`

## 1. Objective

Revise the current SecAware FSE draft into a high-quality pre-results
manuscript. The revision must read as a research paper rather than a design
memo, while preserving every approved causal-design, evidence, provenance, and
research-question boundary.

The manuscript should make one central progression easy to remember:

```text
security-aware prompt representation
    -> stable causal hypotheses
    -> confirmatory effect evidence
```

The revision does not authorize quantitative result backfilling. Unsupported
result cells remain explicit `--` entries until they can be traced to frozen
artifacts and table builders.

## 2. Authority and Non-Negotiable Boundaries

Contradictions are resolved in this order:

1. the user's current explicit instruction;
2. the approved dated causal and RQ specifications;
3. frozen run manifests, immutable artifacts, and table builders;
4. implementation and tests;
5. current manuscript prose.

The revision must preserve:

- Prompt TSG as the sole prompt-side structured feature authority;
- the distinction between Prompt TSG structure and learned causal relations;
- generated code as Oracle and functional-evaluator input only;
- discover/confirm task separation;
- hypothesis and mapping freeze before confirmation;
- family-specific prompt-intervention protocols;
- task-clustered assigned-arm ITT as the primary confirmatory estimand;
- treatment-fidelity variables as diagnostics rather than ITT filters;
- hypothesis-, target-, operation-, model-, and CWE-specific effect boundaries;
- JCI as a secondary structural analysis and RFCI as optional sensitivity;
- complete reporting of null, conflicting, failed, and non-evaluable evidence;
- double-anonymous review; and
- Data Availability after Conclusion.

## 3. Narrative Design

### 3.1 Opening problem

The paper opens from the software-security consequence: prompts can specify
functionality while leaving security requirements implicit, weakly scoped, or
detached from sensitive operations. Token rankings and unconstrained
perturbations can highlight suspicious text, but they do not by themselves
produce an editable prompt-side hypothesis whose effect can be evaluated while
preserving the task.

### 3.2 SecAware response

SecAware contributes an auditable path from prompt semantics to effect
evidence:

1. represent prompt-side task and security semantics in a typed, editable
   structure;
2. use structure-derived constraints, FCI, and task-cluster stability to form
   testable hypotheses;
3. freeze those hypotheses before held-out intervention construction and
   randomized evaluation; and
4. classify hypothesis-specific assigned-arm evidence without conditioning on
   realized edit success.

The opening emphasizes these capabilities. Defensive boundaries are stated
once where necessary and then handled in Methods or Threats rather than
repeated as contribution language.

### 3.3 Claim hierarchy

The contribution hierarchy is:

1. **Security-aware representation.** Convert free-form prompts into typed,
   scoped, editable security factors and relational motifs.
2. **Stable hypothesis discovery.** Combine structural constraints, FCI, and
   task-cluster stability to prioritize reproducible, intervenable candidates.
3. **Causal effect confirmation.** Convert frozen candidates into typed prompt
   interventions and assigned-arm ITT evidence on held-out tasks.
4. **End-to-end evidence accounting.** Measure whether a method progresses from
   native candidates through mapping, protocolization, randomization, and
   confirmation under a fixed candidate budget.

The compact causal boundary is:

> Prompt TSG supplies structured variables and constraints; causal evidence
> comes from discovery and randomized confirmation, not from graph structure
> alone.

## 4. Manuscript Architecture

The revised manuscript uses this order:

1. **Introduction**
2. **Motivating Example and Problem Formulation**
3. **Security-Aware Prompt Representation**
4. **Stability-Guided Causal Discovery**
5. **Causal Effect Confirmation**
6. **Evaluation Design and Results**
7. **Related Work**
8. **Threats to Validity**
9. **Reproducibility**
10. **Conclusion**
11. **Data Availability**

The current standalone `Implementation and Study Status` section is removed
from the paper narrative. Implementation and study completion remain explicit
in the repository README, the evidence ledger, source-level result markers,
and verb tense:

- verified implemented capabilities use present tense;
- approved but unexecuted evaluation work uses future tense;
- final-run result fields remain `--`;
- no planned baseline or human study is described as completed.

The current title remains:

> **Discovering and Confirming Prompt-Side Security Mechanisms in LLM Code
> Generation**

A result-driven title change is deferred until frozen evidence identifies the
strongest supported finding.

## 5. Method Stage Names and Responsibilities

### 5.1 Security-Aware Prompt Representation

This stage introduces Prompt TSG only after the plain-language task has been
established. It covers typed task, security, and presentation semantics,
catalog-bound features, evidence spans, canonicalization, graph-derived
features and motifs, and local causal-variable tables.

### 5.2 Stability-Guided Causal Discovery

This stage covers TSG-derived background knowledge, causal-learn FCI with the
G-square test, task-cluster bootstrap stability, endpoint-aware possible-path
selection, and pre-confirmation hypothesis freeze. It does not claim a new FCI
algorithm or a uniquely recovered DAG.

### 5.3 Causal Effect Confirmation

This stage covers typed TargetSpecs, family-specific arm protocols, hard
pre-randomization freeze gates, blocked random assignment, independent
Oracle/functional outcomes, task-clustered assigned-arm ITT, specificity
contrasts, evidence classification, and secondary JCI/RFCI analyses.

Randomization remains scientifically non-negotiable but appears as the
confirmation technique rather than the stage headline.

## 6. Motivating Example

The motivating example is explicitly illustrative and contains no empirical
effect claim. It shows:

1. a security-neutral programming request;
2. the prompt-side security factor that is implicit or absent;
3. a structured target and operation;
4. the corresponding target, no-op, placebo, and generic-control roles for a
   safety protocol; and
5. the hypothesis-specific effect that the final study is designed to
   estimate.

The example must not claim that generated code was vulnerable, that an edit
improved security, or that the target was confirmed. A final paper-run case may
replace it only when the prompt, hypothesis, variants, assignment, and outcome
summary are traceable to frozen artifacts.

## 7. Evidence and Citation Policy

### 7.1 Quantitative evidence

Every inserted quantitative result requires:

- a frozen artifact path and exact field;
- run and configuration identity;
- dataset version;
- model provenance;
- the table-building or aggregation path; and
- consistency with the approved estimand and multiplicity family.

No value may be inferred from prose, a plot, an exploratory run, or a nearby
table row.

### 7.2 Citations

Related Work and background claims use verifiable primary papers or official
technical documentation. Literature families include:

- FCI/PAG discovery under latent confounding;
- Joint Causal Inference;
- the causal-learn implementation used by the minimum backend;
- prompt explanation, attribution, concept, and perturbation methods;
- security evaluation of LLM-generated code; and
- randomized intervention and ITT analysis where a methodological claim needs
  support.

A cited related method is not described as an executed baseline unless its
adapter, version, native output, mapping policy, and frozen manifest exist.

### 7.3 Draft-state visibility

The abstract no longer advertises “design-stage draft” as the paper's final
message. It includes a clearly marked source-level position for frozen headline
results. Tables retain visible `--` values until evidence is available.

## 8. Required Consistency Corrections

The revision applies these corrections:

1. Replace one-hot JCI language with one categorical `C_arm` column whose
   values are the protocol's finite arm roles.
2. Describe the deterministic catalog extractor as an explicitly selected,
   run-locked backend, never as an automatic fallback.
3. Place independent re-extraction and treatment-fidelity diagnostics in
   variant construction and freeze; never imply that post-outcome diagnostics
   determine primary eligibility.
4. Restrict four-arm language to family-valid Safety ADD and Safety REMOVE
   protocols. Task-function and presentation protocols retain their approved
   family-specific arm sets.
5. Encode valid post-assignment terminal generation, parse, functional, and
   Oracle-unknown outcomes under the preregistered secure-and-functional
   policy. Missing or corrupt required producers block publication and require
   deterministic replay of the same manifest.
6. Restrict `W` to approved pre-treatment task metadata. Preserve model
   identity as an analysis coordinate and provenance field rather than a
   minimum causal-table variable.
7. Permit only identical-byte transport retries. Do not imply semantic retries
   or favorable candidate selection.
8. Distinguish implemented, planned, executed, and reported status throughout.

## 9. Figure and Table Design

### 9.1 Overview figure

Replace the current boxed text placeholder with a reproducible vector figure.
The figure has three left-to-right stages matching the approved names. A
discover band contains representation, local tables, FCI/stability, and
hypothesis freeze. A confirm band begins after the freeze boundary and contains
typed prompt variants, block randomization, generation, Oracle/functional
evaluation, assigned-arm ITT, and evidence classification.

Generated code appears only on the evaluation path. The visual distinguishes
artifacts, transformations, and the freeze boundary without representing
Prompt TSG edges as causal arrows. It must remain legible in grayscale and at
the manuscript's printed width.

### 9.2 Tables

- **RQ1:** fixed-`K` end-to-end funnel with the counts and derived yields
  required by the approved RQ design.
- **RQ2:** frozen two-by-two representation-by-selection design and the same
  downstream funnel/evidence contract.
- **RQ3:** rows generated from frozen target artifacts; no unsupported named
  targets in the pre-results draft.
- **RQ4:** method identities and outcomes filled only after the study protocol,
  case manifest, rendering manifest, and analysis artifacts are frozen.

Captions state the question and statistic. They do not call a table a
“skeleton” or “placeholder outcome.”

### 9.3 Layout

Remove unnecessary `\FloatBarrier` calls that force large blank regions. Keep
figures and tables close to their first substantive discussion. Break long
method walls with stage-level lead sentences, the overview figure, and compact
subsections. Preserve anonymous ACM review formatting.

## 10. Files and Responsibilities

- `paper/fse2027/secaware-fse2027-draft.tex`  
  Revised manuscript structure, prose, equations, tables, citations, and
  figure inclusion.
- `paper/fse2027/references.bib`  
  Verified bibliography entries used by the manuscript.
- `paper/fse2027/figures/secaware-overview.tex`  
  Reproducible vector overview figure.
- `paper/fse2027/revision-evidence-ledger.md`  
  Claim, authority, artifact field, status, and action for material manuscript
  statements.
- `paper/fse2027/README.md`  
  Current manuscript scope, result-backfill boundary, build commands, and
  remaining study work.

## 11. Conflict-and-Evidence Ledger Seed

| Material statement | Authority | Current status | Required action |
| --- | --- | --- | --- |
| Prompt TSG is structured prompt semantics, not a causal graph | Approved causal design | Aligned but over-repeated | State once in setup/method; remove defensive repetition |
| Primary confirmation is task-clustered assigned-arm ITT | Approved causal and RQ designs | Aligned | Preserve and foreground as the confirmation estimator |
| JCI uses one categorical arm-context column | Approved causal design | Current draft conflicts | Replace one-hot language with categorical `C_arm` |
| Deterministic extraction is explicit, not fallback | Approved causal design | Current draft conflicts | Replace fallback wording |
| Safety protocols have four arms; other families are family-specific | Approved causal design | Current draft overgeneralizes | Qualify all four-arm claims |
| Treatment fidelity never filters ITT | Approved causal and RQ designs | Mostly aligned; timing is unclear | Move diagnostics to freeze-stage description and preserve denominator rule |
| Valid terminal non-success differs from missing producer evidence | Approved causal design | Current outcome wording is ambiguous | State zero/contract-failure boundary exactly |
| External baselines, RQ2 runs, RQ4 study, and final paper run are incomplete | Approved RQ design and causal-boundary reference | Current status section is accurate but report-like | Preserve status in ledger/README and use accurate manuscript tense |
| Quantitative paper findings | Frozen final run required | No qualifying artifact identified | Retain `--`; do not backfill |

## 12. Verification

After each meaningful manuscript revision:

1. run the paper contract test;
2. scan for stale causal and status terminology;
3. compile with `latexmk` in anonymous ACM review mode;
4. fail on LaTeX errors, unresolved citations, or unresolved references;
5. render every PDF page to PNG;
6. inspect page transitions, float placement, typography, table width,
   whitespace, headers, and anonymity;
7. compare every material claim against the evidence ledger; and
8. preserve unrelated working-tree changes.

## 13. Acceptance Criteria

The revision is complete only when:

1. page one establishes the problem, gap, three-stage method, and contribution
   hierarchy;
2. the method uses the approved three stage names;
3. all four RQs match the approved wording in substance;
4. every causal, intervention, outcome, and ITT statement matches the approved
   specifications;
5. no unsupported quantitative or completion claim appears;
6. Related Work contains only verified citations and does not imply unexecuted
   baselines;
7. the overview figure is publication-legible and no longer a placeholder;
8. result tables preserve evidence-safe blanks and approved estimand
   boundaries;
9. the contract test and LaTeX build pass;
10. visual inspection finds no clipping, overlap, illegible text, broken
    references, abnormal blank page region, or anonymity leak; and
11. the delivery report enumerates changed files, checks, remaining result
    fields, and claims blocked by missing evidence.

## 14. Out of Scope

This revision does not:

- execute or backfill final paper experiments;
- choose final external baseline implementations after outcomes exist;
- alter approved RQs, estimands, denominators, multiplicity families, or
  evidence levels;
- add Code TSG or code-side causal variables;
- promote demo or smoke-test artifacts to paper evidence; or
- suppress required null, conflicting, harmful, failed, or non-evaluable
  results.
