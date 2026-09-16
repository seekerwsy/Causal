# Manuscript narrative and Method — review notes

## Scope and status

The clarity-first Method is the main manuscript's canonical
`sections/03-method.tex`. Both `main.tex` and the section-only preview read that
same file; the separate draft text has been removed. The preview is a writing
artifact, not an additional experimental method or execution path. Its authority
is `docs/protocol.md`, protocol
`phase-context-policy-v3`, draft revision 2026-09-13. The protocol remains
`SPECIFIED_DRAFT`; no claim-bearing formal result is asserted here.

The author lifted the former three-page target. The preview filename is retained
for continuity, not as a length constraint. A SQL deletion task provides a
running example from source representation through causal analysis to explanation
and guidance; it is illustrative, not an experimental result. This revision is
local only. No Overleaf synchronization, provider call, or formal study is authorized.

The requested conceptual addition is **typed symbolic graph representation
language**. It names the type system, symbolic vocabulary, permitted relations,
source grounding, and query interpretation underlying Prompt TSG. Each extracted
task graph is an instance of that language. It does not assert a new general
purpose programming language, a complete semantics of natural language, or a
new causal discovery algorithm.

## Narrative and section contracts

The approved name is **CausalGuide: Causal Analysis for Explainable Security
Guidance in LLM Code Generation**. The main story is to establish causal evidence
about changing a task-bound security requirement and explain what prompt
modification that evidence supports, in which scope, and with which limitations.
The two contributions are task-grounded requirement-level causal analysis and
evidence-grounded explanations/security guidance. Representation gives these
outputs task-local meaning; budgeted prioritization and independent randomized
evaluation support evidence acquisition. Neither secure prompting, concept
graphs, causal analysis, nor actionable explanations alone is claimed as new.

- Introduction: move from the developer's modification decision to three
  difficulties: task-local meaning, causal support, and evidence-to-guidance
  interpretation. Finish with the three stages and two contributions. Reuse the
  verified closest-work map below; do not claim a missing capability for all prior work.
- Problem Formulation: use SQL deletion to define the explanation object and
  expected output before the endpoint. Explain the matched comparison, scope,
  and distinction between population-average evidence and an individual guarantee.
- Method: carry the same requirement through representation, causal evidence,
  and a specified explanation/reporting contract. Keep Typed Symbolic
  Representation within Stage I and all six existing equations intact. Source
  and implementation evidence below support the existing path; protocol Section
  15.1 supports the new prospective reporting design, not implemented capability.
- Evaluation: connect RQ1 selection quality, RQ2 structural-gate contribution,
  RQ3 hardening evidence, and RQ4 perceived explanation utility. Preserve the
  author's four RQ sentences verbatim; their broad wording does not expand the
  currently specified experiments.
- Related Work: acknowledge causal explanations, prompt adjustment, and joint
  security/functionality objectives in prior work; distinguish the correspondence
  between source-bound requirements, explicit comparisons, evidence, and guidance.
- Conclusion: synthesize the method and its claim boundaries, not unobserved
  empirical findings.

The abstract is intentionally not filled. Its eventual skeleton is the
requirement-level guidance decision, task-scope/causal-evidence/explanation
challenges, the two-part methodological response, verified held-out and expert
study results, and their bounded
implication. The results move remains `[RESULT_NEEDED: frozen formal outputs]`;
`[ABSTRACT_NEEDED: main empirical evidence is not yet available]` stays open.
The title and protocol positioning change, but experimental rules and bibliography
do not. No new figure was requested or added in this prose revision. The existing
Data Availability section is included after Conclusion; it states intended
artifact contents without asserting that a package has already been released.

## Method blueprint

Reader before: understands the requirement-level guidance question. Reader
after: can trace the applicable requirement and edit to a defined comparator,
independent effect evidence, and the action or withheld advice that evidence
permits. Each stage must explain its role and boundary, not reproduce code chronology.

| Reader-facing stage | Scientific operations | Core content |
|---|---|---|
| Structured graph representation | Representation | Typed Symbolic Representation; Graph Construction and Grounding; Context and Requirement Queries; source bindings and four-valued states |
| Requirement-level causal analysis | Prioritization; hypothesis freeze; intervention/randomization; measurement; outcome assembly; inference | Atomic/Pair hypotheses; support and structural admission distinct from RD ranks; fixed budgets and common bridge; addition/removal; matched controls and factorial cells; independent measurement; fixed-weight task-unit ITT; separate simultaneous families |
| Evidence-grounded explanations and guidance | Human-facing reporting within inference/reporting | Fixed content order over linked source/policy/inference records; selection rationale distinct from effects; functionality/coverage/scope; evidence-conditioned advice or explicit withholding |

Keep the explanatory emphasis on task-local requirement scope, the single
structural difference between selector variants, and the separation of generation
randomness from independent task units. Explain the main selection path before
its ablations, and introduce each estimator through its scientific meaning.
Equations specify the graph, factorial arms, safety outcome, task-unit mixture,
and effect contrasts. Stage I first inventories source facts, then binds fixed
local instance IDs, and finally assesses requirement applicability and source
expression separately within fixed scopes. Binding cannot add or relabel facts,
and assessment cannot introduce a new scope. These are source-only operations
within representation, not additional scientific stages. A missing graph match
is not sufficient evidence of requirement absence.
Requirement addition and removal are intervention directions, not separate
top-level components. Stage II defines the proposed direction as part of the
hypothesis and explains its realization and controls within the same stage. The Atomic
FCI gate and observational RD rank are explicitly distinguished: FCI supplies
structural admission, while independently computed RD scores supply priority.
Pair admission instead uses the Prompt-TSG relation gate. Observational RD
prioritizes candidates; assigned-arm RD estimates the frozen intervention
effect. Stage III presents those linked records; it is not a second inference
path or a new data role. Yield@K is explained in RQ1, not used as an explanation score.
Implementation filenames, hashes, provider incidents, old catalog tables, and
historical result labels do not belong in the manuscript prose.

## Evidence hooks

All method facts below are `preexisting_artifact` evidence. They establish the
specified procedure and inspectable implementation, not execution of a formal
experiment.

| Draft topic | Normative evidence | Implementation hook |
|---|---|---|
| Representation language and source semantics | Protocol §§5.1–5.5 | `task_input.py`, `prompt_contract_extract.py`, `prompt_contract.py`, `prompt_tsg.py` |
| Atomic/Pair semantic policies | Protocol §6 and §§24.2–24.3 | `mechanisms.py`, `interaction_selector.py` |
| Shared ranks and structural Gates | Protocol §§7–8, §24.3 | `prioritization.py`, `interaction_selector.py`, `selector_analysis.py` |
| Realization allocation and balanced requests | Protocol §§9–10, §§24.4–24.6 | `randomization.py` |
| Outcomes and mixture estimator | Protocol §11, §24.8 | `measurement.py`, `outcomes.py`, `inference.py` |
| Simultaneous intervals and Yield@K | Protocol §12, §24.9 | `inference.py`, `selector_analysis.py` |
| Optional source supplementation and inactive extensions | Protocol §25 | `discovery_population.py`, `study_design.py` |
| Evidence available for explanation | Protocol §§11–15, §18 | `TaskHypothesisBinding`; `SharedEvidenceRecord` / `TargetEffectEstimate`; `selector_analysis.build_target_rq_tables` and `unique_effect_rows` |
| Explanation mapping and guidance boundaries | Protocol §15.1; approved 2026-09-13 revision | Specified only: no active explanation-composition function or adoption-decision field was verified; the development TSG viewer is not this implementation |

## Explanation and RQ4 design boundary

The fixed explanation content order is task scope -> requirement/location ->
edit/comparator -> effect evidence -> functionality/uncertainty -> supported
action. Semantic, observational, and randomized statements retain distinct
sources. Task binding does not identify an individual treatment effect or prove
transportability to a new population. Realization-specific eligible populations
and original mixture weights remain part of the reported effect's scope.

The new protocol Section 15.1 specifies necessary conditions and withholding
behavior. It does not invent sufficient numerical adoption criteria. Missing
secondary inference rules keep adoption advice explicitly blocked while valid
primary effect evidence remains reportable. Harmful REMOVE is not beneficial
ADD; Pair interaction is not joint benefit; non-significant functionality loss
is not proof of preservation. Source completeness alone never decides the
functional label: independent review of the generated code against the full
original task supplies pass/fail/unknown.

RQ4 compares complete explanation products under a common presentation. No
method receives evidence it did not produce. The comparison cannot isolate
the causal contribution of graph representation or wording to understanding.
Its primary construct/endpoint, baseline material construction, case sampling
across available outcome types, participant assignment, ethics, and repeated
expert/case analysis remain `[METHOD_DETAIL_NEEDED: prospective RQ4 design]`.
Actual adoption/repair success and objective comprehension are not measured by
perceived clarity, credibility, or actionability alone.

## Verified citation-to-claim map

The preview reuses the manuscript's existing bibliography. Its two method
references below were checked against primary publication sources.

- `spirtes1995fci`: FCI and causal discovery with latent variables and selection
  bias. [Primary publication page](https://www.microsoft.com/en-us/research/publication/causal-inference-in-the-presence-of-latent-variables-and-selection-bias/).
- `zheng2024causallearn`: causal-learn is the Python causal discovery library used
  for the FCI implementation. [JMLR paper page](https://www.jmlr.org/papers/v25/23-0970.html).

The narrative revision additionally checked the claim scope of the closest
existing references against primary sources; this is not a fresh verification
of every field in the full bibliography.

- `pearce2022copilot`: vulnerable generated code, without generalizing historical
  rates to current models. [Paper](https://arxiv.org/abs/2108.09293).
- `tony2025prompting`: multiple security-prompting techniques, including
  CWE-specific instructions, not only generic reminders.
  [Paper](https://arxiv.org/html/2407.07064v2).
- `nazzal2024promsec`: prompt optimization through code feedback with security
  and functionality objectives. [Paper](https://arxiv.org/html/2409.12699v1).
- `ji2025causality`: human-understandable prompt/code concepts, causal analysis,
  and prompt adjustment are already present in prior work.
  [Publication record](https://researchportal.hkust.edu.hk/en/publications/causality-aided-evaluation-and-explanation-of-large-language-mode/).
- `velasco2026smells`: causal analysis of generation strategy, model, and prompt
  formulation with code-smell mitigation.
  [Paper](https://arxiv.org/html/2511.15817v7).
- `chen2026nlperturbator`: natural-language transformations for robustness;
  the rewrite does not call every transformation semantics-preserving.
  [Paper](https://arxiv.org/html/2406.19783v1).
- `peng2025cweval` and `vero2025baxbench`: executable security and functionality
  assessment. [CWEval](https://arxiv.org/html/2501.08200v1);
  [BaxBench](https://proceedings.mlr.press/v267/vero25a.html).
- `dai2026rethinking`: functionality and measurement limitations affect the
  interpretation of apparent security improvement.
  [Publication page](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/175/Rethinking-the-Evaluation-of-Secure-Code-Generation).

## Template profile

The [FSE 2027 Research Papers instructions](https://conf.researchr.org/track/fse-2027/fse-2027-papers)
specify the single-column `acmsmall` style and permit numeric citations. The
preview uses the existing `acmsmall,screen,review,anonymous` class options and ACM
bibliography style without reducing fonts, margins, or line spacing. The full
submission limit is 18 pages of text/figures plus 4 pages of references; the
author has lifted the former 2–3 page target for this Method draft. The preview
contains no floats, so there is no separate float-placement map.

## Details reserved for the full paper or appendix

The Method states the design; experiment settings must later supply the
actual qualified language/task scope, fixed model and decoding policy, generation
slot count, role counts, K values, effect margins, power, and evaluator validation.
These numbers cannot be inferred from development batches. Exact query/rewriter
contracts, fold rules, bootstrap validity predicates, and calibration examples
can accompany the artifact or appendix. Context-modifier inference, cross-model
replication, and Pair response-pattern labels remain inactive until their own
rules are prospectively frozen. RQ4 is a separate downstream human study.

Specifically, context-modifier inference still needs exact assignment, joint
bootstrap, and multiplicity rules; Pair response-pattern labels additionally
need deterministic predicates and precedence. A replication model requires its
own prospectively frozen model-bound effect coordinate. Optional Expert/Random
selectors require a jointly frozen budget. Optional discovery-population
supplementation is one outcome- and selector-blind acquisition round of
independent natural tasks against context-only targets, never factor-state or
four-cell filling. These extensions are omitted from the main Method prose.

## Build and review

From `paper/fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out/method-concise method-concise-preview.tex
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out/main-integration main.tex
```

Built with TeX Live 2026, pdfTeX 1.40.29, latexmk 4.88, and acmart 2.16 on
Windows on 2026-09-13. Both final builds returned exit code 0. The Method preview
has seven pages including its two references; the integrated main manuscript
has fifteen pages including references. All fifteen main pages and all seven
preview pages were rendered and visually inspected in their final form. No unresolved
references or overfull boxes remain. The main manuscript retains one
bibliography underfull-line warning and its existing ACM reference-block
warning; the section-only wrapper has expected missing-front-matter warnings.
The final main page contains the end of the bibliography. No fonts, margins,
line spacing, template options, or float settings were changed to control
length. Two discretionary break opportunities in the seven-operation summary
resolved a long slash-connected term without altering its content. No clipped
text, equation overflow, or unreadable section transition was observed. There
are no active floats to relocate in either document.

The revision used writing-ai-paper for the contribution/narrative decisions,
academic-paper-writer in existing-section revision mode, academic-polishing for
prose and claim strength, academic-reviser for bounded cross-section review, and
academic-latex-layout for audit and a minimal line-break repair, with pdf for
rendered-page inspection. The review checked evidence before argument and style.
The main changes replace the selection/testing-centered story with task-grounded
causal analysis for explanation and guidance, add a specified Stage III reporting
contract, and distinguish complete-product RQ4 utility from computational effect
evidence. Independent reviews were incorporated in two bounded rounds. Corrections
separate adverse Atomic effects from negative Pair interactions, require adoption
rules to be frozen before relevant outcomes are inspected, avoid implying an
already preregistered expert study, and distinguish the behavior an explanation
states must be preserved from evidence that generated code actually preserves it.

Scientific consistency checks covered independent Atomic/Pair eligibility,
FCI admission versus observational RD ranking, the common fixed-budget bridge,
model-bound result reuse, one-realization allocation, assigned-arm task-unit
accounting, unknown handling, fixed-mixture estimation, and separate max-|T|
families. Direct source comparisons confirm that the four RQ sentences and six
equations are unchanged. Main and preview still read one canonical Method file;
the manuscript title and protocol positioning were updated together. Protocol
Section 15.1 is a prospective reporting specification, not another execution path
or a claim of an implemented explanation generator. The abstract source,
bibliography, experimental implementation, frozen identifiers, and research
artifacts were not changed by this revision. No formal execution, new task
exposure, provider call, commit, push, or Overleaf synchronization was performed.

## Bounded verification status and remaining evidence

Input scope: the six revised sections, current normative protocol and relevant
implementation hooks, and primary-source checks for the closest literature.
This verifies the wording of a specified method and its cross-section
consistency. It does not qualify the extractor or Oracle, run the formal study,
verify every bibliography field, or establish a submission-ready paper.

- Whole-paper verdict: blocked; safe_to_continue: yes.
- prose_debt: closed for the revised passages; the bounded review corrections are
  incorporated.
- section_contract_debt: open for the full empirical paper because the abstract
  and result-bearing argument remain incomplete; the revised method narrative
  and section transitions have been checked.
- citation_debt: open for a final full-bibliography/citation-to-claim audit;
  the closest-work claim checks are recorded above.
- evidence_debt: open for representation/measurement qualification, the specified
  explanation product's implementation and evaluation, and formal evidence of
  selection quality, intervention effects, and perceived utility. Existing
  inference records establish available inputs, not an executed explanation study.
- figure_debt: closed for this prose-only revision; no new figures or tables
  were in scope and no dangling references were introduced.
- protocol_debt: open for the actual admitted scope, task/model policies,
  budgets and comparator bridge, Oracle qualification, power/margins, and
  separately governed RQ4 design. Exact secondary margins, coverage conditions,
  and joint adoption predicates must be prospectively fixed before inspecting
  relevant Confirmation outcomes; absent rules withhold adoption advice, not
  otherwise valid primary effect reporting.
- result_debt: open; no formal RQ1–RQ4 outputs or traceable result tables exist.
- rationale_debt: closed for the revised core design explanations.
- thin_draft: yes as a complete empirical paper, not as a Method section.

Claims about reliable extraction, Full outperforming its comparators,
beneficial hardening, and experts' utility assessments remain unasserted. Current
prose specifies how to test these claims rather than asserting their outcomes.
They require the corresponding prospective freeze, qualification, and
claim-bearing formal evidence before being written as findings. No additional
experiment was authorized or needed to finish this narrative revision.
