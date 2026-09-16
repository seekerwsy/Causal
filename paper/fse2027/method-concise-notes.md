# Manuscript narrative and Method — review notes

## Current local Method review (2026-09-16)

This follow-up revises Method only, on top of the preceding Overleaf submission.
It is **local and awaiting author review**, with no new commit or remote push.
The canonical Method and one shared method-details appendix are imported by
both manuscript wrappers. Other section prose, protocol, implementation, data,
and frozen evidence are unchanged in this follow-up.

The approved section contract is: readers enter with the requirement-level
security question and leave understanding the scoped edit, its causal comparison,
and the evidence-conditioned action. Stage I establishes task meaning;
Stage II separates selection from assigned-policy effects; Stage III converts
the linked records into Explanation + Suggested Action. Standard execution
details support this chain rather than competing with it in the main prose.

The main Method is reduced by roughly one third. Three equations remain in
the body (graph, endpoint, primary contrast); the weighted arm mean and exact
inference rules are in Appendix A. Repeated SQL background and repeated
scope disclaimers are consolidated. Stage III includes one complete,
explicitly unconfirmed SQL example, with no invented rank, effect, or recommendation.

Review reading order:

1. [Method preview](out/method-concise/method-concise-preview.pdf), Section 3:
   narrative and example.
2. The same PDF, Appendix A: relocated execution and statistical detail.
3. [Canonical Method](sections/03-method.tex) and
   [shared appendix](sections/appendix-method-details.tex): editable sources.

The citation-verification pass adds two verified references and reuses CWEval
at the measurement rationale, bringing the Method to five cited works:

- banarescu2013amr: Laura Banarescu, Claire Bonial, Shu Cai, Madalina Georgescu,
  Kira Griffitt, Ulf Hermjakob, Kevin Knight, Philipp Koehn, Martha Palmer,
  Nathan Schneider. *Abstract Meaning Representation for Sembanking*. LAW 2013,
  pp. 178–186, ACL. VERIFIED against the
  [publication and metadata](https://aclanthology.org/W13-2322/) and
  [paper](https://aclanthology.org/W13-2322.pdf). Stage I cites its concept/relation
  graph representation, not evidence that Prompt TSG is accurate or more readable.
- miller2017explanation: Tim Miller. *Explanation in Artificial Intelligence:
  Insights from the Social Sciences*. arXiv:1706.07269, 2017; reading uses v3.
  VERIFIED [metadata](https://arxiv.org/abs/1706.07269) and
  [§§2.3/2.6.2](https://arxiv.org/html/1706.07269v3). Stage III cites contrast and
  relevance as design motivation, not proof of this method's explanation utility.
  This entry cites the verified preprint rather than guessing metadata for the
  later journal publication.
- peng2025cweval: existing metadata rechecked against the
  [author preprint](https://arxiv.org/abs/2501.08200). Stage II uses the distinction
  between functionality and security, not a claim that our Oracle is qualified.
- spirtes1995fci and zheng2024causallearn: existing verified map below retained.

Academic-polishing's method-prose-rewrite pass follows the approved structural
plan; academic-paper-writer supplies the section contract and bounded read-only
code/preprocessing probes. The probes reconfirmed source-only grounding,
independent editability, task-unit weighting, four arms and the single primary
family. The bounded review led to four local clarifications: correction is
permitted rather than proven effective; bootstrap is with replacement at original
source-stratum size; practical margins precede discovery outcomes; appendix
symbols and the bootstrap order statistic are defined explicitly.
No scientific experiment was run.

The local prose is a reviewable specification, not a claim-bearing completed
study. Formal representation/Oracle qualification, effect results, exact adoption
criteria and expert-study evidence remain open. No performance claim was added.
The explanatory example is explicitly hypothetical and unconfirmed.

Local review verification: prose_debt, section_contract_debt, citation_debt,
and rationale_debt are closed for this Method revision; thin_draft = no.
Evidence/protocol/result debts remain open, so scientific completion is blocked
while local manuscript review is safe. The final bounded reviewer confirmed
the four corrections without repeating a full audit.

Current builds succeeded with the commands below: Method preview 7 pages,
full manuscript 16 pages, including references and the shared appendix.
The preview pages and the full manuscript's Method/appendix pages were rendered
and inspected; changed pages were rechecked after the final corrections.
There are no overfull boxes or unresolved references. The full manuscript
retains a minor underfull bibliography line; the preview retains expected
section-only ACM front-matter warnings. Bibliography warnings for incomplete
preprint volume/page fields are not filled with guessed metadata.
No template, font, margin, spacing, or float settings were changed.
The preview was queued in the local Codex file panel; its link above remains
the direct review entry point.

An overview figure remains a soft, manual publication debt, not part of this
prose revision. Its three panels should map task bindings → matched intervention
evidence → Explanation + Suggested Action, with semantic and causal graphs
visibly distinct. Evidence source: these three Method stages; intended placement:
the opening overview. Caption intent: how task-grounded requirements connect
the analyzed intervention to bounded guidance. No data plot or numerical result
figure is authorized or generated in this turn.

## Scope and authority

The canonical Method is `sections/03-method.tex`, imported by both `main.tex`
and `method-concise-preview.tex`. The preview is not another method path and
has no three-page constraint. The active authority is `docs/protocol.md`,
`phase-context-policy-v3`, Atomic-only revision 2026-09-16, status
**SPECIFIED_DRAFT**. No formal result is asserted.

The author authorized the preceding full-manuscript revision and Overleaf
submission; the current Method follow-up is local only.
Pair interactions remain on `codex/pair-interaction-research` at `e6833027`;
they are not an optional active main-paper track. No provider call, protected
task exposure, new experiment, implementation/schema change or frozen-result
reinterpretation is authorized by this prose work.

The revision integrates the RQ1/RQ4 annotation in Overleaf commit `2528cd2`.
Its PHASE display name becomes the approved CausalGuide name; mock-up counts
are not results. The annotation's historical RQ3 description does not change
the four current RQ sentences.

## Narrative and section contracts

Title: **CausalGuide: Causal Analysis for Explainable Security Guidance in LLM
Code Generation**. Story: task grounding → causal evidence → Explanation +
Suggested Action. The two contributions are task-grounded requirement-level
causal analysis and evidence-grounded explanations/security guidance. Selection
and randomized confirmation acquire the evidence needed by these outputs.
Concepts, causal analysis, secure prompting and actionable explanations alone
are not claimed as first contributions.

- Introduction: developer decision → task-local meaning → causal support →
  evidence-to-guidance → two contributions and complementary evaluation.
- Problem: SQL deletion illustrates a scoped requirement, matched comparison
  and two-part output; no numerical effect or original-code vulnerability is assumed.
- Method: three reader-facing stages cover seven scientific operations. Typed
  Symbolic Representation remains a subsection of Stage I. Stage II has
  task-grounded hypotheses/prioritization, matched interventions, and outcome
  measurement/effect estimation. Stage III specifies explanation content and
  evidence-conditioned actions, not another experiment or a qualified generator.
- Evaluation: same five-method roster in RQ1/RQ4; RQ2 isolates FCI admission;
  RQ3 uses the same held-out effects to evaluate modification evidence.
  Preserve the four RQ sentences verbatim.
- Related Work: acknowledge concept-level causal analysis, prompt adjustment,
  perturbation and security/functionality objectives; distinguish this study's
  task-bound requirement/edit/evidence/guidance correspondence.
- Conclusion: synthesize this correspondence and its limits without findings.

The abstract remains unfilled: [RESULT_NEEDED: frozen formal RQ outputs] and
[ABSTRACT_NEEDED: main empirical evidence]. Data Availability follows Conclusion.
No new figure or numerical table is in scope; no data figures require generation.
An overview, if later requested, should show the three stages and the separate
semantic, observational and randomized evidence sources, not causal TSG edges.

## Method blueprint and evidence hooks

| Reader stage | Scientific operations | Core content |
|---|---|---|
| Structured Graph Representation | Representation | Source records, bounded review/correction, deterministic graph compilation; exact scope; applicability distinct from expression |
| Requirement-Level Causal Analysis | Prioritization; hypothesis freeze; intervention/randomization; measurement; outcome assembly; inference | One editable requirement; FCI admission versus observational RD; fixed K and mapping; ADD/REMOVE; four arms; weighted task-unit ITT; one simultaneous primary family |
| Evidence-Grounded Explanations and Guidance | Reporting within inference/reporting | Explanation + Suggested Action; task/edit/evidence correspondence; coverage/functionality/uncertainty; withholding unsupported advice |

Three main Method equations define the graph, secure-yield endpoint and
target-minus-no-op effect; the weighted arm mean is in Appendix A.
Pair factorial and interaction equations
are removed. Individual-policy evidence does not establish additivity or joint
benefit. Generated code is measured independently, not a PAG variable/mediator.

All hooks below are preexisting artifact evidence of specification or inspectable
implementation, not proof that the formal study ran.

| Topic | Protocol section | Implementation hook |
|---|---|---|
| Source records and graph semantics | §5; tsg-workflow-stability.md | source_records.py; prompt_contract_extract.py; prompt_contract.py; prompt_tsg.py |
| Atomic obligations and exact scope | §§5–6; tsg-candidate-construction.md | candidate_construction.py; mechanisms.py |
| FCI admission, RD ranking and fixed slots | §§7–8 | prioritization.py; selector_analysis.py |
| Realizations and randomization | §§9–10 | randomization.py |
| Outcomes and task-unit estimator | §11 | measurement.py; outcomes.py; inference.py |
| Simultaneous intervals and existing meaningful Yield@K | §12 | inference.py; selector_analysis.py |
| Optional outcome-blind preparation | §4 | discovery_population.py |
| Formal evidence and freezes | §§15,18–19 | SharedEvidenceRecord; TargetEffectEstimate; unique_effect_rows; build_target_rq_tables |
| Explanation/action content and RQ4 | §§15.1–17 | Specified contract only; no qualified composition/adoption classifier verified |

Candidate construction cannot split a compound obligation, treat assumptions as
requirements or repair a graph. The later source-only scope assessment cannot
rebind source facts or choose scope by target state. Unresolved is not absent;
unexpressed in a prompt does not mean protection absent in generated code.

## Five-method reporting and human-study boundary

The roster is CausalGuide, Prompt Attribution (simple correlation), Causal Prompt
Concepts, Prompt Perturbation, and LLM-Judge Explanation (direct prompted LLM).
Causal Prompt Concepts and Prompt Perturbation are working comparator labels:
their exact publication, implementation/version and adaptations remain UNVERIFIED.
Ji et al. and NLPerturbator are relevant prior work, not automatically those
comparators' identities. No reference corpus was supplied; the existing map
below and bounded primary-source checks were reused.

RQ1 reports K, Mapped, Effect-confirmed (+/−), and Effect-confirmed Yield@K.
Mapped resolves a proposal to the frozen common scoped policy space; it is not
successful protocolization or an effect finding. Effect-confirmed means formally
authorized POSITIVE_MEANINGFUL or NEGATIVE_MEANINGFUL under existing simultaneous
intervals/margins. It is a reporting alias, not a new stored field/status.
Original K includes every empty/failed/non-evaluable slot. An opposite-direction
effect can be effect-bearing while contradicting advice. External shared
confirmation is not a baseline's native capability; same K does not mean same
compute. RD-only is an RQ2 ablation. Expert/Random are not extra main methods.

RQ4 compares anonymized English complete Explanation + Suggested Action products
using five 1–5 Likert items: clarity, evidence sufficiency/justification,
credibility, actionability and overall usefulness. Overall usefulness is the
planned primary rating, not a registered or observed endpoint yet. Exact
evidence access, explanation procedures, item anchors, ethics, participants,
cases, assignment, empty/unavailable-product handling, repeated expert/case
analysis and secondary multiplicity remain to be frozen. Common presentation
cannot invent evidence or rewrite every product through CausalGuide. The study
does not isolate wording/TSG effects, causal correctness, comprehension, actual
adoption or repair success.

Adoption needs prospectively frozen security/task-preservation criteria,
secondary margins, coverage and joint decision rules. These remain open.
Missing support withholds advice, not an otherwise reportable effect. Harmful
REMOVE does not validate ADD; no detected functionality loss is not preservation.
Independent original-task assessment supplies functional pass/fail/unknown.

## Verified citation-to-claim map

The preview reuses the manuscript's shared bibliography. The two existing
Method references below were checked against primary publication sources;
the current additions are mapped in the local-review section above.

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


## Build and preceding Overleaf synchronization

Build commands from `paper/fse2027`:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out/main-integration main.tex
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out/method-concise method-concise-preview.tex
```

The existing acmsmall,screen,review,anonymous profile, bibliography style,
fonts, margins and spacing are preserved. No active figures or tables need float
placement. This is a bounded layout audit, not a submission-compliance claim.
The preceding submitted builds on 2026-09-16 succeeded with TeX Live 2026: main 15 pages,
Method preview 7 pages, both including references. All 15 main pages and 7
preview pages were rendered and visually reviewed. Equations and section
transitions are legible; no clipping, overfull boxes or unresolved references
remain. One long FCI sentence was reflowed without changing its meaning.
No fonts, margins, spacing, template options or float settings changed.
The main retains a minor underfull bibliography line and the existing ACM
reference-block warning; the section-only preview has expected front-matter
warnings. This is not a submission-ready build because scientific evidence is
still missing. Four RQ sentences and four retained Atomic equations pass exact
source comparisons. The separate Overleaf checkout also compiled successfully
from source inputs matching this reviewed manuscript (including the unchanged
bibliography). Nine manuscript source files were committed and pushed to
Overleaf as `56f0a549afff886d448a5aca80f0390c9e85b132`, on top of `2528cd2`.
Remote `refs/heads/main` was read back and matches that commit. Generated
PDF/build files, local notes, protocol, code and data were not uploaded.
The research repository's local documentation changes were not committed or
pushed to GitHub as part of this manuscript-only remote submission.

Writing-ai-paper guided contribution framing/readability; academic-paper-writer,
academic-polishing and academic-reviser supplied evidence-first section checks.
Read-only probes verified the current Atomic path and source-record extraction.
Bounded reviews checked Method and Evaluation; incorporated feedback distinguishes
mapping/protocolization/confirmation, reports missing RQ4 products and avoids
presenting suggested actions as an implemented classifier.

## Bounded verification and remaining evidence

Whole-paper verdict: blocked; safe_to_continue: yes for prose revision and the
authorized Overleaf synchronization, not formal execution or submission readiness.

- prose/rationale debt: closed for the revised narrative after bounded review.
- section/result debt: open; abstract and formal RQ1–RQ4 results are unavailable.
- citation debt: open for exact research-baseline identity and a final full
  bibliography audit; closest-work capability claims are checked above.
- evidence debt: independent representation/Oracle qualification, natural support,
  formal effects and human-study results; development success is not confirmation.
- protocol debt: exact comparator bridge/procedures, source/model scope,
  power/margins/budget, secondary adoption rules, and RQ4 preregistration.
- figure debt: none introduced by this prose-only task; no data plots to generate.

No claims of superior selection, beneficial hardening, qualified extraction,
or favorable expert ratings are made. Such findings require frozen, traceable
formal evidence. Research implementation and frozen artifacts remain unchanged.
