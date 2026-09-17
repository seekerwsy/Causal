# Prompt Mechanism Study

Research prototype for **CausalGuide: Causal Analysis for Explainable Security
Guidance in LLM Code Generation**. The current main line studies one prompt
requirement at a time: where it applies, how to add or remove it, and whether
that assigned edit changes independently measured code outcomes.

The normative [protocol](docs/protocol.md) remains `phase-context-policy-v3`,
`SPECIFIED_DRAFT`. No formal Discovery, provider Confirmation, or claim-bearing
schema-3 result exists. Implementation checks and development observations do
not establish research effectiveness.

## Current scope

`main` contains **Atomic single-requirement policies only**. It keeps ADD and
REMOVE as separate policies, Full versus RD-only selection, matched controls,
assigned-arm task-unit ITT, and independent saved-result verification.

Pair interaction research is deferred to
[`codex/pair-interaction-research`](https://github.com/seekerwsy/Causal/tree/codex/pair-interaction-research),
starting at `e6833027`. That branch preserves the complete pre-reduction source,
documentation and manuscript. Main has no Pair candidate generator, relation
selector, factorial arms, interaction estimator, Pair budget or default tests.
Historical artifacts retain their original rules; replay Pair packages with the
preserved branch. Local experiment archives and credentials are not part of the
GitHub source snapshot.

## One active path

```text
representation → prioritization → hypothesis freeze
→ intervention/randomization → measurement → outcome assembly → inference/reporting
```

| Stage | Current responsibility |
| --- | --- |
| Representation | Preserve source requirements, objects, conditions and scope in Prompt TSG; build reviewed Atomic candidates. |
| Prioritization | Check outcome-blind support, then compare Full and RD-only over the same candidates, folds and RD scores. |
| Hypothesis freeze | Freeze fixed-K slots, exact policies, realizations, models, populations, budgets and inference rules. |
| Intervention/randomization | Assign matched target, no-op, placebo and generic-security arms for one requirement. |
| Measurement | Measure code validity, security and functionality independently of assigned-arm labels. |
| Outcome assembly | Account for every assigned task/arm/seed, including failures and unknowns. |
| Inference/reporting | Estimate target-minus-no-op task-unit ITT, apply the Atomic simultaneous family, and independently verify results. |

Prompt TSG edges are semantic, not causal. Unexpressed requirements do not imply
insecure software; unresolved facts do not imply absence. Post-assignment
fidelity, compliance, generation success and drift never filter the ITT denominator.
Secure-code yield, Oracle coverage, functionality and joint success remain separate.

## Current research bottleneck

Automatic TSG extraction can preserve a plausible description while misbinding
its condition or target. The current bounded workflow uses one ordinary source
review and at most one local semantic patch; detailed binding review was not
promoted after its cross-task diagnostic. Candidate-local unknown handling helps
limit unusable comparisons but does not prove semantic accuracy.

The current binding repair separates direct targets from requirement-owned order.
Owned relations retain their requirement, guards and operands through compilation,
candidate matching and edit checks. A [two-task development check](docs/experiments/2026-09-17-tsg-reliable-construction.md#repairing-ownership-of-temporal-requirements)
retained all nine fixed source meanings and three order bindings; one sample per
task does not establish stability. The subsequent complete repair round corrected
two planted target errors, but both natural policy deletions were blocked by
policy-dependent anchors. The current candidate-local revision separates an explicitly
reviewed applicability background from the complete policy signature and permits
reviewed policy-only facts to change during an edit. Authored ADD/REMOVE controls
pass; automatic support judgments and natural edit qualification remain unproved.
TSG construction itself gains no global ownership gate or extra reviewer.
The first natural check of the new background interface stopped at candidate
selection: one proposed background still named the policy action and was rejected;
the other proposal remained unresolved. Three model steps ran, with no fresh
construction or actual edit. Automatic delivery of the separate background remains
unproved; the request's scope-preservation wording also needs clarification.

Complete conditional, whole-task and universal requirements can now enter Atomic
candidate construction at their original boundary. Policy-internal conditions
are separate from task-selection context. The [bounded projection check](docs/experiments/2026-09-17-complete-policy-projection.md)
tests this path through actual prompt edits on authored structures; it does not
establish better automatic extraction or qualify a formal study.
The subsequent [two-task natural check](docs/experiments/2026-09-17-complete-policy-natural.md)
completed both graphs, but its one automatic candidate response truncated. Source
guard/target defects and inappropriate functional candidates remained; no candidate
gain or actual edit was established. Six calls and their failures replay offline.
The [next bounded check](docs/experiments/2026-09-17-tsg-reliable-construction.md)
removed candidate truncation and reference re-entry: one decision now names each
original requirement and the program preserves its bindings. Two factors survived
author review, but inappropriate selections and source-construction errors remain.
Independent inventories were not adopted as a default stage or a reliable reference.
The subsequent source-only agent check compiled all 16 drafts from eight tasks
run twice. Author audit matched 88/96 fixed meanings; 12/16 graphs passed, below
the frozen gate. Repeated source-interpretation and target-binding ambiguities
remain. Direct object requirements now project without invented operation edges,
but candidate editability and a stable automatic construction path are unproved.

The [TSG workflow](docs/tsg-workflow-stability.md) records the exact active procedure,
negative results and next research decision. The
[candidate guide](docs/tsg-candidate-construction.md) explains its downstream use.
Independent representation and measurement qualification, natural candidate
support and a prospectively frozen formal study remain unfinished. This scope
reduction does not claim to solve those empirical gaps.

## Reproduction

Use Python 3.12 and install the declared extras:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

The complete suite already includes the seven-stage offline smoke and independent
verification; the last two commands are for inspecting a standalone package.
The smoke makes zero provider calls and reports `NON_CLAIM_TEST_ARTIFACT`.
Use focused checks for local changes; see the [test guide](tests/README.md).

Explicitly authorized development uses `study development OUTPUT
--development-plan FROZEN_PLAN`; `study verify-development SAVED_RUN` independently
replays it. These commands cannot assign formal roles or authorize scientific claims.

Start with the [reviewer guide](docs/reviewer-guide.md) for stage inputs/outputs
and a reading order of no more than ten files. Other CLI groups are `data`,
`curate`, `representation`, `qualification` and `artifact`; their help lists
stage-specific operations.

The [dataset contract](docs/research-dataset-spec.md) identifies immutable source
reviews, exposed development tasks and protected inputs. The
[manuscript](paper/fse2027/main.tex) describes the Atomic method and planned RQs,
without formal result claims. Historical development records remain under
`docs/experiments`; older execution paths are recoverable through
[Git history](docs/archive/legacy-artifacts.md), not parallel live frameworks.
