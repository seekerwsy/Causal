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

The priority is now a complete development run through causal discovery and the
subsequent experiment, rather than another standalone TSG repetition gate. TSG
still needs correct requirement/target/condition bindings for each admitted
comparison; unrelated local uncertainty does not reject an entire task. The
[TSG workflow](docs/tsg-workflow-stability.md) and
[candidate guide](docs/tsg-candidate-construction.md) define that boundary.

The [downstream check](docs/experiments/2026-09-18-discovery-path-check.md) found
that the seven-stage smoke previously consumed preset FCI adjacency flags. It now
runs causal-learn on its synthetic observations and retains bootstrap matrices,
PAGs and failures before Full/RD-only selection, assignment, measurement and ITT.
This is actual algorithm execution with fixture data, not natural-data Discovery
or evidence that FCI improves discovery. The paid development entry still starts
from supplied policies and does not perform Discovery.

A source-only audit of one existing 12-task exposed development plan found only
unexpressed focal requirements (SQL: 3, command: 8, path: 1). Those historical
annotations are not requalified by this audit. This pool cannot supply natural
0/1 support for the three factors; intervention arms and repeated extraction
cannot repair that population gap. The next scientific step is a fixed,
outcome-blind natural development population and its candidate support, followed
by baseline measurement, actual Discovery and independent held-out development
edits where support permits. Any D0 preparation retains the protocol's independent
natural-source and outcome/selector-blind boundaries.

An [author-constructed reference diagnostic](data/method/manual-graph-downstream-v1/README.md)
now compiles all twelve source graphs and exercises scoped editing on ten. Two
historical command-argument bindings are unsupported and remain unresolved.
The actual fold constructor still blocks all three factors for missing natural
positive states. These reference graphs can now be reused for downstream checks;
they are not independent gold or automatic extraction results.

A [42-task local-model development run](data/method/local-baseline-screen-v1/README.md)
now retains 84 baseline generations from seven natural sources, with unsafe-code
diagnostics kept separate from the complete sample. Source-only support still
blocks the four fixed factors before natural-data FCI. Three preselected author
graphs additionally drove 24 four-arm generations and saved-result verification;
this component check exposed security-profile false alerts and a functional-judge
false pass, not a validated Discovery or confirmatory effect.

Automatic TSG quality remains incomplete. The latest two-task
[DeepSeek thinking check](data/method/tsg-reliable-construction-v1/predicate-binding-thinking-api/README.md)
met a narrow predicate/binding check after repair; the same
[Qwen3.7-Max check](data/method/tsg-reliable-construction-v1/predicate-binding-qwen-max-api/README.md)
did not. Neither establishes whole-graph correctness or repeated stability.
[Earlier checks](docs/experiments/2026-09-17-tsg-reliable-construction.md) retain
the original failures. Independent representation and measurement qualification
and a prospectively frozen formal study remain unfinished.

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
