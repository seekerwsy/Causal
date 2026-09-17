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
its condition or target. The current path preserves complete policy bindings and
reviews a separate applicability background. Candidate proposals account for the
operation, every input and every execution guard with cited retain/omit decisions;
the existing reviewer judges the independence and sufficiency of the whole tuple.
Construction still uses one ordinary source review and at most one local semantic
patch. Component accounting adds no reviewer or scientific stage.

The [fresh two-task check](docs/experiments/2026-09-17-tsg-reliable-construction.md#fresh-complete-background-check)
accepted both target candidates and compiled four initial graphs without mechanical
repair. Privilege lowering passed fresh REMOVE, inverse ADD and independent
verification while preserving elevation. Registration stopped after its present-arm
review disputed username insertion and the local patch repeated the rejected claim;
its removed-arm scope was absent, but no paired support or edit ran. The frozen
both-task gate therefore blocked the conditional follow-up. These 17 fresh Codex
steps used zero external API calls. The successful directions remain one exposed
task's edit pair, not general construction stability or a causal/security result.

The subsequent [representation/repair revision](data/method/tsg-reliable-construction-v1/structural-repair-boundary/README.md)
separates operation predicates from concrete bindings and makes explicit withdrawal
preserve uncertainty while closing dangling dependencies. Authored controls on the
saved registration records now produce a compilable unknown graph, or preserve the
hashing order while retracting the uncertain username binding under a newly frozen
normalized predicate. Both saved privilege graphs retain their structure. No fresh
model improvement was established by those authored controls.

The [non-thinking DeepSeek Flash check](data/method/tsg-reliable-construction-v1/predicate-binding-api/README.md)
compiled both final graphs but missed predicate/binding defects in both source reviews.
A [thinking-mode comparison](data/method/tsg-reliable-construction-v1/predicate-binding-thinking-api/README.md)
used identical tasks, instructions and source code with larger delivery limits.
Both initial graphs compiled; the existing review and local patch corrected four
operation facts while preserving requirements, order and conditions. Registration's
explicit web/account task requirement was restored. Username insertion and the
meaning of supplied `pass` bodies remain disputed, so the 2/2 narrow separation
check is not whole-graph correctness or repeated stability. Each batch made six
API calls; conservative costs were CNY0.178368 and CNY0.964020 respectively. Thinking
and resource limits changed together; no isolated thinking effect is established.

The [TSG workflow](docs/tsg-workflow-stability.md) describes the active procedure;
the [experiment report](docs/experiments/2026-09-17-tsg-reliable-construction.md)
retains earlier failures and the [candidate guide](docs/tsg-candidate-construction.md)
explains downstream use. Independent representation and measurement qualification,
natural candidate support and a prospectively frozen formal study remain unfinished.

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
