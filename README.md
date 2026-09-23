# CausalGuide

Research prototype for finding and testing prompt-side security requirements in
LLM code generation. Each Atomic policy changes one complete requirement while
preserving the task's non-target behavior.

The normative [protocol](docs/protocol.md) is `phase-context-policy-v3`,
**SPECIFIED_DRAFT**. Formal execution is inactive. Implemented components, offline
smoke checks and bounded development results do not establish whole-method efficacy.

## Method

```text
representation → prioritization → hypothesis freeze
→ intervention/randomization → measurement → outcome assembly → inference/reporting
```

| Stage | Responsibility |
| --- | --- |
| Representation | Preserve requirements, objects, conditions and scope in Prompt TSG; construct Atomic candidates. |
| Prioritization | Check support and compare Full (FCI admission plus RD ranking) with RD-only on the same candidates and folds. |
| Hypothesis freeze | Fix policies, slots, task populations, models, budgets and analysis before evaluation. |
| Intervention/randomization | Assign Target, No-op, Style and Generic-security prompts for one requirement. |
| Measurement | Measure security, code validity and functionality independently of assigned-arm labels. |
| Outcome assembly | Account for every assigned task/arm/seed, including failure and unknown. |
| Inference/reporting | Estimate task-unit ITT effects, retain the frozen comparison family and independently verify saved results. |

TSG edges express source semantics, not causal relationships. An unexpressed
requirement does not imply insecure generated code; unknown does not mean absent.
Post-assignment compliance, generation success and drift never filter the ITT
denominator. Secure-code yield, Oracle coverage, functionality and joint success
remain separate. `main` is Atomic-only; [Pair research is deferred](https://github.com/seekerwsy/Causal/tree/codex/pair-interaction-research).

## Reproduce the reviewer smoke

Use Python 3.12:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
```

The default suite includes the complete seven-stage smoke and independent result
verification. To inspect a standalone saved package:

```text
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

The smoke uses synthetic tasks and offline model responses, makes no provider
calls, and runs real FCI on fixture observations. Its output is
`NON_CLAIM_TEST_ARTIFACT`. Reviewers do not need to rebuild the source dataset or
repeat historical curation to run it. See the [reviewer guide](docs/reviewer-guide.md)
for stage inputs/outputs and a reading order of at most ten core files.

## Artifact scope and evidence

The reviewer command above reproduces a **non-claim** seven-stage result from
bundled synthetic tasks and offline code responses. The fixture retains the raw
code; the result package saves assignments, measured labels, unknowns and the
independently checked result.
There is not yet a claim-bearing natural-task result table in `main`.

The [outcome-blind scope preflight](docs/artifact-scope-preflight.md) recounts the
released v4 task inventory and earlier candidate-screen coverage for four Python
CWE labels. It also records why existing AST examples alone do not qualify an
endpoint on generated code. This preflight does not admit any task or policy to a
formal experiment. Natural-task transfer, automatic TSG's incremental value and
FCI's selection benefit remain unproved.

The complete pre-scope development workspace is retained on local branch
`codex/pre-artifact-scope-20260923` at `f1cd0011`. Historical results keep their
original measurement rules and are outside the default reviewer artifact.

## Work on the prototype

Source is grouped directly under `src/`: `data`, `tsg`, `discovery`, `experiment`,
`measurement` and `verification`. `src/cli.py` is the command entry and
`src/target_workflow.py` the linear workflow. `development` only supplies the
reviewer smoke fixture. The import package remains `prompt_mechanism_study`.

| Author operation | Entry or guide |
| --- | --- |
| Prepare new source data | `data` / `curate`; [dataset boundaries](docs/research-dataset-spec.md) and [source preparation](docs/contract-content-cleaning.md) |
| Extract and assess TSG | `representation` / `qualification`; [TSG workflow](docs/tsg-workflow-stability.md) and [candidate semantics](docs/tsg-candidate-construction.md) |
| Run authorized bounded development | `study development OUTPUT --development-plan FROZEN_PLAN` |
| Verify its saved results | `study verify-development SAVED_RUN` |

Use `GROUP --help` for available commands. Source preparation is an author task,
not an extra scientific stage. Frozen historical inputs use their corresponding
implementations on the preserved branch. Current tests are described in the
[test guide](tests/README.md). The [paper draft](paper/fse2027/main.tex) is separate
from the development archive.
