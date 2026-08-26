# Prompt Mechanism Study research artifact

Prompt Mechanism Study is a compact academic artifact for testing whether a
frozen prompt intervention changes Oracle-evaluable secure-code yield while
preserving functionality. It is a research prototype, not a deployment or
campaign-management platform.

## Method at a glance

```text
source benchmark records
        -> deduplicated task units
        -> one representative prompt per unit
        -> Prompt TSG and mechanism binding
        -> four assigned prompt arms
        -> code generation
        -> independent security and functionality measurement
        -> assigned-arm task-unit ITT
```

### Terminology

- A **source record** is one prompt and its metadata from a benchmark.
- A **task unit** is one independent, cross-source-deduplicated experimental
  unit. It may represent one source record or several equivalent records.
- A **task** is the representative prompt executed for a task unit. The active
  four-arm studies use exactly one task per unit, so `task_id` is the analysis
  key.
- A **Prompt TSG** is the typed semantic representation of that representative
  prompt. It is not a causal graph and is not the resampling unit.

Older frozen artifacts use `semantic_cluster_id`, `cluster_id`, and
`semantic_task_cluster_id` for the task-unit coordinate. Those physical field
names remain immutable for reproduction. New method prose and prospective
protocols use **task unit**; "cluster" is otherwise reserved for the internal
deduplication step that groups source records.

## Single active method

The method is organized as seven visible stages.

1. **Representation.** Normalize source records, form conservative task units,
   choose one representative prompt, and extract bounded Prompt TSG facts.
2. **Prioritization.** Apply outcome-blind eligibility and sampling rules to
   the complete candidate inventory.
3. **Hypothesis freeze.** Freeze task units, Prompt TSG bindings, mechanism
   registry, model, Oracles, arm texts, seeds, estimands, and multiplicity.
4. **Intervention and randomization.** Materialize all four prompt variants and
   randomize their execution order without consulting generated outcomes.
5. **Measurement.** Generate code, check Python syntax/compilation, run the
   static Security Oracle, and run the blinded Functional Judge independently.
6. **Outcome assembly.** Account for every assignment and preserve invalid,
   insecure, unknown, failed, and functional outcomes without filtering.
7. **Inference and reporting.** Estimate paired assigned-arm ITT over equally
   weighted task units, report unknown bounds, and build the frozen result
   report.

Prompt TSG selects an applicable mechanism from prompt evidence. It does not
guarantee that generated code realizes that mechanism, and generated code is
not treated as a causal mediator. Realization and non-target drift are
diagnostics only.

## Four prompt arms

Every task unit receives all four assigned variants:

| Arm ID | Prompt operation | Scientific role |
| --- | --- | --- |
| `absent` | Keep the source prompt unchanged | Requirement-absent baseline |
| `specific` | Append the Prompt-TSG-selected concrete mechanism requirement | Target intervention |
| `generic` | Append a general security-safeguards reminder | Tests whether specificity matters |
| `placebo` | Append a style-only instruction about descriptive names, formatting, and straightforward organization | Controls for adding another instruction and changing prompt attention |

`placebo` is the language/code-style arm. It changes the requested presentation
of generated code, not the security mechanism or the natural-language content
of the source task. The primary contrast is `specific - placebo`; `specific -
absent` and `specific - generic` are secondary contrasts. No arm is removed
from the ITT denominator because its generated code ignored the instruction.

## Outcomes and evidence boundary

The primary safety outcome is observed Oracle-evaluable secure-code yield.
Code validity, Oracle evaluability, unknown coverage, functionality, and
secure-and-functional joint success remain separate fields.

The Functional Judge is AST/compilation plus blinded LLM review against the
frozen functional contract. It is not a substitute for executable tests. The
Security Oracle is independent and preserves `unknown`; unknown is never
promoted to secure.

The completed Qwen3.5 and Qwen3.7 strict-TSG studies are frozen null results on
the same 19-task-unit census. Their reports remain evidence of that bounded
population, not a universal no-effect claim:

- `docs/experiments/2026-08-26-prompt-tsg-strict-v2-results.md`;
- `docs/experiments/2026-08-26-prompt-tsg-qwen37-oracle-v3-results.md`.

## Reviewer commands

Run the focused scientific-invariant suite:

```text
python -m pytest -q
```

Verify the tracked Qwen3.7 analysis independently:

```text
prompt-mechanism-four-arm verify-analysis \
  data/formal/results/prompt-tsg-strict-19-qwen37-oracle-v3-analysis \
  --config configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json \
  --tasks data/formal/prompt-tsg-strict-v3-replication-tasks.jsonl
```

The four-arm entry point also exposes `preflight`, intervention, measurement,
and analysis actions. Run `prompt-mechanism-four-arm --help` for their bounded
arguments. Provider credentials and model deployment remain external adapters;
they are not stored in the artifact.

## Review reading order

The active path can be reviewed in at most ten files:

1. `AGENTS.md` -- scientific and reviewability constraints;
2. `README.md` -- terminology, stages, arms, and evidence boundary;
3. `configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json` -- one complete
   frozen study identity;
4. `src/prompt_mechanism_study/four_arm_cli.py` -- single four-arm entry point;
5. `src/prompt_mechanism_study/four_arm.py` -- linear intervention,
   measurement, outcome, and analysis path;
6. `src/prompt_mechanism_study/prompt_tsg.py` -- bounded graph schema and typed
   arm patches;
7. `src/prompt_mechanism_study/prompt_tsg_extract.py` -- LLM-fact proposal and
   deterministic evidence validation;
8. `src/prompt_mechanism_study/security_profiles.py` -- local Security Oracle
   profiles;
9. `src/prompt_mechanism_study/four_arm_verify.py` -- independent result
   verifier;
10. `docs/experiments/2026-08-26-prompt-tsg-qwen37-oracle-v3-results.md` --
    frozen result interpretation and reproduction coordinates.

Historical ADD/REMOVE studies, deployment incidents, provider tuning,
calibration exploration, and server administration remain archival evidence.
They are not alternative active execution paths.
