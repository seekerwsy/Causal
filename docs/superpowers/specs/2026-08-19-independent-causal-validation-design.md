# Independent causal-validation design

## Status

The discovery method is frozen at hypothesis
`hypothesis_3f254cbd3f30ca51351924c43e3b6b44063010ccbc547565064530589bc870c0`.
The hypothesis is specific to Phi-4-14B and the directed relation
`z.target_mechanism_realized -> y.discovery_functional`. It does not assert a complete Prompt
intervention mediation path. The discovery support was 167/200 task-cluster bootstrap replicates
(0.835) under the causal-learn FCI/G-square backend.

No new outcome may be generated until the task pool, mechanism measurement, functional Judge,
four-arm intervention protocol, and analysis manifest are frozen. Data already used in either the
51-task discovery split or the 42-task historical held-out split are method-development data and
cannot be relabelled as independent validation.

## Frozen validation contract

- Primary model: `phi-4-14b`.
- Primary task scope: CWE-78, CWE-89, CWE-502, CWE-328, and CWE-338.
- Context variable: the existing four-arm randomized Prompt assignment.
- Mechanism variable: the existing semantic construct, target-CWE mechanism realized in generated
  code. The measurement implementation may become profile-independent only after outcome-blind
  equivalence calibration; its meaning and binary projection may not change.
- Outcome: the existing single-pass functional Judge decision, produced without arm, security
  label, or mechanism state.
- Primary backend: causal-learn FCI with the frozen G-square configuration and JCI background
  knowledge.
- Stability: 200 complete task-block bootstrap replicates, at least 0.8 compatible directed-edge
  support, and no more than 0.1 failed replicates.
- Minimum pool: 50 independent tasks with all five target CWEs represented. The primary result is
  pooled; per-CWE results are heterogeneity diagnostics and do not require equal task counts.
- A replication succeeds only if the frozen directed edge is present and meets the stability
  threshold. A missing or unstable edge is a non-replication; no threshold or endpoint rule is
  changed afterward.

## Existing-pool preflight

The outcome-blind preflight authenticates four immutable inputs: the 93-task method-development
selection, the 59 strict cross-source candidate clusters, their 59 reconciled audit decisions, and
the frozen hypothesis. It consumes no generated code, functional result, Oracle label, or provider
call.

The result is blocked by construction:

- 12/59 cross-source candidates passed the old task/profile audit, but all 12 task clusters are
  already in the 93-task method-development population;
- the remaining 47 are disjoint but ineligible: 18 lack the target operation, 18 require behavior
  outside the safe substitution scope, and 11 explicitly require a weak mechanism;
- examples of the latter include mandatory MD5/SHA-1, pickle reconstruction, and shell-string
  execution. Including them would violate safety neutrality or task invariance rather than merely
  broaden measurement coverage.

The repository therefore has zero tasks that are simultaneously independent and eligible. The
blocked result is an input-availability finding, not a backend or extractor failure.

## External acquisition order

New sources are acquired and audited before mechanism-extractor development so that the extractor
schema is driven by the languages and CWE operations actually present in the validation pool.

1. CodeGuard+ (`https://github.com/CodeGuardPlus/CodeGuardPlus`) is the first candidate because it
   exposes 91 Python/C/C++ prompts, 34 CWEs, per-prompt functional tests, and CodeQL queries. Its
   SecurityEval/CodeQL ancestry requires exact and semantic de-duplication against all current
   assets.
2. SecCodeBench v2.2.0 (`https://github.com/alibaba/sec-code-bench`) is the preferred independent
   industrial source. It contains 98 runnable project tasks across five languages and 22 CWEs, but
   only 13 tasks are Python; multi-language inclusion is a separately reported transportability
   stratum rather than silent pooling with the Python discovery population.
3. LLMSecEval (`https://github.com/tuhh-softsec/LLMSecEval`) is a supplementary prompt source. Its
   prompts remove direct vulnerability mentions, but it lacks the same per-task executable
   functional contracts and also derives from earlier Copilot scenarios, so it is used only after
   de-duplication and contract construction.

For every source, the repository records the canonical URL, immutable commit or release tag,
license, downloaded file digests, raw task count, five-CWE count, language count, exact overlap,
semantic-cluster overlap, security-neutrality decision, target-operation decision, and executable
functional-contract availability. No code-generation or Judge outcome is observed during this
audit.

## Profile-independent mechanism measurement

If the independent pool contains task shapes outside the existing static profiles, a blinded LLM
facts extractor may replace only the measurement implementation:

1. Input contains target CWE, generated code, and language; it excludes Prompt arm, task outcome,
   Oracle decision, and model identity.
2. Output is a finite structured facts schema for relevant source, sink, guard, sanitizer, and
   source-to-sink path evidence. It never emits secure/insecure or functional labels.
3. A deterministic validator checks schema closure, cited code spans, target-CWE scope, and allowed
   fact relations. Invalid output is an explicit measurement failure, not an inferred negative.
4. The existing deterministic projection maps valid facts to the same five mechanism states and
   the same binary Z definition.
5. A 20-code, five-CWE calibration canary runs first on archived Phi outputs selected without
   functional outcomes. Only after schema validity and disagreement review pass may the identical
   extractor be replayed over the full archived calibration population.
6. Model identifier, provider, system prompt, schema, sampling parameters, retry policy, request,
   response, and digests are frozen before any independent validation output is generated.

## Stop conditions

The validation run starts only after at least 50 eligible, disjoint tasks and the measurement
calibration gates pass. If public sources cannot supply that pool, the experiment reports the
availability boundary and either narrows the preregistered validation scope transparently or
constructs a separately labelled task-generation study. It does not reuse the 93 development
tasks, admit prompts that mandate unsafe behavior, or search analysis variants for a positive
result.
