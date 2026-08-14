# Randomized Exploratory Discovery Canary Design

**Date:** 2026-08-15
**Status:** Approved for a bounded engineering canary; adoption as the primary discovery design is
pending canary evidence and a separate approval
**Scope:** Prompt-only randomized exploratory variation before held-out confirmation

## 1. Decision and objective

The existing natural Prompt distribution does not provide within-CWE variation in the cataloged
safety-control variables. Across 146 deduplicated, independent, candidate-neutral Python tasks, the
audited scoped safety features were all `ABSENT`. This is an identifiability limitation, not a
reason to smooth a constant column, pool incompatible CWE scopes, or manufacture an observational
edge.

This canary tests whether SecAware can create valid, task-preserving Prompt-feature variation on a
dedicated discovery pool and carry that variation into a separately labeled structural analysis.
It does not approve a new general-purpose causal-discovery algorithm and does not change the
held-out four-arm confirmation or task-clustered ITT estimand.

The canary may establish engineering feasibility. It may not publish, confirm, or freeze a paper
hypothesis.

## 2. Evidence sequence

```text
natural observational FCI
  -> natural identifiability report

dedicated exploratory-discovery tasks
  -> outcome-blind finite FeatureSpec targets
  -> randomized Prompt variants
  -> blind Prompt-TSG re-extraction and pre-generation validation
  -> code generation, functional evaluation, and independent Oracle
  -> raw augmented FCI and JCI-constrained FCI
  -> exploratory candidate records only

held-out confirmation tasks
  -> frozen hypotheses after a separately approved selection rule
  -> four-arm randomized confirmation
  -> task-clustered ITT
```

The natural diagnostic, exploratory analysis, and confirmation analysis must remain separately
labeled in configuration, artifacts, reports, and paper prose.

## 3. Non-negotiable boundaries

1. Prompt TSG remains the only task-security graph. Generated-code structure does not become a
   causal variable.
2. The exploratory task IDs must be disjoint from every confirmation task ID.
3. Candidate FeatureSpecs, operations, CWE scopes, arm roles, model, seeds, and budgets are frozen
   before any exploratory outcome is generated.
4. Only finite catalog features may be targeted. The LLM may render text but may not create a new
   feature identity, arm, outcome, or selection rule.
5. The Prompt extractor is blind to arm role, target identity, intended delta, code, and outcome.
6. All variants pass schema, catalog, prompt-role, security-neutrality, task-projection, and
   `AllowedDelta` gates before generation.
7. `target_changed` remains a diagnostic. A structurally valid assigned unit is never removed from
   an exploratory or confirm analysis because the intended feature failed to change.
8. Exploratory task variants and seeds are clustered by `task_id`. They are never treated as
   independent natural tasks.
9. Confirmation outcomes cannot select, rank, edit, or rescue an exploratory candidate.
10. The existing confirm-only JCI stage remains secondary and cannot be reused to select a
    hypothesis. Exploratory JCI requires its own context IDs, tables, PAGs, and provenance.
11. Failed and superseded canary runs use new output directories. No prior artifact is overwritten.
12. Secrets remain environment-only and are excluded from configs, logs, manifests, and errors.

## 4. Canary population and target universe

The first canary uses only the four previously frozen `discover` tasks in
`cyberseceval-v2-cwe78-cwe89-engineering-pilot-v1`:

| CWE | Independent tasks | Pre-registered target | Operation |
|---|---:|---|---|
| CWE-78 | 2 | `safety.safe_subprocess` | `ADD` |
| CWE-89 | 2 | `safety.sql_parameterization` | `ADD` |

The four previously frozen `confirm` tasks are forbidden inputs. This sample is deliberately too
small for a scientific effect or stable-path claim; it is sufficient only to test artifact closure,
feature variation, blind extraction, randomization, generation, evaluation, and failure semantics.

## 5. Exploratory arm protocol

The canary reuses the existing Safety ADD arm roles and `AllowedDelta` definitions:

```text
TARGET_PATCH
NOOP_REWRITE
LENGTH_MATCHED_PLACEBO
GENERIC_SECURITY_REMINDER
```

This reuse is deliberate: the target arm isolates the scoped mechanism, the no-op arm controls for
surface rewriting, the length-matched placebo controls for added text, and the generic reminder
separates a target-specific requirement from general security salience.

The first prompt-only gate uses the versioned deterministic catalog renderer to prove catalog text
ownership, intended deltas, assignment closure, and deterministic replay. The deterministic
extractor is retained as a diagnostic in this gate because its task-prerequisite term matcher is
known to have insufficient recall on these tasks; no new matcher rules are added to make the gate
pass. Its mechanical wording is not approved for outcome generation. Real code generation requires
the locked LLM intervention renderer and LLM-facts blind re-extraction to prove the realized TSG
deltas on the exact frozen texts.

Safety neutrality means that no arm states that the original implementation or task is vulnerable,
requests unsafe behavior, or exposes an expected Oracle result. Safety `REMOVE` is outside this
first canary.

## 6. Assignment and clustering

For each `(task_id, target_feature_id, model_id)` block, four configured seed slots are mapped to a
balanced permutation of the four arm roles using the existing
`sha256-rejection-fisher-yates-v1` deterministic RNG. The permutation and its seed material digest
are committed before generation.

The exploratory structural table may contain all assigned rows, but bootstrap resampling occurs by
task cluster and includes every row belonging to the sampled task occurrence. The observational
rule that selects one seed per natural task remains unchanged and applies only to the natural
observational reference run.

## 7. Exploratory variables and structural analysis

The exploratory table is local to one CWE and model and may contain only:

```text
W: pre-treatment task metadata
C_D: randomized exploratory arm context
X: blindly re-extracted Prompt-TSG feature queries
Y: committed Oracle and functional outcomes
```

The stage persists both:

1. a raw augmented FCI PAG with base `W/X/Y` background knowledge and no `C_D`-incident
   restrictions; and
2. a JCI-constrained FCI PAG that forbids system variables from causing randomized context.

Both use causal-learn FCI with the locked G-square CI configuration. JCI assumptions may orient
endpoints but may not require a context-system adjacency or a target-outcome path.

This canary does not freeze hypotheses. A later adoption specification must preregister the exact
stable-path selection rule, bootstrap threshold, candidate budget, top-k rule, and multiplicity
family before exploratory outcomes are produced at scale.

## 8. Ordered execution gates

### Gate A: zero-provider contract canary

- build four arms for four independent discovery tasks;
- prove exact exclusion of confirmation task IDs;
- commit candidate, variant, assignment, command, environment, and digest artifacts;
- validate balanced permutations and deterministic replay;
- record deterministic extraction as a non-authoritative diagnostic without adding matcher rules;
- reject duplicate, missing, stale, cross-task, cross-CWE, and post-outcome inputs.

### Gate B: blind extraction canary

- render one locked LLM candidate per arm with no semantic retry;
- preserve every raw response in a new run directory;
- blindly re-extract all exact candidate texts with the run-locked Prompt extractor;
- require the source prompt to remain byte-for-byte as the candidate prefix and permit append-only
  intervention text;
- verify allowed safety/presentation deltas and target-state variation as hard graph gates;
- record task-projection differences between independent source and variant extractions as extractor
  drift diagnostics rather than hard semantic failures, because the append-only boundary preserves
  the original task text and the v3 micro run demonstrated a source-side false negative;
- stop before generation if any hard invariant fails.

### Gate C: bounded real outcome canary

- commit assignments before provider calls;
- issue at most 16 generation requests for one code model;
- complete or repair every assigned request;
- run one frozen single-pass functional judge and the independent Oracle;
- publish outcome coverage and failure diagnostics without filtering assigned units.

### Gate D: exploratory table/PAG canary

- assemble separate exploratory tables with `C_D`;
- verify at least two observed states in `C_D`, target `X`, and the configured outcome before FCI;
- run raw augmented and JCI-constrained FCI;
- task-cluster bootstrap only if support and the configured engineering budget allow it;
- report feasibility and uncertainty without a scientific significance claim.

Each gate requires an explicit pass before the next gate may call a provider or increase workload.

## 9. Canary acceptance and rejection

The canary is technically successful only if:

- all 4 exploratory task IDs are disjoint from all confirm task IDs;
- all 16 arm variants are present exactly once and bound to one frozen source Prompt;
- assignments are balanced within every complete block and reproduce byte-for-byte;
- exact texts pass blind extraction and hard pre-generation invariants;
- Gate A exact catalog texts contain both intended target `PRESENT` and `ABSENT` states within each
  CWE, and Gate B LLM-facts TSG extraction realizes both states before generation;
- no task, non-target safety, or undeclared presentation feature changes;
- every generated assignment has complete generation, functional, and Oracle provenance;
- raw and JCI PAGs preserve endpoint marks and committed assumptions;
- no failure is silently skipped, retried semantically, overwritten, or converted into a favorable
  candidate.

Failure of an LLM-rendered arm is evidence about intervention feasibility, not permission to fall
back to deterministic wording in the same run. Failure of FCI support is a typed canary result, not
permission to fabricate or force an edge.

## 10. Adoption decision after the canary

Passing the canary authorizes drafting a scale-up specification; it does not itself authorize the
main experiment. Formal adoption still requires approval of:

- discovery/confirmation task counts and split construction;
- the final CWE and FeatureSpec universe;
- the candidate-freeze and top-k rule;
- exploratory and confirm multiplicity families;
- model and seed budgets;
- exact claims distinguishing natural identifiability, exploratory discovery, and held-out ITT.

If the canary fails because valid target variation cannot be produced without semantic drift, the
fallback remains descriptive observational FCI plus preregistered catalog/theory hypotheses in
held-out randomized confirmation.
