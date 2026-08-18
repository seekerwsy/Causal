# Five-CWE Pooled Policy Estimand

**Date:** 2026-08-18

**Status:** Approved replacement for the equal-per-CWE main-sample assumption

**Applies to:** the frozen five-CWE main task pool only

## 1. Decision

The primary scientific target is the task-population effect of assigning an
operation-specific security requirement. The intervention policy first observes the registered
CWE scope of a task and then selects exactly one existing, typed Prompt-TSG safety feature:

| CWE scope | Existing Prompt-TSG target feature | Required mechanism |
|---|---|---|
| CWE-78 | `safety.safe_subprocess` | argument-vector process invocation without a shell |
| CWE-89 | `safety.sql_parameterization` | parameter binding for query-relevant values |
| CWE-502 | `safety.safe_deserialization` | data-only safe loading |
| CWE-328 | `safety.collision_resistant_hash` | a non-weak collision-resistant hash |
| CWE-338 | `safety.cryptographic_randomness` | security-appropriate unpredictable randomness |

`policy.operation_specific_security_requirement` is a policy-level target, not a sixth
Prompt-TSG feature. It is never rendered directly and it does not collapse the five program
mechanisms into one graph node. In a pooled causal-variable table,
`x_operation_specific_security_requirement` is derived as the state of the one registered child
feature selected for that task. Every underlying graph and intervention artifact retains the child
feature identity.

## 2. Frozen population

The population is the complete outcome-blind task bundle
`five-cwe-main-task-pool-frozen-20260818-07`, digest
`12c6b723ffe8402720bd8cfae34a1098da3cfd9cea537eda8e39409febf064bf`.
The authenticated split is preserved without rebalancing:

- discovery: 51 independent tasks;
- confirmation: 42 independent tasks;
- total: 93 independent tasks.

Every task receives equal weight. The estimand therefore describes the empirical frozen task
population; it is not an equal-CWE standardized effect. The CWE composition is reported with every
estimate. Generated code, Oracle labels, functional judgments, target realization, and outcomes
cannot change membership, weights, or the discover/confirm split.

## 3. Intervention and primary estimand

All five child targets use the existing Safety ADD four-arm protocol:

1. `TARGET_PATCH` adds the task's registered child safety requirement;
2. `NOOP_REWRITE` preserves task and security semantics;
3. `LENGTH_MATCHED_PLACEBO` controls for appended text of comparable length;
4. `GENERIC_SECURITY_REMINDER` adds general security salience without the child mechanism.

The primary estimand is computed separately for each frozen code-generation model:

\[
\operatorname{ITT}_{m} =
E[Y_{\text{secure-and-functional}}\mid A=\text{TARGET\_PATCH},m]
-E[Y_{\text{secure-and-functional}}\mid A=\text{NOOP\_REWRITE},m].
\]

It is the task-clustered, equal-task-weight risk difference over all assigned held-out confirmation
tasks. All assignments remain in the denominator. Parse failure, Oracle unknown, functional unknown,
`target_changed=false`, and semantic-validity diagnostics are not post-randomization filters. The
primary inference is two-sided: completing the experiment does not require a significant estimate or
an improvement in security.

The two model strata are:

- `qwen2.5-coder-7b-instruct`;
- `phi-4-14b`.

They are never pooled. The two primary model-specific tests form one frozen multiplicity family of
size two.

## 4. Secondary and diagnostic analyses

The pre-registered secondary contrasts are:

- `TARGET_PATCH - NOOP_REWRITE` on the CWE-specific secure outcome;
- `TARGET_PATCH - LENGTH_MATCHED_PLACEBO` on secure-and-functional outcome;
- `TARGET_PATCH - GENERIC_SECURITY_REMINDER` on secure-and-functional outcome.

The placebo-versus-no-op and generic-versus-no-op contrasts, parse and Oracle coverage, functional
status, semantic validity, and target realization are diagnostics. CWE is retained as a frozen
context and heterogeneity dimension. A CWE-specific estimate may receive confirmatory status only
when its held-out split has at least 20 independent tasks. With the frozen pool this condition is met
only by CWE-78; the remaining CWE-specific intervals are descriptive heterogeneity diagnostics.

## 5. Discovery and JCI relation

The discovery split uses the same deterministic CWE-to-child mapping. Natural observational FCI and
randomized exploratory JCI-FCI remain separately labeled. In the pooled exploratory table:

- `c.exploratory_arm` records the randomized arm;
- `c.cwe_scope` records the registered CWE scope;
- `x_operation_specific_security_requirement` is the state of the applicable child feature;
- the child feature ID is retained as provenance and for local CWE tables.

Neither the parent variable nor background knowledge requires an adjacency or path. Stable candidate
paths and their directions must still be frozen without access to confirmation outcomes. This
estimand freeze does not authorize code generation: the exact four-arm Prompt variants must first be
validated and frozen.

## 6. Implementation invariants

1. The policy mapping is total and one-to-one over the five registered CWE scopes.
2. Every mapped child is an existing intervenable Safety ADD FeatureSpec applicable to the task's
   CWE and task family.
3. The task bundle, catalog, mapping, model strata, arms, contrasts, minimum task threshold, and
   weighting rule are digest-bound before provider calls.
4. Discovery and confirmation tasks remain disjoint by the already frozen task-cluster split.
5. New runs use immutable directories and retain commands, environment, inputs, mappings, reports,
   and artifact digests.
6. Per-model and per-CWE results are never silently pooled into the primary estimate.
