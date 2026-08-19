# Five-CWE independent-validation source audit

## Scope and environment

- Date: 2026-08-19 (Asia/Shanghai).
- Repository worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`.
- Fixed Python: `D:\MyCode\Causal\.venv\Scripts\python.exe`.
- External cache: `D:\MyCode\Causal\datasets\external-cache`.
- No generated code, functional outcome, Oracle result, or experiment arm was consumed.
- Public-source inventory used zero provider calls. The later eligibility canaries used the
  separately authorized Bailian structured reviewer and retained every request and response.

## Frozen source receipts

| Source | Frozen revision or digest | Raw task units | Five-CWE units |
|---|---:|---:|---:|
| CodeGuard+ | archive SHA-256 `ce1619f...d2bca` | 103 | 17 |
| LLMSecEval | archive SHA-256 `9119fa...7c022` | 150 | 27 |
| SecCodeBench | tag `v2.2.0`, commit `67126ef...d83d` | 98 | 31 |

The combined five-CWE queue has 75 units: CWE-78/89/502/328/338 = 25/25/23/1/1. It
contains 43 Python units and 32 multi-language transportability units. All 75 are exact-digest
disjoint from the 93 method-development tasks. Eight SecCodeBench Python units exactly match
previously inventoried repository assets, but none entered the 93-task outcome population; this is
recorded as asset overlap rather than method-development overlap.

These 75 units are an audit upper bound, not a validation sample. CodeGuard+ and LLMSecEval retain
declared Copilot/SecurityEval ancestry, and task compatibility plus semantic de-duplication remain
outcome-blind review steps.

## Acquisition incidents

1. Two CodeGuard+ shallow-clone attempts failed because the GitHub HTTPS connection reset or could
   not be established. A codeload archive then succeeded and was authenticated by SHA-256.
2. The first SecCodeBench codeload attempt crossed the 30-second command boundary and left an
   incomplete file. The incomplete file was preserved in the external cache and was never accepted
   as input. HTTP range resume was unsupported, and BITS rejected the dynamic response because it
   lacked a content-length header.
3. A shallow clone of SecCodeBench tag `v2.2.0` fetched a valid object database, but Windows failed
   to check out one overlong Docker-model path. The audit reads benchmark manifests and prompts
   directly from Git commit `67126ef...d83d`; it does not execute or repair the checkout.

## Eligibility canary and correction

The first five-call eligibility canary completed with no transport or schema errors. Four decisions
were semantically consistent. The CWE-502 decision incorrectly treated user-controlled YAML and an
imported YAML library as proof that arbitrary unsafe deserialization was required, despite the
Prompt only requesting ordinary mapping fields.

The correction is intentionally bounded:

1. the provider request omits CWE, source, ancestry, Oracle-profile identifier, and repository
   overlap metadata;
2. profile v2 states that ordinary JSON/YAML data parsing can be preserved by a restricted loader,
   and that importing a library or accepting user input alone does not imply arbitrary object
   reconstruction;
3. the same CWE-502 unit was rerun once with the same model and sampling settings.

The corrected call completed successfully and classified the task as compatible because a safe YAML
loader preserves the requested fields. The v1 decision remains immutable and is not mixed into the
v2 review population.

## Verification

- External source audit and task-review preparation tests: 2 passed.
- Main-pool reviewer plus external task-review tests after provider-view blinding: 9 passed.
- No full repository test suite was run.

## Completed outcome-blind review

The complete 75-unit queue was reviewed without generated code, functional outcomes, Oracle
results, or experiment-arm assignments. The provider-facing packet contained only the prompt,
language, finite profile scope, packet identifier, and blindness declaration. It omitted CWE,
source, ancestry, Oracle identifiers, repository overlap, and all outcomes.

The first bulk pass returned 65 structured decisions and 9 parse failures. Parser recovery was
limited to two semantics-preserving cases: normalizing `output` to the registered
`input_output` token, and resolving a uniquely matching whitespace-normalized evidence quote.
Seven residual cases and three materially incorrect classifications received explicit,
line-recorded overrides; neither failures nor original provider responses were overwritten. The
frozen reconciliation contains 75 decisions, zero unresolved units, and 56 eligible prompt units:
CWE-78/89/502/328/338 = 17/24/13/1/1.

## Semantic independence result

Prompt variants expressing the same observable programming task were then collapsed before any
outcome was observed. Six explicit merge groups cover repeated ping-route, unsubscribe, buy-order,
message-post, YAML-price, and payload-name tasks. One Flask YAML parsing task was also excluded as
a semantic match to the 93-task method-development population.

The resulting public-source pool has 41 semantic task clusters, of which 40 are independent of
method development. Their CWE distribution is 14/15/9/1/1 for CWE-78/89/502/328/338. All five
registered CWEs are present, but the frozen minimum of 50 independent tasks is not met. The pool
therefore remains blocked with reason `insufficient_semantically_independent_tasks`; lowering the
threshold or counting prompt paraphrases as independent tasks is not permitted.

Frozen artifacts:

- `five-cwe-external-validation-task-review-reconciliation-reviewed-20260819-06` records the
  reconciled eligibility decisions and override provenance.
- `five-cwe-external-validation-semantic-pool-20260819-01` records semantic clusters, the
  development-overlap exclusion, independent candidates, effective configuration, commands, and
  artifact digests.

Targeted verification after reconciliation and clustering: 12 tests passed. No provider calls,
code generations, or outcome reads were performed during reconciliation or clustering. No full
repository test suite was run.
