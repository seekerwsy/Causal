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

## Supplemental acquisition and threshold resolution

Two additional licensed benchmarks were inspected first. SecRepoBench was frozen at commit
`7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76`; its published 15-CWE mapping covers memory and
pointer-safety weaknesses rather than the registered CWE-78/89/502/328/338 scope, so it was not
used to change the frozen validation question. BaxBench was frozen at commit
`de885cd93d561682e203a5a0d57c33b08aac6f5e`; it remains a useful MIT-licensed application-level
external benchmark, but its 28 scenarios do not supply enough new five-CWE semantic clusters on
their own. A partial-clone blob fetch also failed once during static inspection when the GitHub
connection was unavailable; no benchmark output was read.

CodeSecEval SecEvalPlus was then frozen at revision
`c3ffce09269f2d7b092888efe05d070b6fcb97f5`, file SHA-256
`f2098b4e0d7c8ad58c2855e3de3b8f1a4cc2d8c8dfa654c93979fa8e8fc1a050`. The 140-row source
contains 30 registered-scope tasks: ten each for CWE-78, CWE-89, and CWE-502. The audit extracted
only task ID, problem statement, entry point, and the presence of a functional split. Insecure
code, secure code, combined tests, and security-test contents were neither retained nor consumed.
All 30 prompts were exact- and normalized-digest disjoint from both the 93-task method-development
population, the prior 40 independent clusters, and the complete repository asset inventory.

The source reports that its license is under review. Consequently, raw source prompts and review
packets remain in the local ignored `runs/restricted` area. Versioned public artifacts contain only
the source receipt, identifiers, digests, counts, decisions, and cluster membership; they do not
redistribute source prompts or reference fields.

Protocol adjudication accepted 20 of the 30 tasks. The ten exclusions comprise six CWE-78 tasks
that do not require a process, one arbitrary-code-execution task that cannot preserve semantics
within the finite profile, one arbitrary-SQL executor, and two prompts that explicitly prescribe a
security defense and therefore violate safety neutrality. Semantic consolidation produced 15 new
clusters: 2 CWE-78, 5 CWE-89, and 8 CWE-502. Combined with the frozen public-source clusters, the
independent validation pool now contains 55 clusters:
CWE-78/89/502/328/338 = 16/20/17/1/1. It satisfies the frozen minimum of 50 and contains every
registered CWE without reading outcomes.

One preparation attempt stopped before producing an output directory because the supplemental
audit lacked the required repository-asset-overlap field. The incident was corrected by adding the
complete stage-0 repository record audit as a digest-checked input; no default value was imputed.
The corrected `-02` source audit reports zero exact and normalized repository-asset overlaps.

Frozen public artifacts:

- `five-cwe-codesec-eval-plus-source-audit-20260819-02` records the restricted-source metadata and
  overlap audit.
- `five-cwe-supplemental-independent-validation-pool-20260819-01` records the 15 supplemental
  clusters, 10 exclusions, and final 55-cluster pool.

The next authorized stage is measurement-contract freeze. No code generation may begin until the
mechanism extractor, single-pass functional judge, intervention renderer, Oracle behavior, model
runtime, and causal-analysis configuration are all fixed and canary-validated.
