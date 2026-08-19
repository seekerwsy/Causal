# Five-CWE independent-validation functional contracts v1

## Frozen scope

The independent-validation pool contains 55 semantic task clusters. The contract freeze recovered
and digest-checked every source Prompt before code generation. The distribution is
CWE-78/89/502/328/338 = 16/20/17/1/1 and Python/Java/Go/C = 35/11/4/5.

The 40 prior public-source clusters reuse the 156 functionality requirements already accepted by
the outcome-blind external-task audit. Reuse is keyed by the representative source record and exact
Prompt digest. The 15 supplemental SecEvalPlus clusters received 51 requirements covering only
their stated interfaces, behavior, inputs and outputs, validation, and error handling. The
requirements were completed by Codex before treatment and outcome generation. No CWE identifier,
intervention arm, target mechanism, generated code, model identity, or outcome is available to the
runtime functional Judge.

The runtime outcome remains the previously frozen single-pass LLM functional Judge. This stage only
fixes the per-task contract that the Judge will receive; it does not run the Judge and does not
produce an outcome.

## Result

`five-cwe-independent-validation-functional-contracts-20260819-01` completed with 55 source
Prompts, 55 audit decisions, 55 contracts, zero failures, and zero pending tasks. It made zero
provider calls and consumed zero outcomes. The restricted Prompt bundle digest is
`8ae57b65ba18361b3510e8404ba841b8bb86aa374460291befc060ea66dac470`; the contract bundle digest is
`82b8f26e8bd08e3ec1edab6034b0f3642e88941ea425382c9c6f1bebcfe3cb60`.

Because the SecEvalPlus source reports an unresolved license, the complete source Prompts, evidence
quotes, requirements, decisions, and contracts remain under the ignored `runs/restricted` tree.
The versioned public artifact contains only task/source coordinates, Prompt and requirement
digests, contract IDs, judgeability, counts, configuration, commands, and artifact hashes. It
contains zero raw Prompt and zero raw requirement text.

## Validation and incidents

Five targeted unit tests passed for exact evidence binding and rejection of mechanism or label
leakage. The production freeze then independently revalidated all 55 Prompt SHA-256 values, every
verbatim evidence quote, all schema contracts, unique task/Prompt/contract IDs, required CWE
coverage, and the expected 40/15 origin split.

Two read-only inspection commands initially referenced guessed functional-judge and generation
module filenames that do not exist. The repository was then searched for the authoritative paths
before inspection; no file was changed by either failed lookup. A later unscoped ignored-file status
check also traversed old ignored Windows paths and emitted long-path/permission warnings. It did not
alter repository state. Subsequent status checks must remain scoped and must not request ignored
trees.

The first adjacent-test command also named a nonexistent `test_functional_judge_factory.py`; pytest
correctly stopped during collection and ran no tests. After enumerating the actual files, the
contract and Judge tests passed 26/26 and the functional-Judge stage test passed 1/1.

The next stage is the pre-generation freeze of the four-arm intervention renderer, Phi-4-14B
runtime coordinates, generated-response code extraction policy, single-pass Judge policy digest,
mechanism policy digest, and FCI/JCI analysis manifest.
