# Qwen Max thinking-mode comparison

The actual Alibaba Bailian model `qwen3.7-max-2026-05-20` completed the same two
exposed tasks. Both final graphs compiled, but both still violated the predeclared
operation-predicate/concrete-binding separation. This configuration did not match
the preceding DeepSeek Flash thinking run on that narrow check.

| Observation | DeepSeek Flash thinking | Qwen Max thinking |
| --- | --- | --- |
| Initial extraction compiles without correction | 2/2 | 1/2 |
| Final graph compiles | 2/2 | 2/2 |
| Local semantic patch requested | 2/2 | 1/2 |
| Final predicate/binding separation, author audit | 2/2 | 0/2 |
| Registration web-application requirement represented | Yes | No |
| Actual provider calls | 6 | 6 |
| Conservative cost, CNY | 0.964020 | 1.756200 |

These are one-draw, two-task development observations, not general model accuracy
or ranking. The separation criterion allows action/API/category distinctions but
excludes specific bound participants, destinations, conditions and order from
operation predicates. Passing it does not certify the whole graph.

## Observed defects and repairs

Registration initially used task-wide scopes with nonempty operation target lists.
The one mechanical correction changed four scopes to `targets`; it did not correct
predicate content. The reviewer approved all 14 records and all four source units.
`Insert the username and hashed password into a database.` remains an operation
definition, duplicating concrete bindings. Account registration is represented, but
the explicit web-application constraint appears only in coverage prose. The source's
human user is also treated as a data input to registration/credential collection.
The previously disputed username-insertion interpretation remains separate from
these confirmed defects. Hash-before-insertion is still requirement-owned.

Privilege ordering compiled on the first attempt. The reviewer rejected inputs on
raise/lower-privilege and exception-handling operations. The local patch removed
those three links and withdrew two extra objects, while preserving all four
requirements, both ordering relations and the directory-exists guard. However,
`Create a directory at the /home/ directory.` remains in the operation definition;
no operation fact changed. Thus local repair occurred without fixing this contract
failure. The review's argument that an API has no arguments is not a general proof
that it uses no resource; the three removals are not independently certified fixes.

The patch proposed complete coverage, but the existing withdrawal rule marked source
units u9/u10/u11 unresolved. This exercised the real withdrawal path and preserved
uncertainty; it did not establish absence or downstream candidate availability.
The supplied `pass` bodies are treated as interface/scaffold detail rather than
mandatory no-op implementations. Complete interface preservation is not certified.

## Fixed configuration and evidence

`inputs/plan.json` was fixed before calls. Task inputs, instructions, catalog and
all 52 archived source/runner files are byte-identical to the
[DeepSeek thinking comparator](../predicate-binding-thinking-api/README.md).
Both initial wire requests contain identical messages to that comparator. The
unchanged client uses provider-specific thinking and output-limit fields.

Thinking is enabled; the total completion limit is 65,536 tokens, response cap
2 MiB and timeout 600 seconds. No explicit `thinking_budget` is sent, so the old
4K thinking cap is not reused. Requested temperature is 0, top_p 1 and seed null.
Provider defaults, tokenization and decoding semantics differ; this is not an equal
reasoning-compute or deterministic comparison. See the
[Bailian thinking documentation](https://help.aliyun.com/zh/model-studio/deep-thinking).
All six envelopes finished with `stop`; only final `content` was parsed. There was
no truncation, transport retry, extra reviewer or resampling.

Usage was 48,925 input and 32,475 output tokens, including 19,548 reasoning tokens.
At [uncached list prices](https://help.aliyun.com/zh/model-studio/qwen3-7-max),
conservative debit was CNY1.756200 against the CNY12 ceiling; recorded authorization
remaining is CNY30.328131. This is accounting, not a provider invoice.

Read `analysis/summary.json`, `analysis/source-review.json` and `analysis/calls.json`.
The audit is by the author/assistant against the frozen criteria, not independent
human gold. No candidate/edit/code-outcome evaluation was run. Production code,
paper and Atomic-only scope are unchanged; the protocol remains SPECIFIED_DRAFT.

`execution-source.tar.gz` and `results.tar.gz` retain the exact executable inputs,
requests, envelopes, intermediate records and outputs. Archive identities and replay
results are in `analysis`; the extracted `server-results` directory is regenerable.
The exact offline wire/result replay passed with zero provider calls:

```text
python -c "import runpy; from pathlib import Path; m=runpy.run_path('data/method/tsg-reliable-construction-v1/verify.py'); print(m['verify'](Path('data/method/tsg-reliable-construction-v1/predicate-binding-qwen-max-api')))"
```

The aggregate verifier includes this batch. No full-suite rerun was needed because
the production implementation is unchanged.
