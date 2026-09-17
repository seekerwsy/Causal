# Fresh API check of predicate/binding separation

This exposed-development check used the actual DeepSeek API, model `deepseek-flash`,
thinking disabled and temperature 0. It used the implementation at `c75312c1` and
the existing `scripts/run_tsg_development.py`, without changing production code.
The two natural tasks were already exposed: registration and privilege ordering.
Fresh open extraction received their original input, the new contract and schema,
not previous graphs, reference answers or author-normalized operation definitions.

Six provider requests returned six complete envelopes. Each task needed one
mechanical correction, followed by one ordinary source review. Both reviews
approved all records and all source units, so no semantic patch ran.

| Observation | Result |
| --- | --- |
| First extraction compiles without correction | 0/2 tasks |
| Final graph compiles | 2/2 tasks |
| Model approves every record and source unit | 2/2 tasks |
| Author audit: operation predicates separated from concrete bindings | 0/2 tasks |
| Critical order and exception-guard structures retained | 2/2 tasks |
| Confirmed omission of an explicit task-scope requirement | Registration |

The registration operation still says it inserts the username and hashed password
into the database while also declaring those participants in `inputs`. Its explicit
web-application/account-registration requirement has no requirement record. The
mechanical correction changed that source unit's coverage from `represented` to
`no_task_fact`; the reviewer accepted a global influence annotation as completeness.
Influence scope does not itself represent the missing obligation. The disputed
username-insertion interpretation is retained separately from these confirmed defects.

The privilege graph correctly contains requirement-owned before/after relations
and the directory-exists guard. However, its operation definitions still contain
the after-clause, condition and concrete participants. The reviewer explicitly
acknowledged order/condition in the definitions but approved them because they were
not in the operation fields. This does not satisfy the new contract: future freezing
would retain those assertions inside the operation's meaning as well as its bindings.
This is a representation-contract failure, not a claim that every requirement or
relation in the graph is wrong.

The initial privilege response had extra JSON data after a completed object despite
`finish_reason=stop`; it was not token truncation. Its one allowed mechanical retry
produced parseable records. All new instructions and operation readback were verified
in the retained requests, ruling out use of the old request contract in this batch.

The six calls used 53,120 input and 9,016 output tokens. Accounting at uncached peak
rates from the [official pricing page](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)
conservatively debited CNY0.178368, leaving CNY33.048351 of recorded authorization.
The batch ceiling was CNY3.80. These are accounting bounds, not provider invoices.

Read `inputs/plan.json`, `analysis/summary.json` and `analysis/source-review.json`.
The author audit follows the criteria fixed before requests; it is not independent
human gold. The previous model/runtime and catalog conditions differ, so this is
not a controlled estimate of improvement. Neither repeated stability nor automatic
semantic repair is established. The new withdrawal path was never triggered.
Do not add reviewers or retune this completed batch to erase its negative result.

`execution-source.tar.gz` retains the exact implementation and input bundle;
`results.tar.gz` retains every request body, response, provider request ID, usage,
error and final graph. `launch.sh` records the owner-only credential location and
exact server command, without including credentials. Both archives have identities
in `analysis/identities.json`. They were replayed offline with exact wire and result
equality; replay makes no API calls. To repeat that check from the repository:

```text
python -c "import runpy; from pathlib import Path; m=runpy.run_path('data/method/tsg-reliable-construction-v1/verify.py'); print(m['verify'](Path('data/method/tsg-reliable-construction-v1/predicate-binding-api')))"
```

The existing verifier's aggregate command also includes this batch. The protocol
remains SPECIFIED_DRAFT and Atomic-only; no protected tasks, paper changes, code
outcomes or scientific effect claims are involved.
