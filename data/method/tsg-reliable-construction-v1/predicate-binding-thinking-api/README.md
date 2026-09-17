# Thinking-mode API check of predicate/binding separation

Enabling DeepSeek Flash thinking with larger delivery limits produced a narrow
improvement on the same two exposed development tasks. Both initial graphs compiled;
the ordinary source reviewer then identified operation-definition defects and the
existing local patch corrected them. Source interpretation remains unresolved in
both tasks, so this is not a whole-graph correctness or stability result.

| Observation, per natural task | Previous non-thinking | Thinking configuration |
| --- | --- | --- |
| Initial extraction compiles without mechanical correction | 0/2 | 2/2 |
| Final graph compiles | 2/2 | 2/2 |
| Source review requests a local semantic patch | 0/2 | 2/2 |
| Final action predicate/concrete binding separation, author audit | 0/2 | 2/2 |
| Explicit registration web/account task requirement | Omitted | Represented |
| Actual provider calls | 6 | 6 |
| Conservative cost, CNY | 0.178368 | 0.964020 |

The semantic row checks the predeclared representation boundary, not general
semantic accuracy. A predicate retains action/API/category distinctions: category
terms such as credentials, a password value or a username parameter are allowed.
Concrete bound objects, specific destinations, guards and order belong in their
structured fields. This does not certify that every extracted binding is supported.

## What the existing repair path did

Registration's reviewer rejected three operation facts. The patch changed their
definitions to `Take credentials from the user.`, `Hash a password value.` and
`Insert credentials into a database.` Concrete participants remain in the input
and result bindings. The initial extraction also restored the explicit web
application/account-registration requirement omitted in the preceding batch.
However, it still asserts username insertion; the original singular pronoun leaves
that prior source interpretation disputed. It is not counted as resolved here.

Privilege ordering's reviewer rejected the exception-handler fact. The patch
changed `Handle the exception raised when the directory already exists.` to
`Handle the exception.` The directory-exists guard remains on the requirement.
The named raise/lower API distinctions and both requirement-owned ordering
relations survive; every operation's own `precedes` field is empty.

The privilege extraction also interprets the supplied `pass` bodies as mandatory
no-op implementations of `raisePrivileges` and `lowerPrivileges`. They could instead
be placeholders, and a required no-op body is in tension with the requested
privilege changes. This ambiguity was not flagged as unknown by the model. Those
extra records are not counted as verified coverage gains.

In both tasks only the rejected operation facts changed during patching. All
objects, requirements, input/result bindings, coverage and influence annotations
were preserved. The initial extraction still had predicate/binding defects in both
tasks; improvement came from the existing review/patch steps detecting and fixing
them. No record withdrawal ran, and no extra reviewer or resampling was added.

## Fixed comparison and delivery

`inputs/plan.json` was fixed before requests. The two tasks, catalog, instructions,
evaluation criteria and all 52 archived source/runner files are byte-identical to
the [preceding batch](../predicate-binding-api/README.md). Implementation is
`c75312c11ba89233b5231902de3760881b1b3861`; the exact Docker image and server command
are in `execution/identity.json` and `launch.sh`.

Four evaluator settings changed: thinking false to true, total output cap 16,384
to 65,536 tokens, response cap 256 KiB to 2 MiB, and timeout 180 to 600 seconds.
Both initial wire requests have identical messages to their comparators, with only
`thinking` and `max_tokens` changing in the body. Later review/patch prompts naturally
depend on the newly generated records. This compares configurations; it cannot
isolate the effect of thinking from the larger resource bounds.

The model is `deepseek-flash`. The client does not send `reasoning_effort`, leaving
the provider default high. Requested temperature 0 is ignored in thinking mode;
top_p remains 1. These behaviors are documented in the
[provider's thinking guide](https://api-docs.deepseek.com/zh-cn/guides/thinking_mode/).
There is no seeded decoding guarantee.

All six calls ended with `finish_reason=stop` and complete final JSON. The unchanged
client parsed only final `content`; reasoning text was never used to reconstruct
a missing graph or as evidence of semantic correctness. Four calls used more than
16,384 reasoning tokens alone, demonstrating why the old total allowance was small
for these observed thinking trajectories. No delivery failure or mechanical retry
occurred in this batch.

Usage was 54,362 input and 106,912 output tokens, including 96,069 reasoning tokens.
At [uncached peak rates](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/),
conservative debit was CNY0.964020 against the CNY7.70 ceiling, leaving CNY32.084331
of recorded authorization. These accounting bounds are not provider invoices.

## Evidence and reproduction

Read `analysis/summary.json`, `analysis/source-review.json` and `analysis/calls.json`.
The source audit is by the author/assistant with a second read-only agent pass,
not independent human gold. There was one draw per already-exposed task, no new or
protected task, and no downstream candidate, edit or code-outcome evaluation.
The result supports further use as a development comparison configuration; it does
not promote the configuration to a qualified default or justify another method layer.
The protocol remains SPECIFIED_DRAFT and Atomic-only; no paper changes were made.

`execution-source.tar.gz` retains the exact executable source and frozen inputs;
`results.tar.gz` retains all request bodies, provider envelopes, usage, intermediate
records and final graphs. `analysis/identities.json` records archive hashes.
The extracted `server-results` directory is a regenerable cache, not a second
artifact. Exact wire and result replay passed offline with zero provider calls:

```text
python -c "import runpy; from pathlib import Path; m=runpy.run_path('data/method/tsg-reliable-construction-v1/verify.py'); print(m['verify'](Path('data/method/tsg-reliable-construction-v1/predicate-binding-thinking-api')))"
```

The aggregate verifier also includes this batch. Production source is unchanged,
so the existing focused verification was reused rather than rerunning the full suite.
