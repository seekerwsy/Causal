# Requirement-owned temporal relation check

This is a bounded development diagnostic on two already exposed natural tasks.
The question is whether complete requirements can retain temporal operands without
making both operands direct recipients of the whole predicate. It does not test
general extraction stability or natural intervention effectiveness.

`protocol/plan.json` and the exact source archive were frozen before outputs.
`constructor-instructions.txt` restricts each fresh Codex constructor to its own
input and at most one compiler-only repair. Both retained first drafts compiled;
no review or repair call ran. Original inputs and previous results were not changed.

| Case | Source-reference judgments | Owned orders | Complete structural projections |
| --- | ---: | ---: | ---: |
| Privilege ordering | 5/5 correct | 2 | 2 |
| Registration | 4/4 correct | 1 | 1 |

`analysis/source-audit.json` contains root Codex judgments, not independent human
gold. `analysis/projection.json` checks each actual order binding: removing or
reversing its relation fails positive matching; removing the owner while retaining
source entities does not change the independent scope query. These are structural
mutations, not edits to the natural prompt or approved research factors.

The source owner may itself introduce an operation or transformed participant.
Consequently, real whole-requirement removal may lose required anchors or alter
other obligations. That intervention boundary still needs separate validation.
No security outcomes, Discovery or Confirmation ran. External API calls/cost: zero.
Codex usage is separate; its exact model snapshot and seed are unavailable.

Replay both constructions, projections and audit counts through the existing entry:

```text
.venv/Scripts/python.exe data/method/tsg-reliable-construction-v1/verify.py
```

The replay uses the frozen implementation and saved responses, without model calls.
It verifies reproducibility, not the truth of the author judgments. The clean
reviewer suite passed 104 tests; one ownership invariant test was added and an
existing edit-preservation test was extended.
