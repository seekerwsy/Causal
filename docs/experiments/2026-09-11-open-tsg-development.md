# Open TSG development and operation-bound hypotheses

Status: bounded, exposed development work; no formal Discovery, Confirmation or
representation qualification. The active draft is `docs/protocol.md`. The owner
requested implementation of open concepts, operation instances, context-only D0,
experiments and a case/result visualization. This report preserves the initial
22-call representation exploration. The later 120-assignment comparison, final
visualization and verification are in [the current effects report](2026-09-11-open-tsg-effects.md);
none of its twelve Holm-adjusted comparisons is significant.

## Implemented scientific change

`prompt_contract.py` now distinguishes concrete concept definitions from task-local
instances. `prompt_contract_extract.py` makes one source-only call with no external
CWE/family routing. Open concepts are permitted only during exposed development;
`freeze_open_concepts` fixes a reviewed vocabulary before subsequent use. Normalization
can distinguish an incoming request object from an outgoing request operation even
when the annotator uses the same name. A vocabulary freeze does not grant formal
study or qualification authority.

`prompt_tsg.py` retains explicit absent concepts and per-operation feature states in
schema 3. Omitted features remain unknown. Relation queries join on the same operation
instances instead of combining evidence from different operations. Legacy graph-record
identities and frozen annotation runs retain their old interpretation.

`mechanisms.bind_task_hypothesis` records one source graph, local context, operation,
one or two features and source expression states. `render_task_hypothesis` uses the
same binding for ADD/REMOVE text. Unknown source state blocks the edit. Removal needs
an identifiable requirement confined to that operation and cannot overlap other
source evidence. Pair binding has no Atomic-parent dependency; natural support and
selector admission remain separate requirements.

`discovery_population.py` removes feature states, Pair cells and candidate/fold slots
from D0 profiles, censuses and requests. Context deficits alone determine acquisition
requests. Unknown membership and remaining gaps are retained. The independent verifier
uses the same specified context thresholds without calling the production decision
helper. The current synthetic smoke fixture was updated for the new D0 input schema;
no frozen run was overwritten and its outcome fixtures are unchanged.

## Executed representation checks

All three attempts use only the same ten previously exposed tasks from
`data/method/tsg-label-development-v1/tasks.json`. No new task exposure, protected
qualification input, role assignment or D0 acquisition occurred. Model: fixed
`qwen3.7-flash-2026-07-15`, temperature 0, seed 81370, one attempt per scheduled task.

| Attempt | Calls | Compiled graphs | Retained limitation |
|---|---:|---:|---|
| `open-tsg-development-v1` | 10 | 0 | Repetition indices mistaken for source line numbers; invalid endpoints; generic roles used as concrete concepts |
| `open-tsg-development-v2` | 2 | 1 | Pilot stopped as planned: SQL case had nonliteral edge quotes and duplicated operation aliases |
| `open-tsg-development-v3` | 10 | 8 | Five compiled graphs carry unresolved diagnostics; two responses reference undefined concepts |

The third attempt prospectively retains valid facts when another citation is unbound.
An unbound node remains unknown; an unbound relation asserts no edge. Exact duplicate
concept/span instances are merged with a diagnostic. This is a conservative partial-graph
rule, not a relaxation that turns an unsupported claim into presence or absence.
The first two frozen results are not relabelled under it. All raw returns are retained.

These are development checks of representation behavior, not comparable accuracy
estimates: prompts and compilation rules changed prospectively between attempts.
The eight v3 graphs contain 46 raw concept names before reviewed normalization.
More nodes or names do not establish better hypothesis selection. The observed
`http_request` name collision across node types is a reason to review equivalences.

Inputs and outputs are under `data/method/open-tsg-development-v{1,2,3}`. Each contains
its frozen plan, task selection, evaluator, prompt, raw output bundle and source archive.
Source archive SHA-256 values:

- v1: `cd5aaa458b8a94392cd0e75312093f6d8aeb35c99c9e931fa9cc23d1cd82034e`.
- v2: `92964f6d155484af3865e1a504245c62b878803fd3d41b22591bd5640a0af104`.
- v3: `83b1dc12da81dfcd0380817ec5f7074914373227241a509e1dacbdd7046aea24`.

Server paths remain beneath `/home/wsy/work/prompt-mechanism-study/inputs` and
`results`, with the corresponding attempt name. Execution used Python 3.12.11 image
`sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0`.
Credentials stayed owner-only in the existing server environment. The v3 command,
with its frozen archive mounted at `/input` and result directory at `/output`, was:

```text
PYTHONPATH=/input/src python -m prompt_mechanism_study representation extract-contracts /input/tasks.json /input/catalog.json /input/evaluator.json /input/annotator.md /input/selection.json /output/extraction --development-exposed --workers 1
```

All 22 calls are accounted for in the existing preexperiment ledger. The allocated
ceilings charge CNY 1.10 conservatively, bringing cumulative accounting to CNY 3.533318
and remaining authorization to CNY 96.466682. This is not provider invoice usage.

## Offline case viewer

`representation visualize` writes a standalone HTML file. It verifies the input
bundles and graph evidence, displays failed tasks and unknowns, highlights the exact
source span on node/edge selection, exports editable SVG, and can display effects
and every assigned-arm row from a saved result bundle. Missing measurements are
shown as unmeasured. The page does not generate or estimate outcomes.

```text
prompt-mechanism-study representation visualize data/method/open-tsg-development-v3/tasks.json data/method/open-tsg-development-v3/results results/open-tsg-explorer/index.html
```

The implementation is `tsg_visualization.py` with `fixtures/tsg-viewer.html`.

## Verification and remaining scientific work

The focused contract/query checks passed (55 tests, including retained legacy identity
checks). The seven context-only D0/open-graph checks passed, and both saved two-freeze
lineage variants passed after updating the synthetic D0 fixture. These checks do not
establish automatic annotation accuracy or an experimental effect.

The subsequent report completes reviewed development concept normalization, bounded
code generation/measurement, effect/unknown reporting and clean reviewer reproduction.
It preserves original failures and labels the post-hoc mechanical replay explicitly.
Formal representation acceptance, natural Discovery support, selector comparisons and
Confirmation remain unexecuted and cannot be inferred from these development checks.
