# Single operation-role declaration and prospective source equivalence

This is the next bounded development round after the closed atomic/local check.
It asks whether eliminating duplicate role/input/output decisions removes their
inconsistency while retaining source meanings and all expected scope denominators.
It remains representation in the single seven-stage `SPECIFIED_DRAFT` method.

## Implemented change

The first call still extracts atomic source facts, cites preassigned source units
and lets the program assign fact IDs. The second call now declares each operation/object
role once. `apply_fixed_binding_response` derives `produces` for a result and `used_by`
for every input role, retaining its source citation. The response no longer supplies
separate input/output lists that can contradict those roles. Other rows retain only
operation order, requirement targets/subjects and condition bindings. Fixed template
facts and edges remain mechanical and separate from model assertions.

The binding and scope requests explicitly define roles: userid and filepath stored
in SQL are values; table/column names are structural identifiers; a filepath locating
a download has an identifier role at that different operation. Extracted fields
are results of extraction and inputs to a later query. Ambiguous input roles remain
`input_unspecified`. This removes representational duplication; it cannot prove that
the model chooses the correct role or inventories every source meaning.

There is no new framework or semantic matcher. The existing reference mechanism
prospectively permits four shorter exact citations of the same local objects. Two
return cases retain the return operation, selected-row object and their binding,
without mandating an additional synonymous return-behavior requirement node. An
extra supported requirement node remains permitted and subject to source review.
All declared checks now occur in the full-task required check set. Scope dependencies
retain the relevant structural and state checks. Incorrect concepts, polarity,
thresholds, bindings and unsupported assertions are still defects.

## Fixed scope and validation

The same three natural SQL tasks and three synthetic cases are reused, with the
same exact task bytes, catalogue, Qwen snapshot and decoding settings as the prior
round. The reference has **195 named checks and 20 scopes**. These are exposed
development examples; the reference revision is prospective for this run only.
Old references, counts and judgments remain frozen. This is not independent
qualification or a controlled estimate of semantic-accuracy improvement.

The [input bundle](../../data/method/open-tsg-scope-development-v1/single-role-check/inputs/plan.json)
has digest `225738e96c881d83f585a840db4f6c49e336e73c90e61904113977e1af1220a4`.
Its plan records the exact six source-reference changes and the complete acceptance
and stopping rule. Four focused modules passed **97 tests in 4.15 seconds**.
A source-authored offline replay compiled all six cases and recovered **195/195**
checks and all 20 reference scopes. This proves representability, not model accuracy.

The full reviewer suite passed **321 tests**, with 113 deselected, in **292.27
seconds**, using the established clean Python 3.12.13 environment and unchanged
dependencies. The exact command, environment reference and production source hashes
are captured in
[`validation/report.json`](../../data/method/open-tsg-scope-development-v1/single-role-check/validation/report.json).
No formal reference result exists; the unchanged scientific smoke remains a test artifact.

## Completed real run

After the user's request to continue the next round, the unchanged frozen input
bundle and captured implementation ran once on the same server/provider, within
the original CNY 100 development budget and the 18-call / CNY 1.80 bound. There
were **11 actual calls**: six inventories, four bindings and one scope assessment.
No retries, protected tasks, new natural exposure, code generation, outcome filtering
or formal experiment occurred. The run returned exit code 1 with a closed result
bundle; all six assigned cases remain in the review.

| Case | Calls | Last result | Fixed checks met | Fully accepted |
| --- | ---: | --- | ---: | ---: |
| Natural password lookup | 2 | Bindings compile; scopes withheld for claimed missing resource | 19/22 | No |
| Natural PDF storage | 3 | Scope response retained; extra assertions still need correction | 25/25 | No |
| Natural temperature lookup | 2 | Query misclassified as return operation; no database scopes | 28/51 | No |
| Synthetic two operations | 1 | Output truncated in a coverage rationale at 8192 tokens | 0/30 | No |
| Synthetic conditions/prohibition | 1 | Coverage rejected; template-only unit marked represented without a fact | 0/40 | No |
| Synthetic atomic length | 2 | Binding rejected: empty local impact; input object missing | 15/27 | No |

Four first inventories compiled and three binding steps completed. All submitted
roles produced their corresponding incidence edges without a second model decision;
the previous role-versus-input/output disagreement is absent by construction.
One provider completion ended with `finish_reason=length`, and two cases were
rejected by source coverage/impact validation. The four saved graphs include an
intermediate inventory; they are not four accepted extractions.

The fixed reference yields **87/195** checks: nine missing, 72 blocked by endpoint
binding, one unassessed feature and 26 graph-unavailable checks. These categories
do not represent 108 separate semantic errors. The total includes 20 mechanically
supplied template nodes and 16 template edges. The altered prospective reference
and failed stages prevent treating the count as a controlled improvement or decline
in model semantic accuracy.

Of **20 predefined scopes**, one PDF filepath scope received the expected decisive
answer; **19 remain unassessed**. Zero pass the complete frozen dependencies and
source review, and **zero of six cases pass full acceptance**. The correctly matched
answer concerns a requirement absent from the prompt, not a missing software protection.
The eight generated PDF scopes and eight withheld password scopes are separate
diagnostic counts; neither replaces the predefined 20-scope denominator.

PDF now preserves the storage-before-download relation and distinguishes a filepath
stored as SQL data from a filepath used to locate a download. Its 25 fixed checks
pass, but source review remains necessary: an extra direct upload-destination role
is uncertain, two empty-subject scopes are justified by implicitly substituting the
filepath as subject, and impact lists omit later consumers. The full saved-graph
audit records 94 supported assertions, 14 unsupported and three uncertain; fixed
template assertions are included and identified separately. All returned roles,
coverage/impact rows and notes are also retained in the development source review.
The current graph-assertion helper does not itself inventory this metadata, so its
output alone must not be presented as a complete contract review.

## What this round changes in the diagnosis

The smaller interface repairs a concrete structural defect but does not make the
first source inventory reliable. Temperature has correct extraction-result roles,
yet the query is labeled `operation.return_rows`; the omitted request and endpoint
are substituted with the maximum-temperature object. The length case preserves
the query and both independent requirements, but labels `input x` as an operation,
leaving no object for the required bindings.

Two saved responses reveal a further output-delivery problem:

- The conditional case's notes explicitly recognize the correct parameter-binding
  concept and safe-mode condition, then promise to add them. Neither appears in
  the already submitted node list. Five concatenation proposals repeat the same
  source requirement; they are not five recovered atomic requirements.
- The two-operation response begins with nine draft nodes, including invented
  extraction, concatenation and prohibition. Inside a coverage rationale it later
  recognizes these errors, repeatedly promises corrected JSON and never finishes
  it. The captured envelope reports 3,878 input tokens and **8,192 output tokens**;
  its 32,143-character content contains 82 occurrences of “Final JSON”. The partial
  node prefix was inspected as failed draft evidence and was never compiled.

Both responses also confuse unspecified implementation with missing source meaning:
the lack of an instruction to bind query B is treated as incomplete task coverage,
even though absence of an explicit requirement can be resolved without knowing how
future code will implement the query. Password similarly withholds scopes because
an implied connection/resource node is missing. The unchanged rules preserve these
unknowns; this does not endorse the model's reason for declaring incompleteness.

These observations do not establish whether general model capability, constrained
decoding, output order or interactions among the instructions are the main cause.
They do establish that recognizing a correction in prose does not ensure its
submission in the structured facts. Adding more TSG fields or repeating a full
pipeline prompt edit would not isolate that cause. The next research decision
should be a small, prospectively fixed **first-inventory comparison of semantic
recognition and structured-output delivery**, under matched sources, model and
budget, while explicitly separating source omission from unspecified implementation.
That comparison has not been run or authorized by this round's unused call ceiling.

## Closure and reproduction

All 11 calls replayed offline through the unchanged provider adapter and extraction
implementation. Exact requests, response schemas, graph/contract records, errors and
partial binding/scope records match. Successful stop envelopes were synthesized
around retained content; the original length-failure envelope was replayed exactly.
No credential or network was used in replay. Original token usage is available for
the failure only, not for all successful calls.

The run received one **CNY 1.10 conservative budget debit**, leaving **CNY 49.066682**.
This is the frozen CNY 0.10-per-call accounting rule, not an invoice. No retry or
additional call followed the source review. The round is closed and the extractor
remains unqualified; the active method is still `SPECIFIED_DRAFT`.

The execution source archive is
`a8c699e8e8dda2ab291f812fd25994f214f4dd9262155874bf01475ea74fea4d`;
the result archive is
`0b8713a7f693112fce042e08d312063938e0b76600181f6c8331ec81150f099a`;
the extracted result bundle is
`262c3761bafcf635bcd8bd8e4e1f5236b1961148f65ecfe77bd78d823c061628`.
The exact single launch command is retained in `single-role-check/launch.sh` and
the validation report. Use the captured source and configuration for reproduction;
frozen earlier rounds retain their own implementations and verdicts.

Read the [closed summary](../../data/method/open-tsg-scope-development-v1/single-role-check/analysis/summary.json),
[per-case source review](../../data/method/open-tsg-scope-development-v1/single-role-check/analysis/source-review.json)
and [exact replay record](../../data/method/open-tsg-scope-development-v1/single-role-check/analysis/content-replay.json)
for the source-to-result calculation and its limits. The analysis bundle digest is
`1ef19bff9fd0a1d10cec6bc34837d6edb346cfccd0adb59f0967b4d490c0c57a`.
