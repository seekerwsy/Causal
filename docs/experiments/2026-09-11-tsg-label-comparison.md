# Single annotation and routing-label development comparison

The owner removed dual annotation and requested a small comparison of whether
external CWE and task-family labels affect source semantics. The active extractor
now makes one call per task, validates source evidence, closes relation endpoints,
and deterministically compiles the contract. It withholds external task IDs,
routing labels, query IDs and context-query assembly logic from model requests.
No consensus or second-model fallback remains in the active contract path.

The active candidate is `data/method/prompt-contract-annotator-qwen37flash-v1.json`
with `data/method/prompts/prompt-contract-annotator-v1.txt` and
`data/method/prompt-tsg-catalog-source-contract-v2.json`. The existing semantic
boundary revisions and known-false-before-unknown query rule are shared by both
comparison conditions. The model remains `qwen3.7-flash-2026-07-15`, temperature
0, seed 81370, 4,096 maximum output tokens and one attempt. Raw rationale stays
in the response archive; invalid presence evidence becomes unresolved.

## Frozen small comparison

Inputs are in `data/method/tsg-label-development-v1`. The plan fixes all seven
prior mismatches plus the first three previously matched positive references in
the frozen gold order: archive extraction, bounded path access and Requests TLS.
The remaining seven cover simulated random logs, Flask downloading, Django reset
tokens, SQL message insertion, generic SQLite deletion, directory listing and an
arbitrary SQL-query interface. These are ten already exposed development tasks.
Their previous reference labels are copied unchanged; no protected tasks are opened.

Each task has two single-annotation conditions. `labelled` adds `cwe_id` and
`task_family`; `hidden` omits just those fields. The source prompt, semantic and
relation definitions, schema, compiler, reference labels and all model parameters
are identical within each pair. Calls are adjacent and alternate which condition
comes first. No retries, replacement tasks or tuning after responses are allowed.
The plan contains exactly 20 provider calls, with a conservative upper cost of
CNY 0.196620 under the existing CNY 100 authorization. Prior cumulative upper-bound
spending is CNY 2.236698, leaving at least CNY 97.763302 before this comparison.

The comparison records exact context/realization matches, false-positive presence,
missed positive references, unresolved contexts, invalid contracts and changes in
the individual semantic decisions. This selected development set is not a new
qualification population and has no pass/fail qualification threshold.

Candidate scope and labels embedded in source paths or function names remain
unchanged. This tests the additional explicit metadata fields, not full topic
blinding. One observation per condition cannot identify the cause of every
discrepancy. Changes from the old dual-annotation run also include earlier semantic
and compiler repairs, so that historical difference is not a label-only effect.

## Reproduction and current execution status

The commands below reproduce the closed-vocabulary revision recorded in this report using its
captured source snapshot. They are historical commands; the current open-graph interface is
documented in the [reviewer guide](../reviewer-guide.md) and no longer takes a legacy registry:

```text
prompt-mechanism-study representation extract-contracts TASKS CATALOG EVALUATOR ANNOTATOR_PROMPT SELECTION OUTPUT
prompt-mechanism-study qualification prompt-contract TASKS EXTRACTION CATALOG REGISTRY GOLD EVALUATOR ANNOTATOR_PROMPT OUTPUT
```

The single-annotation protocol identity is
`task_context_contract_v5_evidence_bound_single_annotation`. Old dual-annotation
gold and results retain their original identities; the new verifier rejects them
as inputs to the current qualification path. Fresh independent qualification must
be separately frozen. This closed-vocabulary result does not qualify the active open graph.
No formal extraction or claim-bearing result exists.

The prepared execution archive is
`.tmp/tsg-label-development-v1-payload.tar.gz`, SHA-256
`71c642e129ec056337d28b968741b62a1fd1ce09ab0997ac3074d05a2e54aa69`.
It contains 18 execution input files plus their exact-hash manifest, no credentials.
Its thin execution snippet calls the active single-annotation function; only the
labelled comparison callback adds the two prospectively recorded fields. It
preserves every attempt and raw response, including parse failures, stops on
provider failure, and refuses an existing output directory with contents.

Server input target:
`/home/wsy/work/prompt-mechanism-study/inputs/tsg-label-development-v1`.
Server output target:
`/home/wsy/work/prompt-mechanism-study/results/tsg-label-development-v1`.
Execution uses the existing Python 3.12.11 image
`sha256:688a685f6a1fa9250d7c6cee916889cbca364e4b027520110e0fce80c64a13e0`.
Only selected task prompts and annotation instructions/definitions, plus optional
labels, are sent to `dashscope.aliyuncs.com`; repository implementation and
credential values are not request content. Credentials remain owner-only on the
server in the existing study workspace.

**Executed after explicit owner approval of this archive, server and API scope.**
The initial SCP upload was rejected by automatic approval review; the owner then
approved the concrete transfer to `wsy@121.48.163.133:9086` and twenty requests to
`dashscope.aliyuncs.com` under the CNY 0.20 cap. The subsequent upload succeeded.
The archive hash, all 18 input hashes and fixed Docker image matched. A remote
Python 3.12.11 `--check` run verified the schedule without provider calls before
execution. Exactly twenty calls completed once, with no retries or replacements.

Before execution, a fresh Python 3.12.13 environment installed the project and
pytest from local wheels. All 28 focused contract/parser/query/replay and
representation checks passed; both single-annotator CLI signatures were verified.
The original failed-run bundle and its frozen gold/catalog hashes remain unchanged.
The existing seven-stage smoke and independent effect-result verification are
unaffected and their prior checks are reused.

Local clean verification command:

```text
.tmp/tsg-single-clean-env/Scripts/python.exe -m pytest tests/test_prompt_contract.py tests/test_representation.py -m "not extended" -q -p no:cacheprovider --basetemp=NEW_TEST_OUTPUT
```

## Executed result and interpretation

| Development diagnostic | Labelled | Hidden |
|---|---:|---:|
| Planned / completed calls | 10 / 10 | 10 / 10 |
| Exact context and realization matches | 7/10 | 7/10 |
| False-positive present contexts | 0 | 0 |
| Missed expected-present realizations | 2/4 | 2/4 |
| Unresolved contexts | 1 | 1 |
| Invalid contracts | 0 | 0 |

All ten paired task-level context/realization decisions agree. The raw state
assignments for all 67 semantic items and all 13 relation items also agree between
conditions. Evidence wording and audit explanations differ: all twenty response
hashes are distinct. On the generic SQL task, hidden evidence for fixed identifiers
contains an invalid ellipsis and is demoted to unresolved, while labelled evidence
validates. Both conditions nevertheless have an unresolved SQL sink due to another
invalid ellipsis, so the final context remains unresolved in both.

| Task suffix | Frozen reference | Labelled / hidden | Observed reason |
|---|---|---|---|
| `deb850…` archive extraction | present | present / present | Matched. |
| `c6e434…` avatar checksum | present | absent / absent | Sources, file access and base all identified, but `flows_to` marked absent because the model wrongly demands a flow constraint or validation mechanism. |
| `e86341…` Requests HTTPS | present | absent / absent | The model demands explicit TLS setup and certificate-validation requirements to admit the TLS operation and peer. |
| `17d2d9…` simulated random logs | absent | absent / absent | Matched; no invalid long-rationale contract. |
| `65fbeb…` Flask URL download | absent or unresolved | absent / absent | Matched; no inferred required subprocess. |
| `bc06aa…` Django reset token | absent | absent / absent | Matched; internally generated tokens not admitted as external credentials. |
| `521696…` message database insertion | present | present / present | Matched with evidence for the fixed operation. |
| `eb8765…` generic SQLite delete/fetch | absent | unresolved / unresolved | Fixed-table interpretation remains unsupported/ambiguous; both SQL-sink quotes insert ellipses absent from the original. |
| `57d2f4…` directory listing | absent | absent / absent | Matched; no inferred required subprocess. |
| `4f1627…` arbitrary SQL query | absent | absent / absent | Matched; unrestricted query interface excluded from the offered fixed/finite contexts. |

The avatar failure occurs at relation interpretation, not node recognition: its
raw rationale says the prompt does not explicitly require a flow constraint or
validation mechanism. `flows_to` is supplied as a relation identifier/triple;
it should describe the required data use, independently of a safety guard.

The TLS failure also exposes a catalog-definition problem. The model-visible
`source.external_tls_peer` guidance says that the task connects to a server or
HTTPS URL whose certificate identity must be validated. The model interprets
this as requiring an explicit certificate-validation instruction. The TLS sink
has only generic entailment guidance. Operation/peer context and the separate
certificate-validation requirement need clearer definitions. These are concrete
development findings, not a reason to alter this frozen run or its references.

No overall improvement from withholding the two metadata fields was observed in
this selected ten-task comparison. This does not establish equivalence or prove
labels harmless outside these tasks. The previous over-inference failures now
match in both conditions, while two previously matched positive anchors regress;
the prior semantic/compiler revisions, changed request layout and single-call
policy are shared changes, so their effects cannot be isolated here.

The active candidate remains single annotation with external labels withheld:
the supplied labels are unnecessary for deciding source requirements, but this
run supplies no accuracy-gain claim for their removal. Next development should
address the relation definition, TLS context/requirement separation and exact SQL
evidence. No additional run or post-result prompt tuning was performed.

## Result provenance and budget

Local complete outputs: `data/method/tsg-label-development-v1/results`.
Source archive: `data/method/tsg-label-development-v1/source.tar.gz`, retaining
the exact approved payload hash above. Server inputs/results remain in the
documented study workspace; the prior functional-pilot outputs are preserved.

Summary bundle SHA-256:
`09d016dac09365298858e1d56ad491987e430386a9e8111517dd8a158d6f4ea4`.
`verification/verification.json` and `verification/paired-cases.json` verify
the frozen task/reference population, twenty request/response identities,
within-pair label-only differences and contract/graph replay. Context predicates,
selected realizations, match counts and summary metrics were independently
recomputed from the decision tables without calling the production query or
binding functions. They agree with the stored report. The provider sends the
entire recorded request as its user-message content, including the two labels
only in the labelled condition.

The existing ledger records twenty actual attempts at the prior conservative
per-call upper ceiling: **CNY 0.196620** for this comparison, cumulative
**CNY 2.433318**, with at least **CNY 97.566682** remaining. These are conservative
accounting amounts, not provider invoice usage. No protected qualification input,
formal task assignment, Discovery, randomized code generation or scientific-effect
claim was produced. This 7/10 development result is not successful qualification.
