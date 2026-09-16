# Legacy artifact boundary

This directory records the interpretation and recovery boundary for artifacts
that predate the active schema-3 method, plus superseded source preparations.

## Immutable retained artifacts

The following tracked bundles remain historical evidence and must not be
rewritten, migrated in place, or cited as schema-3 results:

- `data/formal/results/factorial-sql-confirm-qwen35-v3`
- `data/formal/results/factorial-sql-scaffold-repair-qwen35-v1`
- `data/method/archive/legacy-v5`

Their matching historical configurations are under
`configs/archive/schema1`. Result notes are under
`docs/archive/experiments`, and superseded migration/readiness material is recoverable from Git history. These paths are outside the default schema-3
reviewer path.

Generic exact-byte bundle verification can still be performed with
`prompt-mechanism-study artifact verify BUNDLE`. Scientific replay of a historical
schema requires its historical source environment.

## Source recovery

The last repository checkpoint before removal of the live schema-1/2
selector, successor, factorial and intervention implementations is Git commit
`674391f`. Recover a historical verifier or runner from that commit in a
separate checkout. Do not copy it into the active package or import it from the
schema-3 CLI.

The September 15 test cleanup removed 21 checks of closed Prompt TSG experiment
plans, historical budget totals and frozen-file snapshots from
`tests/test_datasets.py`, `tests/test_prompt_contract.py` and
`tests/test_prompt_tsg.py`. They are recoverable at Git commit
`3ac35620710223ef98cb35acae10cefbe72d4980`; use that historical checkout when
auditing those attempts. This removes development-history checks from the
current suite, not the frozen inputs, ledgers or results. Active semantic,
budget-planning and independent-verifier tests remain in the maintained suite.

Git history, this boundary document, and the immutable bundles are the
preservation mechanism. The active code and default tests intentionally contain
no parallel legacy execution path.

## Superseded source preparation

The immutable `data/dataset-curation/research-source-use-v1` package records the
initial full-source preparation before the four ordered review cohorts. It is
retained only as provenance. The current preparation, configuration references
and default released-data checks use `research-source-use-v2`; see the
[dataset contract](../research-dataset-spec.md). Neither preparation is a formal
experiment or a source of effect claims.

## Superseded Prompt TSG extraction

The direct-graph proposer/reviewer implementation in `prompt_tsg_extract.py` is
archival only; its `representation extract-tsg` command has been removed. The
active entry is `representation extract-contracts`, using one evidence-bound
annotation. The frozen source-contract-v1 dual-annotation failure remains under
`data/method/prompt-contract-source-contract-v1-evidence`, including its original
`source.tar.gz`; replay that run only with that archive, not the new single
annotator. Old gold is not accepted by the current contract qualification path.

The same September 15 cleanup also removed 14 test functions (17 parameterized
cases) for that archival direct-graph proposer/reviewer, its path-authority
override, old catalogue wording and historical qualification scores. They are
recoverable in `tests/test_prompt_tsg.py` at commit
`3ac35620710223ef98cb35acae10cefbe72d4980`. The later minimum-suite cleanup
retains shared query-state coverage there and tests current evidence binding
through the active source-inventory path. The maintained tests no longer import
the archival extractor. The [current test guide](../../tests/README.md) is the
single testing policy; historical execution commands use their historical tree.
