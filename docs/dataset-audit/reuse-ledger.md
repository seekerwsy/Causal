# Dataset audit reuse ledger

This ledger freezes the reuse boundary for Stage 0. It was established by
inspecting the legacy implementation under `D:\MyCode\SecAware-Causal` and the
current strict I/O infrastructure before implementation began.

| Legacy/current component | Decision | Reason and adaptation boundary |
|---|---|---|
| Legacy `secaware/dataset/catalog.py` | Consult and adapt | Reuse dataset identifiers and source-field knowledge, but express them as the frozen audit catalog in the current `src/secaware` package. |
| Legacy `secaware/dataset/importer.py` | Consult and adapt | Reuse prompt/ID field knowledge. Do not reuse its Hugging Face or general network loading because Stage 0 uses pinned snapshots and one explicit official v2 source. |
| Legacy `secaware/dataset/build.py` | Consult and adapt | Reuse the prompt-fingerprint and disjoint-grouping ideas. Replace row-level splitting with conservative task-cluster splitting and preserve duplicates instead of dropping them. |
| Legacy `secaware/dataset/triage.py` | Reject direct reuse | It invokes code generation and security analysis, which are explicitly outside this audit. |
| Current `src/secaware/io/jsonl.py` | Reuse directly | It provides strict bounded JSONL parsing and canonical serialization. |
| Current `src/secaware/io/transaction.py` | Reuse directly | It provides fail-closed transactional artifact publication and recovery. |
| Current `src/secaware/io/run_store.py` | Reuse selectively | Its run/provenance conventions are retained where compatible; dataset audit runs remain immutable and separate from causal pipeline stage state. |

No legacy module is copied wholesale. Each adapted behavior requires a new
current-repository test and must preserve source coordinates and evidence.
