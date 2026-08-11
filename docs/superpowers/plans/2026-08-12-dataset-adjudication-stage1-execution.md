# Dataset Adjudication Stage 1A Execution Log

## Frozen environment

- Machine: local Windows workstation
- Workspace: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/dataset-adjudication-stage1`
- Python: `D:\MyCode\Causal\.venv\Scripts\python.exe`
- Fixed runtime: Python 3.12
- Source audit: `runs/dataset-audit/stage0-combined-20260810-08`
- Source stable digest:
  `2d5c16c613988dffd7f9a9299bcb7a43ef8fab6cc91ad45ae0b8e99c11cc38a8`

## Immutable runs

### Packet run

- Run: `runs/dataset-adjudication/stage1a-packets-20260812-01`
- Status: `PACKETS_READY`
- Neutrality packets: 117
- Cluster-relation packets: 55
- Total packets: 172
- Pilot: 20 neutrality and 20 cluster-relation packets
- Source-manifest digest:
  `9136c486dbea05b73c1bd44ea96682311ad42d846bf50bc70fb00c204b068d4f`

### Superseded pilot reconciliation

- Run: `runs/dataset-adjudication/stage1a-pilot-reconciliation-20260812-01`
- Preserved status: `AWAITING_HUMAN_AUDIT`
- Reason superseded: two evidence strings were faithful abbreviations rather
  than exact substrings of the blinded packet text.
- The run and original decision input were not modified or deleted.

### Current pilot reconciliation

- Decision input:
  `runs/dataset-adjudication-inputs/stage1a-pilot-codex-20260812-02`
- Run: `runs/dataset-adjudication/stage1a-pilot-reconciliation-20260812-02`
- Status: `AWAITING_HUMAN_AUDIT`
- Codex decisions: 40 pass A and 40 pass B
- Repeat-consistent labels: 40/40 (1.000)
- Low-confidence decisions: 0
- Pass disagreements: 0
- Human review queue: 19
  - neutrality: 8
  - cluster relation: 11
  - reason: deterministic stratified audit for all 19
- Human fields auto-filled: 0

The 19-item queue is larger than an unstratified 20% sample because the frozen
rule selects at least one high-confidence agreement from every non-empty
`(dimension, source_stratum)` cell. This is expected and must not be reduced
after observing the queue.

## Pilot label distribution

Both Codex passes produced the same counts:

- Neutrality:
  - `SECURITY_FEATURE_PRESENT`: 13
  - `INELIGIBLE_SECURITY_CONSTRAINT`: 4
  - `NON_SECURITY_USAGE`: 3
- Cluster relation:
  - `SAME_TASK_VARIANT`: 17
  - `SAME_TASK`: 2
  - `DISTINCT_TASK`: 1

This is repeat consistency from one Codex workflow, not human inter-rater
agreement and not independent-model agreement.

## Validation

- Targeted reconciliation and CLI tests: 8 passed.
- Adjudication plus adjacent clustering/schema/packaging tests: 52 passed.
- Python bytecode compilation: passed.
- `git diff --check`: passed before the final formatting-only test edit.
- Ruff: unavailable in the fixed virtual environment; no dependency was
  installed. The changed files were checked separately against the configured
  100-character line width.
- Full repository suite: not run, consistent with the approved accelerated
  validation plan because the changed boundary is confined to dataset
  adjudication and its CLI registration.

## Failure and repair ledger

1. A read-only packet inspection first timed out under a 30-second bound in
   the earlier reconstruction; the same bounded operation completed with a
   120-second limit.
2. Two read-only commands failed because the Windows sandbox could not spawn
   a child process (`CreateProcessAsUserW`, access denied). They were rerun
   read-only with approved escalation.
3. Initial red tests failed on missing pilot-subset and reconciliation-run
   symbols, confirming the intended test-first boundary.
4. The new run test initially omitted `schema_version`; the fixture was fixed.
5. The fixture initially produced no ambiguous cluster edge; it was replaced
   with the existing near-duplicate clustering fixture.
6. CLI registration was initially inserted across the old function boundary;
   immediate source inspection caught it before real execution, and the two
   command paths were separated. CLI tests then passed.
7. Exact-quote inspection found 2/80 non-verbatim evidence strings. An exact
   visible-quote gate was added, the original run was retained, corrections
   were recorded in a two-entry immutable correction file, and a new `-02`
   decision input and reconciliation run were published.
8. Ruff was not present in the fixed environment. No unregistered dependency
   installation or environment drift was introduced.

## Current progress and remaining work

- Completed: 172/172 blinded packet units; 80/80 pilot decision records;
  current pilot reconciliation and review template.
- Running: 0.
- Failed and unrepaired: 0.
- Awaiting human audit: 19 pilot entries.
- Pending Codex adjudication: 132 non-pilot units per pass, or 264 decision
  records.
- Pending after full adjudication: full deterministic human-review queue,
  human decisions, eligibility overlay, then the independent functional
  contract recovery gate.

No dataset is yet declared eligible for the primary secure-and-functional
experiment. Stage 1A resolves neutrality and cluster independence only.
