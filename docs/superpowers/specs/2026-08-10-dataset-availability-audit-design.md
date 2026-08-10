# Dataset Availability Audit Design

**Date:** 2026-08-10  
**Status:** Approved scope awaiting implementation  
**Repository:** `D:\\MyCode\\Causal`  
**Source snapshot repository:** `D:\\MyCode\\SecAware-Causal`

## 1. Objective

Complete the paper-data availability audit before any model generation,
extractor call, intervention execution, or GPU workload. The audit determines
which task sources and CWE/security scopes can support the approved
Prompt-only discovery and held-out randomized-confirmation design, and records
why every other source is currently limited to calibration, secondary
analysis, external replication, or unresolved status.

This stage produces objective inventory and deterministic triage. It does not
author missing functional contracts, invoke an LLM, perform human adjudication,
freeze the final paper sample, or claim that an automatically screened prompt
has received a security-neutrality attestation.

## 2. Fixed Scope

### 2.1 Legacy inputs

Copy the following existing normalized files byte-for-byte from
`D:\\MyCode\\SecAware-Causal\\datasets\\benchmarks` into an immutable dated
snapshot in the current project:

1. `apps.jsonl`
2. `classeval.jsonl`
3. `cweval.jsonl`
4. `cweval_python.jsonl`
5. `cyberseceval_discover_adv.jsonl`
6. `cyberseceval_secure_code.jsonl`
7. `humaneval.jsonl`
8. `humaneval_plus.jsonl`
9. `mbpp.jsonl`
10. `sallm.jsonl`
11. `seccodebench_python.jsonl`
12. `securityeval.jsonl`

The source files remain untouched. Hugging Face caches, nested Git
repositories, old raw archives, virtual environments, and historical run
directories are not copied.

### 2.2 CyberSecEval updated source

Acquire the official PurpleLlama secure-code-generation
`instruct-v2.json` from a resolved upstream Git commit rather than an
unversioned moving URL. Persist the repository URL, resolved commit, source
path, retrieval timestamp, byte length, and SHA-256. A third-party mirror may
be used only to diagnose availability; it cannot become the authoritative
source without a separately recorded decision.

The existing local CyberSecEval JSONL files remain labeled
`legacy-unversioned` until overlap analysis establishes their relationship to
the pinned upstream file. They are not silently renamed as v2.

## 3. Storage and Immutability

Use these boundaries:

```text
datasets/
  snapshots/
    legacy-2026-08-10/
      *.jsonl
  sources/
    cyberseceval/
      <resolved-commit>/
        instruct-v2.json
  manifests/
    audit-v1/
      migration-manifest.json
      source-lock.json

runs/
  dataset-audit/
    <run-id>/
      config.json
      commands.jsonl
      environment.json
      run.log.jsonl
      file-inventory.jsonl
      record-audit.jsonl
      duplicate-groups.jsonl
      cluster-summary.jsonl
      split-simulations.jsonl
      dataset-role-summary.jsonl
      failures.jsonl
      report.json
      report.md
```

`run-id` contains a UTC timestamp and configuration digest. Existing paths are
never overwritten. The audit writes to a staging directory, validates the
complete output set, then commits the run atomically. An incomplete run remains
typed failure evidence and cannot replace a previous successful run.

## 4. Reuse Boundary

Before implementing new import or triage logic, inspect the existing
`secaware/dataset/catalog.py`, `importer.py`, `build.py`, and `triage.py` plus
their tests in `D:\\MyCode\\SecAware-Causal`. Reuse compatible pure parsing,
canonicalization, digest, and validation behavior. Do not copy the old package
wholesale: every reused unit must be adapted to the current `src/secaware`
layout, current schemas, Prompt-only causal boundaries, and transactional
artifact contracts.

The implementation report records, for each reused or rejected old unit, its
source path, adopted behavior, adaptations, and rejection reason.

## 5. Audit Model

### 5.1 File integrity

For every input, record and validate:

- absolute source and destination paths;
- source and destination SHA-256 equality for migrated snapshots;
- byte size, line count, and valid-record count;
- UTF-8 and JSONL parse status;
- union of top-level fields and field-presence counts;
- duplicate source IDs and conflicting duplicate records;
- source/version/license metadata availability.

A malformed record is preserved in the immutable input and emitted to
`failures.jsonl` with its file and line coordinate. It is never silently
skipped or rewritten.

### 5.2 CWE/security-scope evidence

Each normalized audit row carries a value and provenance state:

```text
CweEvidenceState =
  EXPLICIT_FIELD
  SOURCE_ID_PARSE
  SOURCE_MAPPING
  CONFLICTING
  UNRESOLVED
```

Explicit source fields have priority. Parsing identifiers such as
`CWE-502` from a source record ID is allowed only when the exact matched text
is retained. Filenames or ordinal-looking tokens are not assumed to be CWE
labels without a reviewed source mapping. Conflicts remain visible.

### 5.3 Task clustering and duplicates

The audit computes separately:

- exact byte-level prompt digest;
- normalized-text prompt digest;
- source-native task coordinate;
- repository/file coordinate when supplied;
- cross-dataset exact duplicates;
- variant-family relationships when explicitly supported by source metadata.

Exact prompt duplicates share a duplicate group. They do not automatically
share a semantic task cluster when their source metadata conflicts. Ambiguous
relations receive `cluster_state=UNRESOLVED`; they are not counted as multiple
independent tasks in conservative split simulations.

CyberSecEval comparison reports exact and normalized prompt overlap, source
record overlap, CWE/language overlap, records removed by v2, records newly
present in v2, and the relationship between the existing 150- and 260-record
files.

### 5.4 Security-neutrality pre-screen

The deterministic pre-screen emits only:

```text
NeutralityPrescreenState =
  OBVIOUS_CONFLICT
  CANDIDATE_NEUTRAL
  UNRESOLVED
```

`OBVIOUS_CONFLICT` covers directly observable violations such as explicitly
asking to create insecure behavior, declaring that supplied code contains a
security vulnerability, revealing an expected security label, or including a
positive target requirement where a neutral baseline is required.

`CANDIDATE_NEUTRAL` means no configured obvious conflict was detected. It is
not an attestation and cannot satisfy the final pre-randomization
`SecurityNeutralPromptInvariant`. Uncertain context, mixed instructions, and
unsupported formats are `UNRESOLVED`. Every decision records the matched
evidence span and rule version; there is no extensible runtime rule registry.

### 5.5 Functional-contract availability

Use these states:

```text
FunctionalContractState =
  EXECUTABLE_VALIDATED
  PRESENT_UNVALIDATED
  REFERENCE_ONLY
  ABSENT
  CONFLICTING
  UNRESOLVED
```

Field names such as `test`, `test_list`, `input_output`, reference solution,
or remote verifier metadata are evidence inputs, not automatic proof of an
executable contract. Validation first runs on three to five representative
records per compatible dataset in an isolated environment. Only after this
smoke gate passes may validation expand to the remaining existing contracts.
No missing contract is authored in this stage.

### 5.6 Split simulations

Simulate, but do not freeze, deterministic task-cluster splits for:

- 50% discover / 50% confirm;
- 60% discover / 40% confirm; and
- 70% discover / 30% confirm.

Each simulation is stratified where possible by dataset source, language, and
CWE/security scope, uses a recorded seed and algorithm version, and assigns an
entire conservative task cluster to one side. Report per-side independent
cluster counts, unresolved exclusions, and whether each side reaches the
configured minimum. The current minimum of 20 independent tasks is reported
as a pipeline eligibility floor, not as a statistical-power justification.

## 6. Dataset-Role Classification

The audit may assign multiple evidence-backed candidate roles:

```text
PAPER_PRIMARY_CANDIDATE
SECURITY_ONLY_SECONDARY_CANDIDATE
FUNCTIONAL_CALIBRATION
ORACLE_CALIBRATION
EXTRACTOR_OR_TSG_EVALUATION
EXTERNAL_REPLICATION_CANDIDATE
PENDING_CONTRACT_OR_ADJUDICATION
UNUSABLE_UNDER_CURRENT_SCOPE
```

`PAPER_PRIMARY_CANDIDATE` requires supported language and scope, a usable
functional contract, no deterministic neutrality conflict, conservative task
clustering, and sufficient counts under at least one recorded split
simulation. Because this stage performs no final neutrality adjudication, the
classification remains a candidate status and cannot enter a paper run by
itself.

The audit must not label a dataset “discovery-only” merely because it lacks a
functional contract: the approved primary discovery outcome is also
secure-and-functional. Security-only use must be explicitly secondary and
pre-registered later.

## 7. Implementation Components

The later implementation plan will separate:

1. immutable snapshot migration and source locking;
2. dataset adapters that expose source facts without silently normalizing
   uncertainty;
3. deterministic record audit and evidence-state construction;
4. duplicate and conservative task-cluster analysis;
5. functional-contract smoke validation;
6. split simulation and role classification; and
7. transactional artifact writing and human-readable report generation.

Each component has a bounded input/output schema and can be tested without
network, GPU, or LLM access. Network access is confined to the explicit
CyberSecEval acquisition step.

## 8. Failure Handling

- Missing source file, destination hash mismatch, or upstream digest mismatch
  aborts publication of the run.
- Individual malformed or unresolved records remain typed rows and failures;
  they are not silently discarded.
- Network failure leaves the legacy audit available but marks the combined
  CyberSecEval-v2 audit incomplete; no false v2 conclusion is published.
- A functional-test crash records dataset, task, command, exit status, timeout,
  stdout/stderr digests, and bounded excerpts. It does not convert the record
  to functional failure for a generated model output.
- Re-running after repair uses a new run ID and records the parent failed run;
  old artifacts remain unchanged.

## 9. Validation Strategy

Validation expands in gates:

1. unit tests for digesting, JSONL validation, explicit CWE evidence,
   conservative clustering, pre-screen states, functional states, split
   determinism, and role rules;
2. three-to-five-record fixtures per dataset adapter;
3. one full small dataset and the CyberSecEval 150/260 overlap check;
4. full twelve-file legacy inventory;
5. pinned CyberSecEval-v2 acquisition and comparison; and
6. deterministic rerun comparison of all manifests and summaries.

Every command, configuration, environment fact, log, intermediate artifact,
failure, and final report is retained under the run directory. Progress
reports give total, completed, running, failed, unresolved, and pending counts,
processing rate, and estimated remaining time.

## 10. Explicit Non-Goals

This stage does not:

- call Alibaba Bailian or any other model API;
- connect to or consume GPU resources on the model server;
- construct Prompt TSGs or run FCI/JCI/RFCI;
- generate intervention arms or code;
- author missing tests, prompts, counterparts, or attestations;
- make final paper dataset, CWE, sample-size, or model selections; or
- modify the approved RQs, ITT estimand, evidence levels, or causal boundaries.

## 11. Acceptance Criteria

The stage is complete only when:

1. all twelve legacy JSONL files exist in the dated snapshot and match their
   source SHA-256 values;
2. the official CyberSecEval `instruct-v2.json` is locked to a recorded commit
   and digest, or a typed acquisition failure prevents the combined report
   from claiming completion;
3. every parseable record has a deterministic audit row and every malformed
   record has a failure row;
4. CWE evidence, duplicates, conservative task clusters, neutrality
   pre-screen, functional-contract state, and candidate role are reported with
   provenance;
5. all three split simulations report independent counts by source, language,
   and CWE/security scope;
6. the 150/260 legacy CyberSecEval relationship and their relationship to v2
   are explicitly reported;
7. small-case gates pass before full expansion;
8. a second identical run produces matching content digests for deterministic
   outputs; and
9. no source data, historical result, untracked `paper/tmp/`, or untracked
   `uv.lock` is modified or removed.
