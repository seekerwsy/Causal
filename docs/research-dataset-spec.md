# Prospective Research Dataset Specification

## Status and scope

This document defines the prospective dataset design for the single active
Prompt Mechanism Study path. The 240-task-unit Python population remains a
coverage target, not a claim of current readiness. The previously reported
1,222 quality-qualified tasks, 563 Python tasks, and 166 technically ready
Python tasks belong to the frozen pre-successor v4 baseline; they are planning
history, not the current quality authority. The active successor retains all
2,165 task units and requires the unanchored dual-subagent review, blind third
adjudication, and repaired-subset re-review defined in
[the contract content cleaning protocol](contract-content-cleaning.md). Its
final quality and readiness counts remain unset until that data foundation
passes the independent verifier.
The 240-task Python measurement gate therefore remains closed. Section 8 records a smaller,
outcome-blind 60-task-unit sample as a historical population-feasibility and
power-planning canary; it is not a frozen successor assignment manifest or
evidence that an intervention effect exists.

Generator identities, assignment records, and the pilot split remain unfrozen.
No generated-code outcome, model score, or historical per-task result may
influence admission or sampling.

## 1. Statistical units, terminology, and study layers

The highest independent and resampling unit is the **task unit**, identified as
`task_unit_id` in prospective protocols. A task unit is the cleaned dataset row
seen by the experiment, but it may summarize several equivalent source records.
Rows, prompt rewrites, source mutations, framework variants, language
translations, request slots, and multiple hypotheses over the same semantic
task are dependent descendants of that unit.

The curation implementation groups source records into conservative semantic
clusters before choosing a representative. Frozen artifacts therefore retain
physical names such as `cluster_id` and `semantic_task_cluster_id`; these are
legacy task-unit coordinates, not an additional paper-facing statistical
concept. This document uses **task unit** for populations, sampling, assignment,
resampling, and effect estimation, and reserves **cluster** for the internal
deduplication group or an immutable legacy field/file name.

The prospective dataset has three inferentially separate confirmation layers:

| Layer | Target task units | Role | Primary pooling rule |
| --- | ---: | --- | --- |
| Python confirmatory core | 240 | primary assigned-arm ITT | may pool only under the frozen stratified estimator |
| C/C++ memory-safety replication | 28 | cross-language replication | report separately |
| backend-application replication | 28 | end-to-end functional/exploit replication | report separately |

The planned evaluation population therefore contains 296 task units,
but **296 is not one analysis denominator**. The two replication layers cannot
be silently pooled with the Python core because their languages, task
granularity, functional contracts, and security Oracles differ.

Two additional outcome-excluded resources are planned:

- 24 task-unit-disjoint tasks for intervention-executor development; and
- 24 independent gold programs for functional-Judge and security-Oracle
  calibration.

Neither resource contributes to an intervention-effect estimate. Historical
canaries, failed runs, Judge-tuning cases, and previously inspected
confirmatory outcomes are also excluded.

The observational discovery population is a fourth, non-confirmatory resource.
It retains natural, unmanipulated Prompt variation, including explicit,
implicit, and absent security requirements. It is task-unit-disjoint from every
confirmation and replication layer. Discovery outcomes may rank hypotheses but
never contribute to their held-out randomized effect estimates.

## 2. Confirmatory security families

The Python core targets four mechanism families with 60 task units per
family. Leaf-CWE quotas are prospective balancing targets, not separate
confirmatory estimands.

### 2.1 Injection and interpreter boundaries

Target 60 task units, approximately 15 per leaf:

- CWE-78: OS command injection;
- CWE-79: cross-site scripting;
- CWE-89: SQL injection; and
- CWE-94: code injection.

### 2.2 File, parser, and external-resource boundaries

Target 60 task units, approximately 10 per leaf:

- CWE-22: path traversal;
- CWE-434: unrestricted or dangerous file upload;
- CWE-502: deserialization of untrusted data;
- CWE-611: XML external entities;
- CWE-776: recursive entity or resource amplification; and
- CWE-918: server-side request forgery.

### 2.3 Identity, authorization, permissions, and sensitive information

The original planning target was 60 task units, approximately 10 per leaf:

- CWE-200: exposure of sensitive information;
- CWE-287: improper authentication;
- CWE-306: missing authentication for critical function;
- CWE-732: incorrect permission assignment;
- CWE-798: hard-coded credentials; and
- CWE-862: missing authorization.

The completed outcome-blind quality census contains 48 task units: 11
CWE-200, 0 CWE-287, 5 CWE-306, 7 CWE-732, 10 CWE-798, and 15 CWE-862. Because
the seven-source census is complete, 60 is no longer treated as an admission
gate or a reason to manufacture, duplicate, or weaken tasks. The prospective
family scope is all 48 quality-qualified units, with measurement support
recorded separately: 17 already have qualified static profiles, 20 have
audited task-specific source safety tests pending executable-Oracle
qualification, and 11 remain contextual or lack a usable security test. The
frozen identities and source-test audit are in
`data/dataset-curation/identity-family-scope-v1.json`.

### 2.4 Cryptography, randomness, and integrity

Target 60 task units, approximately 12 per leaf:

- CWE-295: improper certificate validation;
- CWE-327: use of a broken or risky cryptographic algorithm;
- CWE-328: use of a weak hash;
- CWE-338: use of a cryptographically weak pseudo-random number generator;
  and
- CWE-347: improper verification of cryptographic signature.

The primary paper-facing effect is the frozen overall, hypothesis-specific
assigned-arm ITT over eligible Python-core task units. The four family results
are preplanned heterogeneity estimates. Individual CWE results are descriptive
unless a later, outcome-blind power simulation explicitly freezes a supported
CWE-level family before generation.

If a leaf quota cannot be filled by eligible, independent task units, the data
gate fails for that planned coverage claim. Before any model outcome is read,
the study may either acquire additional tasks, document an outcome-blind
within-family redistribution, or narrow the prospective coverage. It may not
duplicate tasks, count variants as independent, or pool unrelated CWEs to hide
the shortfall.

For Identity, the third option has now been taken prospectively: the paper may
claim coverage of the observed 48-task census, but not balanced six-leaf or
60-task coverage. Oracle qualification still controls which stratum can enter
a particular confirmatory estimate; it does not remove the other units from
the quality-qualified data set.

## 3. Replication layers

### 3.1 C/C++ memory safety

The memory-safety layer targets four independent task units for each of
CWE-119, CWE-120, CWE-125, CWE-190, CWE-416, CWE-476, and CWE-787, for 28
task units total. Measurement requires compilation, a frozen functional test,
and the applicable executable security check such as ASan/UBSan or a frozen
exploit. A Python static-analysis result cannot substitute for this layer.

### 3.2 Backend applications

The backend layer targets 28 independent application scenarios with frozen
functional tests and end-to-end security checks. BaxBench is the preferred
initial source. Framework implementations of one scenario are dependent
realizations of that scenario, not independent task units. The selected
framework/language realizations and their weights must be frozen before any
generation outcome is read.

## 4. Candidate source policy

The Python-core inventory retains eligible candidates from the current cleaned
SecurityEval, LLMSecEval, SALLM, CWEval, CodeSecEval/SeCodePLT, and CyberSecEval
Instruct collections. Source breadth is reported rather than used as a task
quality threshold.

`source_lineage_family` records derivation and task overlap, not merely dataset
name or author institution. A copied, translated, reformatted, or mutated task
remains in the same lineage unless independence is demonstrated.

For the Python core:

- lineage identity and concentration are diagnostics, not admission gates;
- selection prefers an underrepresented lineage only after family and leaf-CWE
  balance, without rejecting an otherwise qualified task;
- the paper reports source-specific estimates and leave-one-lineage-out
  sensitivity when the frozen sample makes them estimable;
- exact and semantic duplicates across all sources count once; and
- dataset availability or previous model performance cannot change the
  selection rule after outcomes are visible.

The local CyberSecEval source is the submission-provided **Instruct Prime**
dataset snapshot at
`datasets/Submission Code and Results/Data/Instruct Prime/instruct.json`.  It
contains 1,404 records (251 Python) and has SHA-256
`2bbc433c91a625dd82fa2f9e71d94b7318e1b6bbb077987d058d71a80a022788`.
It is byte-identical to the `instruct.json` placed in the accompanying modified
PurpleLlama working tree.  It is not byte-identical to that working tree's
upstream commit `db023dcdf35971c8fb1def3a0ba460c7e1bbdf0c`, whose committed
file contains 1,916 records and has SHA-256
`c1ea5ca9a6e6aa4e9af8bcba701f78fb7077fbb859afd4d61b11b6cb9ed3f6a6`.
The study treats this 1,404-record file directly as the external dataset version
it received; it does not need to reconstruct how that external version was
created.  The paper and artifact report the snapshot name, size, path, digest,
citation, and upstream address, without calling it an official `instruct-v2`
release.  Our own outcome-blind lineage, deduplication, contract, and Oracle
gates start from these 1,404 records.  Bundled model
responses, statistics, logs, and notebooks are never selection inputs.

SecurityEval, CodeSecEval, and SeCodePLT follow the same scientific admission
pipeline as the other candidate sources.  The final artifact records each
source's citation, address, version, and content digest.  License metadata is
descriptive provenance rather than a separate sampling stratum.  CodeSecEval
SecEvalBase and its SecurityEval ancestors nevertheless remain one lineage for
sampling and cannot be counted as independent tasks.

The first cleaning pass proceeds in this order:

1. SALLM and CWEval, to validate normalization and functional-contract import
   against sources with explicit licenses and source-native tests;
2. the local CyberSecEval Instruct Prime snapshot;
3. LLMSecEval, to fill prospectively specified mechanism-family shortfalls;
4. SecurityEval, CodeSecEval, and SeCodePLT; and
5. BaxBench and C/C++ sources in their separate replication layers.

## 5. Data quality and later study admission

The field-level authority is `docs/task-unit-data.md` plus its executable
verifier. This section states only the research boundary so that the data
specification cannot drift into another hand-maintained schema.

The prospective pipeline has separate records and freeze points:

```text
TaskUnitRecord
  -> FunctionalContract
  -> QualityDecision
  -> RoleExposureRecord
  -> provisional TechnicalReadiness
  -> PromptTSG after method freeze
  -> HypothesisEligibility after hypothesis freeze
  -> Assignment after confirmation freeze
```

Admission to the quality-qualified curated corpus requires only:

1. immutable and traceable source identity;
2. complete representative model-visible input;
3. a coherent software request with observable behavior;
4. a source-bound functional contract that is faithful and sufficiently
   evaluable under blind review; and
5. no unrecoverable source defect or unresolved source-level insufficiency.

CWE, mechanism, Oracle, runtime, exposure, ADD/REMOVE applicability, formal
role, and split do not determine data quality. A task may therefore be
`QUALITY_INCLUDED` while remaining outside the current study or unsupported by
the current measurement stack.

`ADD/REMOVE eligibility` is not an original task property. It is derived only
after a concrete hypothesis freezes its target control, natural source state,
operation, allowed requirement delta, Prompt TSG policy, and measurement
profile. Discovery eligibility, confirmation eligibility, role assignment,
and assignment are likewise separate successor artifacts and never appear in
the source-data tables.

The formal allocator must enforce zero task-unit overlap across roles and at
most one selected task unit per frozen near-duplicate group across the union of
all prospective formal roles. Development or outcome exposure restricts later
role reuse but does not rewrite quality. A supported Oracle profile may still
return `unknown` for generated code; that outcome remains explicit and is never
recoded as secure or removed from assigned-arm ITT.

## 6. Deduplication and clustering

Deduplication proceeds before sampling and includes:

1. exact source and prompt identity;
2. normalized prompt identity;
3. source-location and upstream-commit identity;
4. known benchmark derivation and mutation relations; and
5. conservative semantic clustering with frozen model/rules, thresholds, and
   human-adjudication procedure.

The implementation first emits lexical candidate pairs within the same
language block. CWE labels are retained as attributes but cannot be retrieval
blocks because copied tasks may carry inconsistent CWE annotations across
sources. Those pairs are only a scalable retrieval stage: they do
not become semantic duplicates until a separately frozen blind adjudication
accepts them.  Exact duplicates require no model adjudication.

The adjudication tests task identity rather than mechanism-family similarity:
two records share a cluster only when their functional contracts are
substitutable up to incidental naming, library, route, formatting, or
presentation changes. Tasks that merely share an operation such as XML
parsing, password hashing, command execution, or memory allocation remain
independent when their required inputs, outputs, side effects, or user-visible
goals differ. This prevents single-linkage chains from collapsing a broad
mechanism family into one experimental unit.

An outcome-blind retrieval benchmark compared character 3--5-gram TF--IDF with
the frozen `BAAI/bge-base-en-v1.5` revision
`b4595376fce1812665312d0557400026cdeb7739`.  Across 357 deterministic
signature-and-contract views and 230 directed known-lineage queries, both
methods reached Recall@10 = 1.0.  TF--IDF ranked contract-view targets more
highly (MRR 0.983 versus 0.950), so the embedding method failed the prospective
+0.05 Recall@10 admission threshold.  The artifact therefore keeps TF--IDF for
candidate retrieval and the blind LLM for semantic adjudication; it does not
add an embedding runtime dependency.  This is an artifact-specific engineering
decision, not a claim that lexical retrieval dominates embeddings generally.
The frozen setup and hashes are recorded in
`docs/experiments/2026-08-22-dedup-retrieval-benchmark.md`.

Uncertain semantic similarity is not sufficient to merge confirmatory units.
Only exact-prompt identity and frozen source-lineage identity currently have
merge authority. LLM and retrieval similarities are retained as diagnostics.
Discover, development, calibration, confirmatory, and replication boundaries
are cluster-disjoint under this conservative rule.

### 6.1 Frozen seven-source curation artifact

The outcome-blind curation covers 2,283 normalized task records from the seven
candidate datasets. Language-blocked lexical retrieval produced 4,744
candidate pairs, all classified by a frozen blind adjudication with
`qwen3.5-flash-2026-02-23`. An independent stress-tail review later found that
the LLM-positive edges were not precise enough to define confirmatory
experimental units: only 8 of 30 lowest-similarity accepted edges were judged
substitutable instances of the same task. That sample diagnoses over-merging;
it is not a population precision estimate.

The active assembly therefore applies only exact-prompt and known-lineage
must-links. It produces 2,165 conservative clusters: 2,047 singletons and 118
pairs, with no LLM edge applied. The earlier 1,844-cluster result is retained
only as an engineering/sensitivity artifact. Of the 2,165 conservative cluster
representatives, 1,844 matched an existing security-neutral functional contract
by record ID and prompt hash. The remaining 321 contracts were extracted in 17
blinded batches and all resolved, so the active contract set now covers all
2,165 representatives. The frozen local bundles are:

Here, `resolved` means that every representative received a schema-valid extracted
contract; it does **not** mean that all 2,165 contracts passed an independent
semantic-quality review. A later outcome-blind 25-contract development pilot found
that one strong LLM reviewer was not accurate enough to serve as an automatic gate
(fault precision and recall were both 4/6 on the pilot), while a deterministic scan
found 71 contracts containing response-format instructions as functional
requirements. The successor review therefore treats LLM output as triage and
requires a corrected contract bundle plus independent adjudication for tasks that
may enter a formal experiment. See
`docs/experiments/2026-08-31-functional-contract-review-pilot.md`.

The complete outcome-blind review has now processed all 2,165 contracts in 433
closed batches. It labels 1,667 contracts `faithful` and 498 `faulty`; functional
evaluability is 1,378 `sufficient`, 769 `limited`, and 18 `insufficient`. The
strict conjunction of no deterministic issue, `faithful`, and `sufficient`
contains 1,203 reviewer-qualified candidates, but the review explicitly records
that semantic quality and final experiment eligibility are not established. A
diagnostic audit of 30 reviewer-qualified Python candidates still found a clear
material omission plus multiple evaluability and CWE/scope concerns. The
pre-successor 373-task Python census intersected the original strict set in 216
task units. These were review candidates, not an automatically admitted sample. Full
counts, evidence identities, and protocol risks are recorded in
`docs/experiments/2026-08-31-functional-contract-review-full.md`.

A deterministic successor bundle removes the 71 pure response-format requirements,
retains all 2,165 task units, and gives only the corrected contracts new content
IDs. This repair does not resolve semantic faults. Its local path is
`.codex-runtime/contract-repair-7c9dc1c-20260831-05`, with bundle SHA-256
`1b081f1f693fdd68ab1cf14c1caf42f91afa35372f844d8addae64860111e894`.
Replaying the complete review against that explicit repair lineage yields 1,215
strict contracts; the additional 12 are cases whose only deterministic issue
was the removed response-format instruction.

- semantic pair decisions:
  `.codex-runtime/semantic-curation-seven-v9-strict-20260823-12/final`,
  SHA-256 `ecd11b14e55241aa5bf912e90abb1b1b65e09c1543d5ffd47b63efdba46dea26`;
- historical conflict-constrained clusters (engineering/sensitivity only):
  `.codex-runtime/semantic-clusters-seven-v10-constrained-20260823-13`,
  SHA-256 `f592bfcaf77b3c86a1bc96c2f191b65afbb2f4f3c74b4a6c87dc46e4f0c179da`;
- active conservative clusters:
  `.codex-runtime/semantic-problem-pilot-final`,
  SHA-256 `88e22630523f571070be6427d91ad34106c72343ccdfed1b584da3790eccd263`;
- independent outcome-blind review:
  `.codex-runtime/semantic-cluster-independent-review-20260823-28`,
  SHA-256 `3f663654595f342cf432f9ecebc357db0437c08285b5152c557a24d777a83d42`;
- historical functional contracts available for exact representative reuse:
  `.codex-runtime/contract-curation-seven-v7-20260823-20/final`,
  SHA-256 `be661b9121830b4757eae86e766affba57aa59916347d1120b0bb3354b94b2ca`;
- pre-repair complete functional contracts:
  `.codex-runtime/gate-c-contracts-complete/contracts-full/final`,
  SHA-256 `eef5ed574bc5bebcbee07ecaee9ff5e7dd24d8c8dba32cd75c5d103be3daa3e0`;
- full functional-contract quality triage:
  `.codex-runtime/contract-quality-triage-37acead-20260831-03-r6-closed/final`,
  SHA-256 `137f94f6b629585f60308d927496b4ae980bd4b8e1efcadc50ebbb71478623cc`;
- deterministic response-format repair successor:
  `.codex-runtime/contract-repair-7c9dc1c-20260831-05`,
  SHA-256 `1b081f1f693fdd68ab1cf14c1caf42f91afa35372f844d8addae64860111e894`;
- historical combined handoff:
  `.codex-runtime/dataset-curation-seven-final-20260823-21`,
  SHA-256 `e4617233d5c2b805aadcc3f1fe9f2b67ce73c66959e382f0d526ac0b594898d1`.

No generated program, experimental arm, Security Oracle output, or experiment
outcome was supplied to curation. The artifacts are preparation evidence and
do not themselves support a scientific effect claim.

### 6.2 Pre-successor frozen candidate ledger

The frozen v4 outcome-blind audit emits one upstream record for each of the 2,165 task
units. Its physical `final_dataset_status` and mutually exclusive
`candidate_status` fields are retained only as legacy compiler inputs. The
reviewer-facing v4 bundle replaces them with an explicit quality disposition,
an exposure/role record, and a multi-axis derived readiness view. A failure on
one axis never erases a task or silently hides another blocker.

Applying the former quality-only rule to all 2,165 task units placed 1,222 in the
quality-qualified curated corpus. It contains 563 Python, 151 C, 102 C++, 121 JavaScript, 91 C#, 66 Java,
58 Rust, 53 PHP, and 17 Go task units. Of the 1,229 strict contracts, six remain
pending independent review of a known material
omission or functional-evaluability concern. Another 930 task units remain pending
contract-quality repair, and seven incoherent source prompts are excluded. All
dispositions remain in the complete ledger.

The old audit's 164 `READY_CONFIRMATORY` rows were a provisional implementation
view, not the definition of the curated corpus or a formal experiment role.
The response-format repair produced 1,215 strict contracts. A bounded
outcome-blind adjudication then reviewed the 17 faulty+sufficient Python tasks
that otherwise had mechanism, Oracle, and runtime support: eight stale or
self-contradictory review labels were corrected, six contracts were repaired,
and three source-inconsistent cases remained pending. That pre-successor population
contains 1,229 strict and 936 repairable contracts.

The deterministic registry matcher left 220 task units ambiguous or unresolved.
A blind Qwen3.7-Max review saw only the source prompt, repaired functional
contract, and finite same-CWE registry candidates. It produced 86 bindings to
qualified local profiles, two bindings to a registered but unsupported
contextual profile, and 132 not-applicable or unresolved decisions. All accepted
bindings carry a literal source-prompt evidence span. Three spans were recovered
by a deterministic case-insensitive contiguous-subspan projection; two weak
anchors were conservatively downgraded to unresolved. This binding review is a
single-model curation decision, not human gold.

A subsequent outcome-blind case adjudication reviewed the 21 unresolved rows
that affected quality-qualified tasks. Six were grounded to an existing
realization with exact prompt evidence and 15 remained unresolved because the
registered mechanism would narrow or change the task contract. The bounded
Oracle extension then admitted only Python-literal dictionary parsing,
Requests certificate validation, and explicit cipher/hash selection shapes; it
did not generalize those profiles to arbitrary code execution, custom TLS
contexts, dynamic algorithm names, or contextual identity policy.

A second outcome-blind review then adjudicated all twelve quality flags from
the earlier diagnostic sample. Five functionally coherent tasks were admitted:
four remain `PENDING_SCOPE` because their source CWE does not match the prompt
mechanism, and one remains `PENDING_BINDING`. One unresolved literal
`<language>` prompt was reclassified as a source defect. Five genuinely
under-specified contracts and one material contract omission remain pending.
This review therefore increased data-quality coverage without changing the
legacy compiler's 164-task `READY_CONFIRMATORY` count. The corrected v4 view
derives 166 technically ready tasks because exposure is no longer conflated
with technical support.

For historical traceability, the upstream compiler input had these mutually
exclusive candidate statuses:

| Status | Task units |
| --- | ---: |
| `READY_CONFIRMATORY` | 164 |
| `PENDING_CONTRACT` | 930 |
| `PENDING_ORACLE` | 209 |
| `PENDING_RUNTIME` | 174 |
| `PENDING_BINDING` | 59 |
| `PENDING_INDEPENDENT_REVIEW` | 15 |
| `PENDING_SCOPE` | 607 |
| `EXCLUDED_SOURCE_DEFECT` | 7 |

They are not the current readiness protocol. The v4 reviewer bundle reports
scope, mechanism registration, binding, Oracle, runtime, functionality, and
quality-review axes independently. Its single workstream is only a
deterministic `primary_next_action`. Exposure exists exclusively in the role
record, so removing exposure from technical readiness can change the derived
technical-ready count without changing any task, contract, or measurement
support.

The 166 technically ready Python task units cover seven source lineages and
thirteen CWEs; 141 are unexposed. All remain quality-qualified regardless of
lineage composition; exposure is a separate role coordinate. This historical
population is planning evidence, not the active successor or a frozen confirmatory
sample. CyberSecEval contributes
57/166 (34.3%) of the technically ready pool; this is reported as a
transportability diagnostic rather than an exclusion rule.

The Security-Oracle registry published with the audit distinguishes 14
qualified deterministic Python profiles, one registered contextual profile
that remains unsupported, and 28 BaxBench source-native profiles pending Docker
qualification. The target-schema producer delegates the 12 immutable legacy
profiles and owns only the two new CWE-295/CWE-327 profiles. A task can be
`READY_CONFIRMATORY` only with a qualified profile; an unsupported or missing
profile remains `PENDING_ORACLE`.

The priority-extension inventory contains 207 source-tested task units:

| Priority tier | All candidates | Strict-contract subset | Remaining gate |
| --- | ---: | ---: | --- |
| Python mechanism extension | 113 | 89 | freeze a task-applicable MechanismSpec and Oracle profile |
| C/C++/Go/JavaScript extension | 94 | 80 | freeze language runtime, intervention realization, and Oracle |

The C/C++ memory-safety data pool contains 102 strict, non-exposed candidates
across the seven planned CWEs and has at least four per CWE. Only six reference a
source functional test, so compilation, frozen functional tests, and
task-applicable sanitizer/exploit measurement remain a runtime gate. The audit
does not prematurely choose four per CWE before those measurements exist.

The BaxBench snapshot contains exactly 28 independent scenario files, 34
source-native functional tests, 70 source-native security tests, and 14
dependent framework realizations. Its data-coverage target is met, but every
scenario remains `PENDING_RUNTIME_QUALIFICATION` until the frozen Docker replay
passes and one framework realization per scenario is selected before outcomes.

The active closed artifacts are:

- adjudicated mechanism-binding run:
  `.codex-runtime/mechanism-binding-adjudication-20260831-19`, SHA-256
  `089ac31dd29bb5ba89a4ba5dcd4776f8f6ad2c1e871bf3629d9f0ae59f8eef19`;
- targeted outcome-blind contract recovery:
  `.codex-runtime/contract-recovery-adjudication-20260831-10`, SHA-256
  `6df47b0ce9f9a5a02d91a94323c5a12fa56472101e77761f5856994897700be0`;
- target Security-Oracle qualification:
  `data/oracle-calibration/phase-context-policy-v3-security-profiles-v1-qualification`,
  SHA-256
  `fc4216dc7cb6e8f8e0377e69e300bded30485f1725b7d855504adab3b396ab75`;
- schema-3 mechanism registry:
  `data/method/phase-context-policy-v3-mechanism-registry-v1.json`, SHA-256
  `bff8b78e67520725d7cdd644b77ad7c2d6df64531bee0479a2c08ba9d1874970`;
- schema-3 eligibility policy:
  `data/dataset-curation/phase-context-policy-v3-eligibility-policy-v1.json`, SHA-256
  `8d8401ad3c1a45b295d4febdef8a5fb3f524e11b88f28e7a447afcd0b97792fb`;
- independent blind quality adjudication:
  `data/dataset-curation/contract-quality-independent-adjudication-v1.json`, SHA-256
  `d98983a1af79361a6f6b2d9ff49a3f3ff235f87d0650fd14a4de9bb26a812650`;
- candidate-data audit after independent quality adjudication:
  `.codex-runtime/dataset-final-quality-20260831-40-independent-quality`,
  SHA-256
  `2b74784e5917bd6a76f9bddc4aac0f24c0a332cc4ad60cd3113a4ab9c428f143`;
- audit report:
  `docs/experiments/2026-08-31-final-candidate-data-audit.md`.

No generated program, assigned arm, Security-Oracle output, Functional-Judge
verdict, or experiment outcome was consulted. The ledger completes data
disposition, but it does not authorize confirmatory generation while the Python
population and both replication runtime gates remain closed.

### 6.3 Historical outcome-blind eligibility audit (superseded)

The previous implementation-readiness audit classified all 1,844 historical
clusters
against the frozen study layers, mechanism registry, qualified Functional
Oracle, and available Security Oracle profiles. It did not require a
source-native executable test because the frozen Python functional outcome is
AST/compile validity plus a blinded whole-task LLM review; source tests remain
an independently recorded evidence attribute.

Its result was 204 `eligible`, 456 `calibration_only`, and 1,184 `excluded`
clusters. The 204 historically runnable Python clusters covered only five
registered CWEs: CWE-78 (84), CWE-89 (42), CWE-502 (22), CWE-328 (23), and
CWE-338 (33). Their family support is:

| Python family | Eligible | Target | Gate |
| --- | ---: | ---: | --- |
| injection and interpreter | 126 | 60 | count pass |
| file, parser, external resource | 22 | 60 | count fail |
| identity, authorization, permissions | 0 | 60 | count fail |
| cryptography, randomness, integrity | 56 | 60 | count fail |

These counts are not valid for sampling from the new 2,165-cluster population.
Before the correction, the prospective 240-task-unit Python population gate did
**not pass**. In addition, 148 of the 204 eligible representatives came from the
CyberSecEval Instruct Prime lineage. That concentration remains evidence of a
narrow source mixture, but it no longer invalidates otherwise qualified tasks.
This is a transportability diagnostic, not an experiment result and not a
reason to sample selectively from previously favorable tasks.

The closed audit bundle is
`.codex-runtime/dataset-eligibility-seven-v3-final-20260823-24`, SHA-256
`a6b17780f6051e316d17500b5dd98b5de24b6b766a6a2f4d829b1d7bd1abbac1`.
It contains separate eligible, calibration-only, and excluded manifests plus
the complete per-cluster decision ledger.

## 7. Arms and assignment budget

The successor protocol uses one operation-specific four-arm family per frozen
hypothesis. ADD uses `TARGET_PATCH`, `NOOP_REWRITE`,
`LENGTH_MATCHED_PLACEBO`, and `GENERIC_SECURITY_REMINDER`. REMOVE uses
`TARGET_REMOVE`, `NOOP_RETAIN`, `LENGTH_MATCHED_SHAM_EDIT`, and
`GENERIC_SECURITY_REPLACEMENT`. The primary contrast is Target minus the
operation-matched No-op. Placebo/sham and generic contrasts are secondary
specificity evidence.

The 60-task-unit canary contains 15 independent task units per mechanism
family, but it does not imply 240 successor assignments. A task enters an ADD
block only when its context is present and source feature is absent; it enters
a REMOVE block only when the feature is present and its task-preserving neutral
counterpart is frozen. The earlier `absent`, `specific`, `generic`, and
`placebo` design and its `specific - placebo` contrast remain immutable legacy
study coordinates and are not reused for successor confirmation.

The dataset size does **not** determine the final assignment count. Assignment
count is computed only after the hypothesis freeze as the sum over frozen
hypotheses, their eligible task populations, realizations, models, request
slots, and arm protocols. Therefore the earlier arithmetic of 592 or 688
assignments is a budgeting illustration, not a frozen run contract.

## 8. Outcome-blind sample-size gate

The 240-task-unit Python core is a prospective design target, not a substitute
for hypothesis-specific power analysis. Before confirmation, simulation must
use plausible and documented values for:

- baseline oracle-evaluable secure-code yield;
- within-task-unit dependence among descendant records or realizations;
- request-randomness and realization heterogeneity;
- terminal-no-code and Oracle-unknown rates;
- the minimum scientifically important effect;
- the number of selected hypotheses and all primary contrasts; and
- the frozen max-|T| multiplicity procedure.

The simulation reports power and interval width for each selected hypothesis's
actual eligible task-unit set. A total pool of 240 cannot rescue a hypothesis
with sparse applicability. If the target design is insufficient, the study
must acquire more eligible task units, reduce the prospectively selected
hypothesis family, or report that confirmation is not supported. It cannot
change the denominator, combine incompatible strata, or continue sampling in
response to the observed effect.

### 8.1 Frozen minimum validation design

The active outcome-blind design bundle is
`.codex-runtime/study-design-python-four-arm-v1-20260823-48`, SHA-256
`f9df3a6ff55698914e9f515ab07249b8aea70c8c838be665544d9c2d36aeebe0`.
It selects 60 unique task units with no co-selection violation and exactly 15
per family. That immutable historical artifact happened to include at least
three lineages per family and a maximum lineage contribution of 15/60 under its
then-active hard constraints. Those constraints are not carried into the
prospective successor. The active selector balances family and leaf CWE first,
uses lineage only as a non-excluding tie-breaker, and then uses frozen hash
order. Selection uses only frozen task, contract, lineage, mechanism, and
Oracle-profile fields.

The existing paired `specific - placebo` planning calculation used a
20-percentage-point minimum effect, two-sided alpha 0.05, and a prospective
discordant-pair probability of 0.30; its normal-approximation power was 0.807,
falling to 0.688 if discordance was 0.40. This remains an
assumption-conditional legacy planning diagnostic, not observed effect evidence
and not a successor Target-Noop power authorization.

Confirmatory generation is not yet authorized. The next successor gate must
first freeze hypotheses, operation-specific eligibility, complete realization
support, generator identity, arm texts, request slots, and the actual assignment
count. It then reruns power simulation for each selected hypothesis's eligible
task-unit set and Target-Noop primary contrast before any confirmation outcome
is generated.

The simulation assumptions, code, seeds, candidate curves, chosen design, and
maximum authorized sample are frozen before the first confirmatory generation.

## 9. Freeze sequence and acceptance gate

The only accepted sequence is:

```text
source inventory and version lock
-> CWE normalization and source-lineage mapping
-> exact and semantic deduplication
-> functional-contract and Oracle-profile admission
-> outcome-blind power simulation
-> stratified task-unit sampling with a fixed seed
-> task, split, hypothesis-eligibility, and arm manifests frozen
-> confirmatory generation authorized
```

The final freeze must publish counts by layer, family, leaf CWE, language,
granularity, source lineage, functional-contract type, Oracle profile, and
eligibility status; all excluded and unresolved candidates remain counted with
typed reasons.

The planned design is accepted only when:

- all 240 core, 28 memory, and 28 backend targets are either filled by eligible
  independent task units or a prospective shortfall amendment is documented
  before outcomes;
- the primary hypothesis-specific power gate passes;
- development, calibration, and all scientific layers are task-unit-disjoint;
- source-lineage composition is published and the prespecified source
  sensitivity analyses are run when estimable;
- every admitted task has a functional contract and calibrated Oracle profile;
- the assignment budget is recomputed from the frozen hypothesis and arm
  manifests; and
- no selector, generator, Judge, Oracle, or historical per-task outcome was
  consulted during admission or sampling.

Until those conditions pass, this document specifies the intended study design
but does not authorize a confirmatory run or a paper claim that the final
dataset has been frozen.
