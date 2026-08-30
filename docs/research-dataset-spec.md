# Prospective Research Dataset Specification

## Status and scope

This document defines the prospective dataset design for the single active
Prompt Mechanism Study path. The 240-task-unit Python population remains a
coverage target. Section 8 records a smaller, outcome-blind 60-task-unit sample
as a population-feasibility and power-planning canary; it is not a frozen
successor assignment manifest or evidence that an intervention effect exists.

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

Target 60 task units, approximately 10 per leaf:

- CWE-200: exposure of sensitive information;
- CWE-287: improper authentication;
- CWE-306: missing authentication for critical function;
- CWE-732: incorrect permission assignment;
- CWE-798: hard-coded credentials; and
- CWE-862: missing authorization.

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

The Python-core inventory should draw from at least five independently derived
benchmark lineages, with candidates from the current cleaned SecurityEval,
LLMSecEval, SALLM, CWEval, CodeSecEval/SeCodePLT, and CyberSecEval Instruct
collections where eligible.

`source_lineage_family` records derivation and task overlap, not merely dataset
name or author institution. A copied, translated, reformatted, or mutated task
remains in the same lineage unless independence is demonstrated.

For the Python core:

- no source lineage may contribute more than 25 percent of frozen task units;
- every mechanism family must contain at least three source lineages;
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
release.  Our own outcome-blind lineage, deduplication, contract, Oracle, and
25-percent source-cap gates start from these 1,404 records.  Bundled model
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

## 5. Task admission contract

Every admitted task must bind:

```text
task_id
task_unit_id
source_dataset
source_version
source_item_id
source_lineage_family
language
task_granularity
cwe_leaf
mechanism_family
functional_contract_id
security_oracle_profile
oracle_support_status
discovery_eligible
confirm_add_eligible
confirm_remove_eligible
source_feature_state
neutral_counterpart_status
eligible_arm_protocol_ids
split
deduplication_digest
```

All regimes additionally require:

1. a clear functional request with enough context to produce and evaluate one
   candidate;
2. the most specific defensible CWE label and a documented mapping to one
   mechanism family;
3. a frozen semantic functional contract independent of the generated
   candidate; AST/compilation plus the blind Functional Judge is the common
   functionality Oracle, while source-native executable tests are retained as
   optional calibration evidence rather than a universal admission condition;
4. a prospectively calibrated security-Oracle profile for the language,
   task shape, and CWE;
5. for confirmation, at least one valid frozen Target/Noop arm protocol for the
   relevant hypothesis;
6. stable source, version, license, original identity, and content digest;
7. no task-unit overlap with development, calibration, discovery, or
   another confirmatory/replication split; and
8. no selection based on generated code, security label, functional verdict,
   or effect direction.

Regime-specific admission is then applied without collapsing the states:

- **Discovery:** the source Prompt is natural and unmanipulated. The target
  feature may be `PRESENT`, `ABSENT`, or `UNRESOLVED`; its state and evidence are
  extracted before any discovery outcome is read. Each family-local FCI table
  must pass a frozen within-context positivity and source-overlap audit.
- **ADD confirmation:** the context is `PRESENT` and the target feature is
  `ABSENT`. The original Prompt is the source-state no-op; no vulnerable
  instruction is inserted.
- **REMOVE confirmation:** the context and target feature are `PRESENT`, the
  positive requirement has provenance-bound evidence, and a task-preserving
  neutral counterpart is attested before generation.

Eligibility for one regime does not imply eligibility for another. In
particular, the security-neutral criterion belongs to ADD confirmation rather
than to observational discovery as a whole.

A task-level profile may be supported while a generated program still yields
an Oracle coverage unknown. Such unknowns remain explicit outcomes. They are
never recoded as secure or removed from assigned-arm ITT.

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

- semantic pair decisions:
  `.codex-runtime/semantic-curation-seven-v9-strict-20260823-12/final`,
  SHA-256 `ecd11b14e55241aa5bf912e90abb1b1b65e09c1543d5ffd47b63efdba46dea26`;
- historical conflict-constrained clusters (engineering/sensitivity only):
  `.codex-runtime/semantic-clusters-seven-v10-constrained-20260823-13`,
  SHA-256 `f592bfcaf77b3c86a1bc96c2f191b65afbb2f4f3c74b4a6c87dc46e4f0c179da`;
- active conservative clusters:
  `.codex-runtime/semantic-clusters-seven-v11-conservative-20260823-29`,
  SHA-256 `88c03c9dd609779d5301d03bcabdb80533b7d0aa84a3877a8c6933f758ea4e0e`;
- independent outcome-blind review:
  `.codex-runtime/semantic-cluster-independent-review-20260823-28`,
  SHA-256 `3f663654595f342cf432f9ecebc357db0437c08285b5152c557a24d777a83d42`;
- historical functional contracts available for exact representative reuse:
  `.codex-runtime/contract-curation-seven-v7-20260823-20/final`,
  SHA-256 `be661b9121830b4757eae86e766affba57aa59916347d1120b0bb3354b94b2ca`;
- active complete functional contracts:
  `.codex-runtime/contract-curation-seven-v8-conservative-20260823-32/final`,
  SHA-256 `daa6601152a76a20e8bd0fc82e0347c9a31fe0c103ba29754238706c88099fe4`;
- historical combined handoff:
  `.codex-runtime/dataset-curation-seven-final-20260823-21`,
  SHA-256 `e4617233d5c2b805aadcc3f1fe9f2b67ce73c66959e382f0d526ac0b594898d1`.

No generated program, experimental arm, Security Oracle output, or experiment
outcome was supplied to curation. The artifacts are preparation evidence and
do not themselves support a scientific effect claim.

### 6.2 Active outcome-blind eligibility and under-merge audit

The active eligibility pass classifies all 2,165 conservative clusters. It
finds 306 `eligible`, 497 `calibration_only`, and 1,362 `excluded` clusters.
In addition to the original five CWE classes, an outcome-blind task-level
audit binds 71 clusters to six bounded local profiles for path confinement,
archive extraction, XML external entities, outbound URL origins, file
permissions, and credential sources. The audit does not promote 29 clusters
whose CWE label does not match the frozen functional contract, or 15 CWE-862
clusters whose authorization correctness requires framework or caller
context.

At the family level, injection/interpreter has 144 eligible clusters,
file/parser/external-resource has 79, identity/authorization/permissions has
22, and cryptography/randomness/integrity has 61. Three families now meet the
60-task-unit target. The identity family remains below target, so the
prospective four-family population gate remains closed rather than treating
context-dependent authorization as locally proven.

To check whether the conservative rule split paraphrases too aggressively, an
outcome-blind requirements review examined every original eligible-pool
LLM-positive diagnostic pair (44) and every BGE top-10 pair absent from the
frozen lexical candidate set (123). A focused expansion then examined 19
same-CWE TF-IDF nearest-neighbor pairs involving the 71 newly eligible
clusters. Ten accepted duplicate edges form five components overall.
Collapsing them reduces the 306 eligible clusters to 299 task units. Two
borderline pairs remain separate but carry an
`at_most_one_unit_may_be_selected` constraint. This review changes only the
prospective sampling units; it does not retroactively give LLM or retrieval
edges general merge authority.

The active closed artifacts are:

- task-to-profile binding audit:
  `.codex-runtime/realization-binding-audit-seven-v1-20260823-38`,
  SHA-256 `970efdf5d916dbf8256b2725b422d4396a54adcbaf2b50db8f092c0306fb1adf`;
- eligibility:
  `.codex-runtime/dataset-eligibility-seven-v6-realization-profiles-20260823-42`,
  SHA-256 `208794e253ab91679ca2d27260d5bbf7042c02c35a9cb6eaaca26967584a588c`;
- complete embedding-only candidate reconstruction:
  `.codex-runtime/eligible-undermerge-embedding-complete-seven-v1-20260823-36`,
  SHA-256 `42914bd58129ca442df48368433aa8886c6b508751654b359fa1c6dee15667ec`;
- expanded eligible under-merge review and sampling-unit ledger:
  `.codex-runtime/eligible-undermerge-review-seven-v4-profile-bound-20260823-43`,
  SHA-256 `da61093463e252a3eb0c5dd040cab890381bcba9310bfd5abd8cf1736a19b96e`.

The 1,362 excluded clusters have still been normalized, clustered, and given
functional contracts. They are outside the current frozen Python mechanisms
or language layers, so they are inventory for later extensions rather than
part of the next formal denominator. Separately, 229 C/C++ memory-safety
clusters are retained as replication candidates. The outcome-blind readiness
audit selects four per target CWE (28 total), but only 6 currently carry a
source functional test. The C/C++ replication therefore remains gated on 22
frozen functional tests plus a compiler/sanitizer execution adapter.

An outcome-blind quality screen now retains 201 of the 1,362 outside clusters
as explicit priority-extension candidates. Admission to this pool requires a
nonempty frozen functional contract and at least one source test reference; it
uses no generated code, arm, Oracle output, or experiment outcome. The pool has
two tiers:

| Priority tier | Clusters | Scope | Remaining admission gate |
| --- | ---: | --- | --- |
| Python mechanism extension | 113 | 49 injection, 18 file/resource, 35 identity/permission, 11 crypto/transport | freeze a task-applicable MechanismSpec and Oracle profile |
| Cross-language replication extension | 88 | C 25, C++ 21, Go 19, JavaScript 23 | freeze the language runtime, intervention realization, and Oracle |

The Python tier covers source-tested adjacent mechanisms rather than arbitrary
new CWE labels: CWE-74/77/95/113/117/643/943; CWE-377/379/601;
CWE-250/259/269/276/352/522/863; and CWE-319/321/326/329/760. Every included
CWE has at least two candidates. These tasks are the first pool to examine when
the study prospectively expands its mechanism scope, but they remain excluded
from the current 60-task-unit denominator until their measurement gate passes.
The remaining 1,161 outside clusters stay in the inventory at lower priority;
most lack a source test, a supported language runtime, or a mechanism close to
the frozen research question.

The frozen selection policy is
`data/dataset-curation/priority-extension-policy-v1.json`, SHA-256
`b0f3439f07b7027e571f9cb34925b498c58bf467cd7bfc892525562f73a3b5fd`.
The selected record IDs and blockers are published in
`priority-extension-candidates.json` inside the active study-design bundle.

The review used prompts and frozen functional contracts only. It did not use
generated programs, assigned arms, Security Oracle outputs, or experiment
outcomes. It is a Codex requirements audit rather than an independent human
annotation study; that limitation is retained in the artifact report.

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
| injection and interpreter | 126 | 60 | count/lineage pass |
| file, parser, external resource | 22 | 60 | count fail |
| identity, authorization, permissions | 0 | 60 | count/lineage fail |
| cryptography, randomness, integrity | 56 | 60 | count fail |

These counts are not valid for sampling from the new 2,165-cluster population.
Before the correction, the prospective 240-task-unit Python population gate did
**not pass**. In addition, 148 of the 204 eligible representatives came from the
CyberSecEval Instruct Prime lineage. Under the frozen 25-percent per-lineage
cap, at most 64 of the currently eligible clusters can be selected, even before
family balancing. This is a corpus/method-coverage shortfall, not an experiment
result and not a reason to sample selectively from previously favorable tasks.

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
It selects 60 unique task units with no co-selection violation, exactly 15 per
family, at least three lineages per family, and a maximum lineage contribution
of 15/60. Within each family, the deterministic selector also balances the
available leaf CWEs before breaking ties by lineage and frozen hash order.
Selection used only frozen task, contract, lineage, mechanism, and
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
- source-lineage caps and family diversity constraints pass;
- every admitted task has a functional contract and calibrated Oracle profile;
- the assignment budget is recomputed from the frozen hypothesis and arm
  manifests; and
- no selector, generator, Judge, Oracle, or historical per-task outcome was
  consulted during admission or sampling.

Until those conditions pass, this document specifies the intended study design
but does not authorize a confirmatory run or a paper claim that the final
dataset has been frozen.
