# Prospective Research Dataset Specification

## Status and scope

This document defines the prospective dataset design for the single active
Prompt Mechanism Study path. It is a design target and an outcome-blind data
gate, not a frozen task manifest and not evidence that the listed tasks are
already available or eligible.

The final task IDs, sample size, hypothesis-specific eligible populations,
request slots, realizations, models, and assignment count remain unfrozen until
the inventory, deduplication, executable-contract, Oracle-calibration, and
power-simulation gates below pass. No generated-code outcome, model score, or
historical per-task result may influence admission or sampling.

## 1. Statistical units and study layers

The highest independent and resampling unit is `semantic_task_cluster_id`.
Rows, prompt rewrites, source mutations, framework variants, language
translations, request slots, and multiple hypotheses over the same semantic
task are dependent descendants of that cluster.

The prospective dataset has three inferentially separate layers:

| Layer | Target semantic clusters | Role | Primary pooling rule |
| --- | ---: | --- | --- |
| Python confirmatory core | 240 | primary assigned-arm ITT | may pool only under the frozen stratified estimator |
| C/C++ memory-safety replication | 28 | cross-language replication | report separately |
| backend-application replication | 28 | end-to-end functional/exploit replication | report separately |

The planned evaluation population therefore contains 296 semantic clusters,
but **296 is not one analysis denominator**. The two replication layers cannot
be silently pooled with the Python core because their languages, task
granularity, functional contracts, and security Oracles differ.

Two additional outcome-excluded resources are planned:

- 24 cluster-disjoint tasks for intervention-executor development; and
- 24 independent gold programs for functional-Judge and security-Oracle
  calibration.

Neither resource contributes to an intervention-effect estimate. Historical
canaries, failed runs, Judge-tuning cases, and previously inspected
confirmatory outcomes are also excluded.

## 2. Confirmatory security families

The Python core targets four mechanism families with 60 semantic clusters per
family. Leaf-CWE quotas are prospective balancing targets, not separate
confirmatory estimands.

### 2.1 Injection and interpreter boundaries

Target 60 clusters, approximately 15 per leaf:

- CWE-78: OS command injection;
- CWE-79: cross-site scripting;
- CWE-89: SQL injection; and
- CWE-94: code injection.

### 2.2 File, parser, and external-resource boundaries

Target 60 clusters, approximately 10 per leaf:

- CWE-22: path traversal;
- CWE-434: unrestricted or dangerous file upload;
- CWE-502: deserialization of untrusted data;
- CWE-611: XML external entities;
- CWE-776: recursive entity or resource amplification; and
- CWE-918: server-side request forgery.

### 2.3 Identity, authorization, permissions, and sensitive information

Target 60 clusters, approximately 10 per leaf:

- CWE-200: exposure of sensitive information;
- CWE-287: improper authentication;
- CWE-306: missing authentication for critical function;
- CWE-732: incorrect permission assignment;
- CWE-798: hard-coded credentials; and
- CWE-862: missing authorization.

### 2.4 Cryptography, randomness, and integrity

Target 60 clusters, approximately 12 per leaf:

- CWE-295: improper certificate validation;
- CWE-327: use of a broken or risky cryptographic algorithm;
- CWE-328: use of a weak hash;
- CWE-338: use of a cryptographically weak pseudo-random number generator;
  and
- CWE-347: improper verification of cryptographic signature.

The primary paper-facing effect is the frozen overall, hypothesis-specific
assigned-arm ITT over eligible Python-core clusters. The four family results
are preplanned heterogeneity estimates. Individual CWE results are descriptive
unless a later, outcome-blind power simulation explicitly freezes a supported
CWE-level family before generation.

If a leaf quota cannot be filled by eligible, independent clusters, the data
gate fails for that planned coverage claim. Before any model outcome is read,
the study may either acquire additional tasks, document an outcome-blind
within-family redistribution, or narrow the prospective coverage. It may not
duplicate tasks, count variants as independent, or pool unrelated CWEs to hide
the shortfall.

## 3. Replication layers

### 3.1 C/C++ memory safety

The memory-safety layer targets four independent semantic clusters for each of
CWE-119, CWE-120, CWE-125, CWE-190, CWE-416, CWE-476, and CWE-787, for 28
clusters total. Measurement requires compilation, a frozen functional test,
and the applicable executable security check such as ASan/UBSan or a frozen
exploit. A Python static-analysis result cannot substitute for this layer.

### 3.2 Backend applications

The backend layer targets 28 independent application scenarios with frozen
functional tests and end-to-end security checks. BaxBench is the preferred
initial source. Framework implementations of one scenario are dependent
realizations of that scenario, not independent clusters. The selected
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

- no source lineage may contribute more than 25 percent of frozen clusters;
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

Every admitted confirmatory task must bind:

```text
task_id
semantic_task_cluster_id
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
eligible_arm_protocol_ids
split
deduplication_digest
```

Admission additionally requires:

1. a clear, security-neutral functional request with enough context to produce
   and evaluate one candidate;
2. the most specific defensible CWE label and a documented mapping to one
   mechanism family;
3. a frozen semantic functional contract independent of the generated
   candidate; AST/compilation plus the blind Functional Judge is the common
   functionality Oracle, while source-native executable tests are retained as
   optional calibration evidence rather than a universal admission condition;
4. a prospectively calibrated security-Oracle profile for the language,
   task shape, and CWE;
5. at least one valid frozen Target/Noop arm protocol for the relevant
   hypothesis;
6. stable source, version, license, original identity, and content digest;
7. no semantic-cluster overlap with development, calibration, discovery, or
   another confirmatory/replication split; and
8. no selection based on generated code, security label, functional verdict,
   or effect direction.

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

When independence is uncertain, records are placed in the same semantic
cluster. Discover, development, calibration, confirmatory, and replication
boundaries are cluster-disjoint.

### 6.1 Frozen seven-source curation artifact

The current outcome-blind curation covers 2,283 normalized task records from
the seven candidate datasets. Language-blocked lexical retrieval produced
4,744 candidate pairs. A frozen blind adjudication with
`qwen3.5-flash-2026-02-23` classified every pair; cluster assembly first
applied exact and known-lineage must-links, then accepted LLM-positive edges
only when no adjudicated negative edge crossed the proposed components. This
blocked 121 contradictory single-link bridges and produced 1,844 semantic
task clusters (largest cluster: 7 records).

One minimal, security-neutral functional contract was then extracted for the
representative of every cluster. All 1,844 clusters have a contract, comprising
8,122 explicit requirements in total. The frozen local bundles are:

- semantic pair decisions:
  `.codex-runtime/semantic-curation-seven-v9-strict-20260823-12/final`,
  SHA-256 `ecd11b14e55241aa5bf912e90abb1b1b65e09c1543d5ffd47b63efdba46dea26`;
- conflict-constrained clusters:
  `.codex-runtime/semantic-clusters-seven-v10-constrained-20260823-13`,
  SHA-256 `f592bfcaf77b3c86a1bc96c2f191b65afbb2f4f3c74b4a6c87dc46e4f0c179da`;
- functional contracts:
  `.codex-runtime/contract-curation-seven-v7-20260823-20/final`,
  SHA-256 `be661b9121830b4757eae86e766affba57aa59916347d1120b0bb3354b94b2ca`;
- combined handoff:
  `.codex-runtime/dataset-curation-seven-final-20260823-21`,
  SHA-256 `e4617233d5c2b805aadcc3f1fe9f2b67ce73c66959e382f0d526ac0b594898d1`.

No generated program, experimental arm, Security Oracle output, or experiment
outcome was supplied to curation. The artifacts are preparation evidence and
do not themselves support a scientific effect claim.

### 6.2 Outcome-blind eligibility audit

The current implementation-readiness audit classifies all 1,844 clusters
against the frozen study layers, mechanism registry, qualified Functional
Oracle, and available Security Oracle profiles. It does not require a
source-native executable test because the frozen Python functional outcome is
AST/compile validity plus a blinded whole-task LLM review; source tests remain
an independently recorded evidence attribute.

The result is 204 `eligible`, 456 `calibration_only`, and 1,184 `excluded`
clusters. The 204 currently runnable Python clusters cover only five registered
CWEs: CWE-78 (84), CWE-89 (42), CWE-502 (22), CWE-328 (23), and CWE-338
(33). Their family support is:

| Python family | Eligible | Target | Gate |
| --- | ---: | ---: | --- |
| injection and interpreter | 126 | 60 | count/lineage pass |
| file, parser, external resource | 22 | 60 | count fail |
| identity, authorization, permissions | 0 | 60 | count/lineage fail |
| cryptography, randomness, integrity | 56 | 60 | count fail |

The prospective 240-cluster Python population gate therefore **does not
pass**. In addition, 148 of the 204 eligible representatives come from the
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

Target and Noop are required arms in every feasible primary complete block.
Generic and Placebo form a preplanned specificity panel over a target of 48
Python-core semantic clusters, balanced across the four families and admitted
only where the frozen hypothesis-specific arm protocol makes them meaningful.
ADD and REMOVE operations remain separate.

The dataset size does **not** determine the final assignment count. Assignment
count is computed only after the hypothesis freeze as the sum over frozen
hypotheses, their eligible task populations, realizations, models, request
slots, and arm protocols. Therefore the earlier arithmetic of 592 or 688
assignments is a budgeting illustration, not a frozen run contract.

## 8. Outcome-blind sample-size gate

The 240-cluster Python core is a prospective design target, not a substitute
for hypothesis-specific power analysis. Before confirmation, simulation must
use plausible and documented values for:

- baseline oracle-evaluable secure-code yield;
- semantic-cluster dependence;
- request-randomness and realization heterogeneity;
- terminal-no-code and Oracle-unknown rates;
- the minimum scientifically important effect;
- the number of selected hypotheses and all primary contrasts; and
- the frozen max-|T| multiplicity procedure.

The simulation reports power and interval width for each selected hypothesis's
actual eligible cluster set. A total pool of 240 cannot rescue a hypothesis
with sparse applicability. If the target design is insufficient, the study
must acquire more eligible clusters, reduce the prospectively selected
hypothesis family, or report that confirmation is not supported. It cannot
change the denominator, combine incompatible strata, or continue sampling in
response to the observed effect.

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
-> stratified cluster sampling with a fixed seed
-> task, split, hypothesis-eligibility, and arm manifests frozen
-> confirmatory generation authorized
```

The final freeze must publish counts by layer, family, leaf CWE, language,
granularity, source lineage, functional-contract type, Oracle profile, and
eligibility status; all excluded and unresolved candidates remain counted with
typed reasons.

The planned design is accepted only when:

- all 240 core, 28 memory, and 28 backend targets are either filled by eligible
  independent clusters or a prospective shortfall amendment is documented
  before outcomes;
- the primary hypothesis-specific power gate passes;
- development, calibration, and all scientific layers are cluster-disjoint;
- source-lineage caps and family diversity constraints pass;
- every admitted task has a functional contract and calibrated Oracle profile;
- the assignment budget is recomputed from the frozen hypothesis and arm
  manifests; and
- no selector, generator, Judge, Oracle, or historical per-task outcome was
  consulted during admission or sampling.

Until those conditions pass, this document specifies the intended study design
but does not authorize a confirmatory run or a paper claim that the final
dataset has been frozen.
