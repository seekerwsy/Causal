# Final Candidate-Data Audit (Outcome Blind)

## Scope

This audit completes the data-preparation path requested before any new
generation experiment. It does not freeze assignments, inspect generated code,
or establish an intervention effect. Every admission decision uses only source
records, conservative task units, repaired functional contracts, blind contract
reviews, registered mechanism realizations, source-native tests, and frozen
Oracle qualifications.

## Evidence inventory

| Evidence | Evidence type | Role |
| --- | --- | --- |
| Seven-source prepared corpus, 2,283 rows | `preexisting_artifact` | source inventory |
| Conservative task units, 2,165 units | `preexisting_artifact` | independent sampling coordinates |
| Repaired functional contracts, 2,165 contracts | `preexisting_artifact` | task semantics |
| Complete blind contract review, 2,165 reviews | `preexisting_artifact` | contract quality/evaluability |
| Targeted outcome-blind contract adjudication, 17 cases | `newly_run` | correct contradictory reviews and bounded contract faults |
| Blind mechanism-binding run, 220 task units | `newly_run` | resolve finite registered task shapes |
| Unified 2,165-row candidate ledger | `newly_run` | final data status and blockers |
| Quality-qualified final dataset, 1,217 task units | `newly_run` | all tasks meeting the frozen data-quality rule, independent of implementation support |
| BaxBench 28-scenario source audit | `newly_run` | backend replication inventory |

No row is an `user_claim`, and no experimental outcome was used.

## Frozen identities

- prepared corpus bundle:
  `c391c7a13603542e5edd725dcc4018b4abaae0bfaa75177067561a166f7816d4`;
- conservative task-unit bundle:
  `88e22630523f571070be6427d91ad34106c72343ccdfed1b584da3790eccd263`;
- response-format-repaired contract bundle:
  `1b081f1f693fdd68ab1cf14c1caf42f91afa35372f844d8addae64860111e894`;
- adjudicated successor contract bundle:
  `6df47b0ce9f9a5a02d91a94323c5a12fa56472101e77761f5856994897700be0`;
- complete contract-review bundle:
  `137f94f6b629585f60308d927496b4ae980bd4b8e1efcadc50ebbb71478623cc`;
- mechanism-binding plan:
  `f2f8556a4fad016413aa0f4585f4769ea81b0fa11bc2632c2e32a159cb77690e`;
- adjudicated mechanism-binding bundle:
  `089ac31dd29bb5ba89a4ba5dcd4776f8f6ad2c1e871bf3629d9f0ae59f8eef19`;
- qualified local Security-Oracle implementation:
  `6286a2f091322b90bc7b9af28b5aafd1078d9dbe3a4a219a7af9afa19cbd634c`;
- target Security-Oracle qualification bundle:
  `fc4216dc7cb6e8f8e0377e69e300bded30485f1725b7d855504adab3b396ab75`;
- schema-3 mechanism registry:
  `data/method/phase-context-policy-v3-mechanism-registry-v1.json`, SHA-256
  `bff8b78e67520725d7cdd644b77ad7c2d6df64531bee0479a2c08ba9d1874970`;
- schema-3 target eligibility policy:
  `data/dataset-curation/phase-context-policy-v3-eligibility-policy-v1.json`,
  SHA-256
  `8d8401ad3c1a45b295d4febdef8a5fb3f524e11b88f28e7a447afcd0b97792fb`;
- current final quality-data bundle:
  `64f1241574197ad17e64ae547c9dc611ff01add2ec2393ae2c8ba420d4f8136c`;
- eligibility implementation:
  `src/prompt_mechanism_study/eligibility.py`, SHA-256
  `5f14e0fc00fff9b02f06c033632d31a5892e00d389164e99843440127681b8e8`;
- curation implementation:
  `src/prompt_mechanism_study/curation.py`, SHA-256
  `4a28c79e45e7accf5f3124cf4bd439d8f2b5ce04835916c7b684447b855d3a6d`;
- BaxBench source-tree snapshot:
  `d438c3c484e352a74f34ab0f177c2f9dfd0cea418f995712eee79d6e31624ae2`.

The active local paths are:

- `.codex-runtime/mechanism-binding-adjudication-20260831-19`;
- `.codex-runtime/contract-recovery-adjudication-20260831-10`;
- `data/oracle-calibration/phase-context-policy-v3-security-profiles-v1-qualification`;
- `data/method/phase-context-policy-v3-mechanism-registry-v1.json`;
- `data/dataset-curation/phase-context-policy-v3-eligibility-policy-v1.json`;
- `.codex-runtime/dataset-final-quality-20260831-38-schema3-registry-bound`.

The earlier `dataset-final-quality-20260831-36-target-oracle-final` bundle is
retained as development history but superseded because its policy pointed at
the legacy registry path after adding target-only realizations. The corrected
audit binds the same registry bytes under a prospective schema-3 path; its two
independent replays are byte-identical and its substantive task counts are
unchanged.

## Contract closure

Every task unit has one current contract and one traceable blind review. The 71
response-format-only defects were removed through explicit old/new contract
lineage. After that deterministic repair, 1,215 contracts satisfied the strict
conjunction:

```text
faithful AND functionally sufficient AND no remaining deterministic issue
```

The targeted recovery pass then reviewed all 17 faulty+sufficient Python tasks
that already had mechanism, Oracle, and runtime support. Eight frozen reviews
were self-contradictory or stale, six contracts needed bounded corrections, and
three source tasks remained inconsistent or metadata-misaligned. This yields
1,229 strict and 936 repairable contracts. Limited or insufficient prompts were
not expanded merely to increase sample size.

## Blind mechanism binding

The deterministic registry matcher left 220 task units ambiguous or unresolved.
Qwen3.7-Max reviewed them in 44 closed batches of at most five items. Each request
contained only the source prompt, repaired functional contract, and same-CWE
finite registry candidates.

- 86 task units received a registered realization backed by a qualified local
  profile;
- 2 matched a registered contextual realization whose local Oracle remains
  unsupported;
- 132 remained not applicable or unresolved;
- 85 accepted evidence anchors were exact model copies;
- 3 were deterministically projected to a strong contiguous source-prompt span;
- 2 weak evidence candidates were downgraded to unresolved.

An independent replay found zero accepted evidence spans absent from the source
prompt, zero unknown realization IDs, and zero accepted profiles outside the 14
qualified local profiles.

The deterministic stages reproduced byte-for-byte: the contract-recovery
bundle digest was
`6df47b0ce9f9a5a02d91a94323c5a12fa56472101e77761f5856994897700be0`
on both builds, the adjudicated binding digest was
`089ac31dd29bb5ba89a4ba5dcd4776f8f6ad2c1e871bf3629d9f0ae59f8eef19`,
and the current candidate-ledger bundle digest was
`64f1241574197ad17e64ae547c9dc611ff01add2ec2393ae2c8ba420d4f8136c`
on both builds. The binding adjudication resolved 6 of the prior 21 cases and
conservatively retained 15 as unresolved.

## Unified candidate status

The final ledger contains exactly 2,165 unique task units:

| Final-dataset disposition | Task units | Meaning |
| --- | ---: | --- |
| `INCLUDED_FINAL_DATASET` | 1,217 | strict contract and no unresolved quality flag |
| `PENDING_INDEPENDENT_REVIEW` | 12 | strict contract but a diagnostic quality concern remains |
| `PENDING_QUALITY_REPAIR` | 930 | contract is not yet faithful and sufficient under the frozen rule |
| `EXCLUDED_SOURCE_DEFECT` | 6 | incoherent source prompt |

This is the paper-facing data boundary. Mechanism, Oracle, runtime, language,
current scope, lineage, and development exposure do not remove a
quality-qualified row from the final dataset. They determine only whether that
row can be measured in a particular study. The final dataset contains 558
Python, 151 C, 102 C++, 121 JavaScript, 91 C#, 66 Java, 58 Rust, 53 PHP, and 17
Go task units.

The separate execution-readiness classification is:

| Status | Task units | Meaning |
| --- | ---: | --- |
| `READY_CONFIRMATORY` | 164 | strict contract, supported Python runtime, registered mechanism, qualified local Security Oracle |
| `PENDING_CONTRACT` | 930 | contract quality/evaluability gate not met |
| `PENDING_ORACLE` | 209 | mechanism or task-applicable Security Oracle not frozen |
| `PENDING_RUNTIME` | 174 | non-Python execution/measurement runtime not qualified |
| `PENDING_BINDING` | 58 | a registered same-CWE mechanism exists but its narrow task shape is not established |
| `PENDING_INDEPENDENT_REVIEW` | 21 | development exposure or known diagnostic concern |
| `PENDING_SCOPE` | 603 | outside the currently registered research families |
| `EXCLUDED_SOURCE_DEFECT` | 6 | internally incoherent prompt as written |

The 164 ready Python task units span seven source lineages and thirteen CWEs.
Family coverage is 45 injection/interpreter, 60 file/parser/resource, 17
identity/permission, and 42 cryptography/randomness task units. Lineage count
and share are diagnostics rather than admission gates, so all 164 remain
eligible on task quality. The largest ready lineage is CyberSecEval at 57/164
(34.8%). The file/parser family now reaches 60; the other three count
shortfalls, not lineage composition, keep the 240-task Python population gate
closed.

## Oracle choice by layer

1. **Python core:** one of 14 qualified deterministic static profiles is bound
   before assignment. The same profile is used for all arms; `unknown` is
   preserved. These profiles have 43 secure/insecure/unknown gold fixtures in
   the existing qualification bundle, but that boundary is not a global CWE
   accuracy claim. The two new profiles live in the target-schema producer,
   which delegates the original 12 profiles without changing their frozen
   implementation identity.
2. **C/C++ memory replication:** the data pool contains 102 strict,
   independently reviewable candidates and at least four for each of the seven
   planned CWEs. Only six currently reference source tests. Formal admission
   still requires compilation, a frozen functional test, and task-applicable
   ASan/UBSan or exploit checks. No Python static profile substitutes for this
   layer.
3. **BaxBench backend replication:** all 28 source scenarios are inventoried.
   They define 34 functional tests and 70 security tests across 14 dependent
   framework realizations. Their primary Oracles are those source-native
   executable tests, but all 28 profiles remain
   `PENDING_RUNTIME_QUALIFICATION` until a frozen Docker replay passes and one
   framework realization per scenario is frozen outcome-blindly.

Functionality evidence remains separate: source-native executable tests are
preferred where available; Python tasks without them use AST/compile validity
plus the frozen blind LLM plausibility Judge and cannot be described as proven
functional correctness.

## Priority extensions

The ledger retains 207 source-tested extension candidates: 113 Python mechanism
extensions and 94 C/C++/Go/JavaScript extensions. Of these, 89 and 80,
respectively, also have strict contracts. They remain `PENDING_ORACLE` or
`PENDING_RUNTIME`; the audit does not invent a profile merely to fill a quota.

## Measurement coverage next steps

Measurement support is not a final-dataset gate. It is needed only when a task
is sampled into an effect estimate. All 558 Python tasks already have runtime
support, so another Python runner is unnecessary. Within the 21 prospectively
listed Python CWEs, the final dataset contains 346 quality-qualified tasks:
132 injection/interpreter, 103 file/parser/resource, 48
identity/authorization/permissions, and 63 cryptography/randomness/integrity.
Of these, 164 are ready. The 58 `PENDING_BINDING` rows include the 15
conservatively unresolved prior cases plus newly recognized same-CWE tasks that
fall outside the narrow code-execution, certificate-validation, and cipher/hash
shapes. Most of the remainder still need a registered mechanism plus a
qualified task-applicable Oracle.

The completed extension resolved 6 existing binding cases and added only eight
quality-qualified READY units: two Python-literal dictionary tasks, two bounded
certificate-validation tasks, and four cipher/hash-selection tasks. Arbitrary
code execution, custom OpenSSL contexts, dynamic hash names, and contextual
identity policy remain non-ready rather than being forced through a broad
static rule.

The prospective Identity population decision is now frozen in
`data/dataset-curation/identity-family-scope-v1.json`. The former 60-task number
is a planning target, not an admission gate. All 48 quality-qualified Identity
tasks remain in the final data set and are partitioned without outcomes into:

- 17 `READY_CONFIRMATORY` tasks with qualified static profiles (CWE-732/798);
- 20 source-native safety-test candidates (5 CWE-200 and 15 CWE-862); and
- 11 contextual or incomplete-Oracle tasks (6 CWE-200 and 5 CWE-306).

The source-native audit is deliberately narrower than “a test file exists.”
The four accepted SeCodePLT CWE-200 tasks and five accepted SeCodePLT CWE-862
tasks expose explicit `capability` and `safety` partitions. The ten CWE-862 and
one CWE-200 CodeSecEval tasks contain concrete allowed/denied or
non-disclosure assertions, but require a frozen assertion split before they
can be a Security Oracle. A SALLM CWE-200 test was not accepted because its
vulnerability assertions expect leaked values to be present; the SALLM
CWE-306 snapshot has no executable test module. Neither was relabeled merely
to increase coverage.

The remaining implementation order is therefore:

1. qualify one task-bound executable Security Oracle for the 20 audited cases,
   keeping safety results separate from capability results;
2. review only bounded injection and crypto task shapes that can close their
   READY gaps with an honest Oracle;
3. implement non-Python runtimes only for a separately claimed replication.

The 659 non-Python final-dataset tasks remain valid data without those runtimes.
Building every language environment is not required for the Python primary
study and would not repair its identity-family population shortfall.

## Protocol risks and gate decision

- Mechanism binding is a single-model blind review, not human gold. Exact source
  anchors and conservative unresolved handling bound, but do not eliminate,
  semantic error.
- Contract quality is also based on a blind model review plus deterministic and
  targeted case audits. `STRICT` means the frozen audit criteria passed, not
  universal semantic correctness.
- Source lineage can encode shared templates or annotation conventions. It is
  retained for source-specific reporting and leave-one-lineage-out sensitivity,
  but an arbitrary count or percentage no longer rejects a qualified task.
- Static Python profiles may miss runtime vulnerabilities and can return
  `unknown`; source-native executable replication is therefore reported
  separately.
- The Python population, C/C++ runtime, and backend runtime gates are still
  closed. No confirmatory generation is authorized by this audit.

The data-preparation stage is complete: every source task has a typed
disposition, every quality-qualified task is in the final dataset, every
currently supported Oracle is explicit, and both replication inventories are
closed. The Identity shortfall decision is no longer open. The next step is a
bounded measurement qualification for the already identified 20 source-native
cases; it is not another corpus-wide curation pass and it does not authorize a
generation experiment by itself.
