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
- mechanism-binding result:
  `aa270c7fb9cdc8f32417ee1a7c9d83dcdcf9ab80739cd9cec2b8e82b6da617ed`;
- final quality-data bundle:
  `b0800bac8f6e3f0ed61cff2b111cf04e901597d06d77352993590ef9e043fef3`;
- eligibility policy:
  `29acf991090278a109b23ea358342f4e266e24d2153409abf594a25fddbed17e`;
- eligibility implementation:
  `src/prompt_mechanism_study/eligibility.py`, SHA-256
  `41d6957cbb7e6e57e520af2c4007338460e92aa7562a0a346718f384b373a34b`;
- curation implementation:
  `src/prompt_mechanism_study/curation.py`, SHA-256
  `4a28c79e45e7accf5f3124cf4bd439d8f2b5ce04835916c7b684447b855d3a6d`;
- BaxBench source-tree snapshot:
  `d438c3c484e352a74f34ab0f177c2f9dfd0cea418f995712eee79d6e31624ae2`.

The active local paths are:

- `.codex-runtime/mechanism-binding-review-f2f115f-20260831-01`;
- `.codex-runtime/contract-recovery-adjudication-20260831-10`;
- `.codex-runtime/dataset-final-quality-20260831-14`.

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
prompt, zero unknown realization IDs, and zero accepted profiles outside the 12
qualified local profiles.

Both new deterministic stages reproduced byte-for-byte: the contract-recovery
bundle digest was
`6df47b0ce9f9a5a02d91a94323c5a12fa56472101e77761f5856994897700be0`
on both builds, and the successor candidate-ledger digest was
`b0800bac8f6e3f0ed61cff2b111cf04e901597d06d77352993590ef9e043fef3`
on both builds.

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
| `READY_CONFIRMATORY` | 150 | strict contract, supported Python runtime, registered mechanism, qualified local Security Oracle |
| `PENDING_CONTRACT` | 930 | contract quality/evaluability gate not met |
| `PENDING_ORACLE` | 260 | mechanism or task-applicable Security Oracle not frozen |
| `PENDING_RUNTIME` | 174 | non-Python execution/measurement runtime not qualified |
| `PENDING_BINDING` | 21 | registered mechanism shape remains unresolved |
| `PENDING_INDEPENDENT_REVIEW` | 21 | development exposure or known diagnostic concern |
| `PENDING_SCOPE` | 603 | outside the currently registered research families |
| `EXCLUDED_SOURCE_DEFECT` | 6 | internally incoherent prompt as written |

The 150 ready Python task units span seven source lineages and ten CWEs. Family
coverage is 38 injection/interpreter, 59 file/parser/resource, 17
identity/permission, and 36 cryptography/randomness task units. Lineage count
and share are diagnostics rather than admission gates, so all 150 remain
eligible on task quality. The largest ready lineage is CyberSecEval at 54/150
(36.0%). No family reaches the prospective target of 60; that count shortfall,
not lineage composition, keeps the 240-task Python population gate closed.

## Oracle choice by layer

1. **Python core:** one of 12 qualified deterministic static profiles is bound
   before assignment. The same profile is used for all arms; `unknown` is
   preserved. These profiles have 37 secure/insecure/unknown gold fixtures in
   the existing qualification bundle, but that boundary is not a global CWE
   accuracy claim.
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
Of these, 150 are ready, 21 need only a frozen binding decision, and most of the
remainder need a registered mechanism plus a qualified task-applicable Oracle.

The implementation order is therefore:

1. resolve the 21 existing finite-registry binding cases;
2. qualify only locally measurable missing profiles, beginning with bounded
   code-execution and cryptographic API cases rather than contextual Web policy;
3. make a prospective population decision for the identity family, whose 48
   quality-qualified tasks cannot meet a target of 60 even with perfect
   implementation support;
4. implement non-Python runtimes only for a separately claimed replication.

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
closed. The next scientific choice is not another curation pass. It is a
prospective measurement-population decision: extend only defensible Oracle
coverage, add an outcome-blind identity-family scope extension or new tasks, or
freeze a documented shortfall amendment and power the study on the measurable
population.
