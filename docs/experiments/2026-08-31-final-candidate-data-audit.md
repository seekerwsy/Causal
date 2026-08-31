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
| Blind mechanism-binding run, 220 task units | `newly_run` | resolve finite registered task shapes |
| Unified 2,165-row candidate ledger | `newly_run` | final data status and blockers |
| BaxBench 28-scenario source audit | `newly_run` | backend replication inventory |

No row is an `user_claim`, and no experimental outcome was used.

## Frozen identities

- prepared corpus bundle:
  `c391c7a13603542e5edd725dcc4018b4abaae0bfaa75177067561a166f7816d4`;
- conservative task-unit bundle:
  `88e22630523f571070be6427d91ad34106c72343ccdfed1b584da3790eccd263`;
- repaired contract bundle:
  `1b081f1f693fdd68ab1cf14c1caf42f91afa35372f844d8addae64860111e894`;
- complete contract-review bundle:
  `137f94f6b629585f60308d927496b4ae980bd4b8e1efcadc50ebbb71478623cc`;
- mechanism-binding plan:
  `f2f8556a4fad016413aa0f4585f4769ea81b0fa11bc2632c2e32a159cb77690e`;
- mechanism-binding result:
  `aa270c7fb9cdc8f32417ee1a7c9d83dcdcf9ab80739cd9cec2b8e82b6da617ed`;
- final candidate-data bundle:
  `32f7d0e18801de99a0bc670ae4c517792e8cfbc51f3bb294b204452bd3c2e442`;
- eligibility implementation:
  `src/prompt_mechanism_study/eligibility.py`, SHA-256
  `eb88d855c88a902e0b21770c65fd414d41c62307dadebdd0494ebf22daaf8444`;
- BaxBench source-tree snapshot:
  `d438c3c484e352a74f34ab0f177c2f9dfd0cea418f995712eee79d6e31624ae2`.

The active local paths are:

- `.codex-runtime/mechanism-binding-review-f2f115f-20260831-01`;
- `.codex-runtime/dataset-candidate-ledger-20260831-06`.

## Contract closure

Every task unit has one current contract and one traceable blind review. The 71
response-format-only defects were removed through explicit old/new contract
lineage. After that repair, 1,215 contracts satisfy the strict conjunction:

```text
faithful AND functionally sufficient AND no remaining deterministic issue
```

The other 950 remain in the ledger as `REPAIRABLE`; they are not silently
discarded and do not enter a formal denominator. This follows the prior decision
not to expand limited or insufficient contracts merely to increase sample size.

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

## Unified candidate status

The final ledger contains exactly 2,165 unique task units:

| Status | Task units | Meaning |
| --- | ---: | --- |
| `READY_CONFIRMATORY` | 136 | strict contract, supported Python runtime, registered mechanism, qualified local Security Oracle |
| `PENDING_CONTRACT` | 944 | contract quality/evaluability gate not met |
| `PENDING_ORACLE` | 260 | mechanism or task-applicable Security Oracle not frozen |
| `PENDING_RUNTIME` | 174 | non-Python execution/measurement runtime not qualified |
| `PENDING_BINDING` | 21 | registered mechanism shape remains unresolved |
| `PENDING_INDEPENDENT_REVIEW` | 21 | development exposure or known diagnostic concern |
| `PENDING_SCOPE` | 603 | outside the currently registered research families |
| `EXCLUDED_SOURCE_DEFECT` | 6 | internally incoherent prompt as written |

The 136 ready Python task units span seven source lineages and ten CWEs. Family
coverage is 35 injection/interpreter, 54 file/parser/resource, 15
identity/permission, and 32 cryptography/randomness task units. All families meet
the minimum lineage-diversity rule, but none reaches the prospective target of
60. The maximum ready sample under the 25% lineage cap is 116. Therefore the
240-task Python population gate remains closed.

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

## Protocol risks and gate decision

- Mechanism binding is a single-model blind review, not human gold. Exact source
  anchors and conservative unresolved handling bound, but do not eliminate,
  semantic error.
- Contract quality is also based on a blind model review plus deterministic and
  targeted case audits. `STRICT` means the frozen audit criteria passed, not
  universal semantic correctness.
- Static Python profiles may miss runtime vulnerabilities and can return
  `unknown`; source-native executable replication is therefore reported
  separately.
- The Python population, C/C++ runtime, and backend runtime gates are still
  closed. No confirmatory generation is authorized by this audit.

The data-preparation stage is complete in the narrower sense that every source
task has a typed disposition, every currently supported Oracle is explicit, and
both replication inventories are closed. The next scientific choice must be
made prospectively: acquire/qualify more tasks to retain the 240-task target, or
freeze a documented shortfall amendment and power the study on the actually
ready population.
