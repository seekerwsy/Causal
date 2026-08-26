# Factorial SQL confirmation v3 results

**Evidence type:** newly run formal confirmation  
**Study:** `factorial-sql-confirm-qwen35-v3`  
**Execution commit:** `e72fd24`  
**Execution date:** 2026-08-27  
**Result bundle:** `data/formal/results/factorial-sql-confirm-qwen35-v3`  
**Downloaded archive SHA-256:**
`6d48facfc5d50da3ff21d94c71beb3f33153d26b830cdac826e4f160a8d217e2`

## Evidence boundary

This run is the prospectively frozen confirmation of one registered pair on a
controlled Python DB-API mechanism-response corpus. It estimates the assigned-cell
policy effects of adding:

1. SQL value parameterization; and
2. finite-domain control of a caller-selected SQL identifier.

It is not a representative sample of all CWE-89 prompts or programming tasks. The
pair was selected from the reviewed mechanism registry after the observational
support gate failed; it was not discovered by FCI. The result cannot establish a
universal interaction between the two mechanisms because the qualified security
endpoint itself requires both controls.

## Frozen design

- 30 task units, selected without consulting confirmation outcomes;
- one generation model: `qwen3.5-flash-2026-02-23`;
- two frozen operator orders;
- four complete-block cells per task unit and order;
- 240 total assignments;
- static profile `python.cwe89.dynamic_identifier_and_values.v2`;
- blinded Qwen3.7-Max Functional Judge after Python AST/compile validation;
- assigned-cell, equally weighted task-unit ITT;
- two-sided secure-yield interaction as the primary estimand;
- 5,000-draw max-|T| task-unit bootstrap at familywise alpha 0.05;
- practical interaction margin 0.10, maximum unknown fraction 0.10, and
  A11-versus-A00 functionality non-inferiority margin 0.10.

The frozen corpus digest is
`c680a851181d8cc3f79d1013d8290c94878689141364de8b9b20dbd7ef58fcf8`.
The Oracle qualification used eight gold programs, two per cell, with zero label
mismatches. Its support is limited to direct Python DB-API calls using admitted
literal-map or dominating finite-domain membership guards.

## Execution and verification

The run executed on Linux with Python 3.12.13 on an NVIDIA A800 host. Provider
credentials were inherited in process and were not written to the artifact.
`PYTHONDONTWRITEBYTECODE=1` was set, and the deployment was checked for generated
bytecode after execution.

All 240 assignments reached terminal measurement records. The generic bundle
hash verifier passed on the remote host and again after download. The independent
factorial verifier, which does not import the production estimator, reported:

```json
{"assignments":240,"coordinates":5,"primary_intervals":1,"secondary_intervals":3,"status":"FACTORIAL_INFERENCE_VERIFIED"}
```

## Results

| Cell | Secure yield | Code valid | Oracle evaluable | Functionality |
| --- | ---: | ---: | ---: | ---: |
| A00: neither target | 58/60 (96.7%) | 60/60 | 60/60 | 60/60 |
| A10: value parameterization | 58/60 (96.7%) | 60/60 | 60/60 | 60/60 |
| A01: identifier control | 59/60 (98.3%) | 60/60 | 60/60 | 59/60 |
| A11: both targets | 59/60 (98.3%) | 60/60 | 60/60 | 59/60 |

The secure-yield estimates were:

- factor 1: `0.0000`;
- factor 2: `+0.0167`;
- joint A11-A00: `+0.0167`;
- primary interaction: `0.0000`;
- simultaneous interaction interval: `[-0.0833, +0.0833]`.

The max-|T| secondary intervals were:

- factor 1: `[-0.0833, +0.0833]`;
- factor 2: `[-0.0594, +0.0928]`;
- joint: `[-0.0594, +0.0928]`.

No security interval excluded zero, and the primary interaction did not meet the
0.10 practical margin. Oracle evaluability was 100%, so unknown bounds equal the
observed estimates. The functionality contrast A11-A00 was `-0.0167`, which passed
the frozen `-0.10` non-inferiority gate. The formal primary claim gate therefore
failed because the security significance and practical-effect conditions failed,
not because of missing assignments, Oracle coverage, or functional collapse.

## Case-level diagnosis

The no-target cell already implemented both controls in 58 of 60 assignments.
Across all cells, value parameterization was nearly universal and finite-domain
identifier control was also common without a target instruction. The few failures
were concentrated in three task instances (`browse_invoices`, `find_employees`,
and `update_settings`) rather than spread across the population.

The source tasks state that the identifier is chosen from a finite domain. The
generation model generally inferred value parameterization and identifier validation
from that functional context even in A00. This creates a severe baseline ceiling and
weak treatment positivity: the experiment has little room for the added requirements
to change the measured outcome. Increasing the same sample or selecting only the
three responsive tasks would not repair that design problem.

## Interpretation and successor boundary

This is a valid formal null result on the frozen controlled corpus. It does not show
that prompt mechanisms never affect code generation; it shows that the two added
requirements produced no detectable or practically large improvement when a capable
model generated code from scratch under a task prompt that already made the finite
identifier domain salient.

A distinct prospective follow-up may study repair of an explicitly vulnerable starter
implementation. It must retain all task units, freeze new prompt identities and a new
estimand before generation, and preserve this v3 result unchanged. A favorable repair
result would establish context-conditioned repair-policy response, not retroactively
convert v3 into a positive confirmation or prove universal mechanism synergy.
