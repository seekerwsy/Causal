# Functional Oracle and realistic underspecification

Date: 2026-09-11. Initial status: **assessment and proposed revision**. The
assessment below describes the pre-revision behavior; the subsequent authorized
prototype change is recorded at the end. No generated-model outcomes or external
calls were used. Formal measurement remains unqualified and inactive.

## Finding

The strongest evidence of over-conservatism is the deterministic source-scope
gate, not an observed error rate of the LLM judge. `functional_source_scope`
maps the source's insufficient label to partial scope. `measure_generated_code`
then returns functional unknown immediately for any valid code whose scope is
not complete. It never asks the functional judge to inspect that code.

The frozen broad pool contains 1,207 non-complete specifications among 1,995
tasks (60.5%). Under that measurement path, these task inputs cannot produce a
functional pass or fail for syntactically valid code. This is a consequence of
the implementation, not 1,207 observed failed or unknown model generations.
Their recent inclusion in the source pool did not remove this measurement gate.

## Subsequent authorized prototype change

The author then asked to remove the front gate. `measure_generated_code` now
calls the blinded functional judge for every syntax-valid program. Source scope
remains descriptive request/evidence metadata, not an automatic unknown. Missing
summaries are allowed; an inapplicable parent summary and its dependencies are
withheld, while the original source task remains visible. Raw security findings,
arm and generator identity are not added to the functional request.

The prospective Flash configuration now selects
`data/functional-judge/prompts/functional-oracle-task-relative.txt`, SHA-256
`f750e2fe095e1a40a5d8dc9b6ee959231e99e38082e2b0f64d4a7085dc3adbb4`.
It permits reasonable implementation freedom, requires assessable material
requirements for whole-task pass, preserves demonstrated failure even when other
requirements are unknown, and requests a specific reason for unresolved judgments.
The original prompt and all frozen judgments are preserved. The result verifier
replays pre-revision records under their original source-scope rule. Qualification
remains pending; no corpus rescoring or provider calls were performed.

Validation used the existing Python 3.12.13 reviewer environment at
`.tmp/sequential-source-review-20260909/final-reviewer-env`, explicitly importing
the current source tree. The 70 workflow/inference cases passed, including all
nine language adapters, all three source scopes and verdicts, empty/inapplicable
summaries, terminal-code behavior, independent security outcomes and tamper
rejection. The four functional-judge checks passed after shortening the prompt
to satisfy the existing compact-prompt check. These are controlled responses,
not measurements of LLM accuracy.

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$reviewPython = '.tmp/sequential-source-review-20260909/final-reviewer-env/Scripts/python.exe'
& $reviewPython -m pytest tests/test_target_workflow.py tests/test_target_inference.py tests/test_functional_judge_gate.py -q -o addopts= -p no:cacheprovider --basetemp=.tmp/function-review-gate-tests-new
& $reviewPython -m prompt_mechanism_study.cli study smoke .tmp/function-review-gate-smoke-new
& $reviewPython -m prompt_mechanism_study.cli study verify-result .tmp/function-review-gate-smoke-new
```

The executed smoke is `.tmp/function-review-gate-smoke`: seven stages, 80
assignments/measurements/outcomes, zero provider calls. Both its independent
verification and read-only verification of the existing
`.tmp/sequential-source-review-20260909/final-reviewer-smoke` passed. Their frozen
scientific output bundle is identical:
`3c63bb76176af0f344b40cab8e388917005a9d7895e7e57d29e9afcb7a8e073e`.
Both remain `NON_CLAIM_TEST_ARTIFACT`; no formal result or new installed release
is claimed. The assessment and larger calibration proposal below remain context;
they were not expanded into another qualification campaign by this change.

The judge prompt itself assumes declared dependencies and valid inputs are
available, asks for control/data-flow inspection, and uses pass/fail/unknown.
It does not demand a unique implementation. Source-review instructions also
say implementation freedom is not insufficiency, but several actual judgments
appear stricter than this principle. A revised rubric must make that boundary
concrete rather than merely tell the judge to be more lenient.

## Observed examples and local diagnosis

Three source examples illustrate different situations:

| Example | Observation | Proposed treatment |
|---|---|---|
| JavaScript array shuffle | Source asks for a randomized shuffle and returned array; review cites unspecified algorithm, RNG, bias requirement, and mutation/copy choice. | Accept reasonable choices where unconstrained. Inspect preservation of elements and multiplicities, an actual shuffle, and the returned array. Do not require a named algorithm or particular mutation behavior absent a source constraint. |
| Python SQLite row counts | Counting, SELECT usage and two error conditions are explicit, but database connection context is absent. | Judge visible logic under a declared, shared environment assumption. Actual runtime success needs an appropriate fixture; arbitrary invented interfaces or schemas cannot be excused as available dependencies. |
| `jwt_decode(payload)` | Source says to decode a payload into a JWT; transformation direction and representation are unclear. | Preserve unknown for the unresolved core transformation. Do not choose encode/decode after seeing an implementation. |

These exact task IDs, prompt hashes and near-duplicate groups are recorded in
`configs/formal/qualification_data_manifest.json` under
`additional_method_development_exposures`. They were used to develop the
assessment and must remain outside future QUAL_ACCEPT, Discovery and Confirmation
roles. This adds no formal role assignment and does not rewrite a frozen pool.

A zero-network, synthetic control-flow probe supplied two programs for the
request to sum supplied numbers: one returns `sum(items)`, the other always
returns zero. A fixed offline judge supplied pass/fail when invoked. With
complete scope, the measurement path invoked it and retained pass/fail. With
partial scope, both became unknown and the judge was not invoked. This verifies
the gate's behavior only; it is not evidence of any LLM's accuracy.

## External comparison

[SWE-bench](https://proceedings.iclr.cc/paper_files/paper/2024/hash/edac78c3e300629acfe6cbe9ca88fb84-Abstract-Conference.html)
provides a repository together with the issue description. Its realism does not
depend on the prompt alone restating all project context.
[SWE-bench Verified](https://openai.com/index/introducing-swe-bench-verified/)
distinguishes small gaps with a sensible success interpretation from material
ambiguity. Its acceptable annotation level includes the former, and its test
review checks whether reasonable correct solutions would be rejected.
[CWEval](https://arise-lab.github.io/cweval-bench/) deliberately provides clear
signatures/specifications and checks basic functionality separately from security
on adversarial inputs. These are different evaluation settings; importing a
fully specified function-benchmark requirement into every natural task can alter
the population being studied. That last implication is our methodological inference.

## Proposed minimal revision

1. **Separate specification detail from functional evaluability.** Retain the
   historical source-quality judgment as descriptive metadata. A task can omit
   implementation details while still having adequate observable acceptance
   criteria. Evaluate all material requested functional behavior, including
   semantically necessary constraints, without adding preferred algorithms,
   security best practices, production hardening or unstated edge cases.
2. **Declare permitted freedom and environment assumptions before outcomes.**
   Use original visible context and ordinary language/API contracts. Any supplied
   fixture or assumption must be documented and shared across arms. If different
   assumptions change the requested operation, input/output meaning, trust
   boundary or expected side effects, the uncertainty is material. Do not resolve
   it differently for different generated programs.
3. **Inspect incomplete tasks instead of preemptively assigning unknown.** A
   demonstrated violation of an explicit requirement supports fail even if some
   other requirements remain uncertain. Pass requires sufficient evidence for
   the whole task-relative functional contract. If all assessed requirements
   pass but a material requirement remains unevaluable, whole-task status stays
   unknown; subset success is diagnostic only. Ordinary implementation freedom
   alone is not such an unknown.
4. **Make unknown reasons specific.** Distinguish missing material source
   semantics, missing environment evidence and inability of the evaluator to
   resolve the code. Preserve a reference to the affected requirement. Do not
   replace unknown with pass merely to enlarge the evaluable sample.
5. **Calibrate both wrongful rejection and wrongful acceptance.** On already
   exposed development material, use a bounded set of equivalent valid solutions,
   clear omissions/defects, environment-dependent examples and truly ambiguous
   cases. Measure false fail and unnecessary unknown as well as false pass.
   Include plausible security-preserving rewrites so complexity or code style
   cannot systematically favor one arm. Keep the selected model policy and
   accuracy requirements; freeze the revised rubric before independent acceptance.

No new primary endpoint is proposed. The primary safety outcome remains
oracle-evaluable secure-code yield, with functionality and joint success separate.
All assigned tasks remain in ITT, and evaluator uncertainty cannot filter the
denominator. Functional pass under the revised contract would be task-relative
evidence, not a proof of production readiness or all-input program correctness.

Implementation would affect the existing source-scope interpretation, the
functional judge instructions, the early return in measurement, independent
verification and their focused invariants. Old source labels, code measurements
and qualification artifacts retain their original policy. The proposal does not
authorize relabeling all 1,207 sources, silently inheriting old qualification,
or claiming that the new rubric has been implemented or empirically qualified.
