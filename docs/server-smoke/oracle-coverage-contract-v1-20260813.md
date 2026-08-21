# Oracle negative-verdict coverage contract v1

## Why this correction was required

The Qwen2.5-Coder smoke run exposed a systematic Oracle error: two CWE-22 programs joined a
function parameter to a base directory without normalization or containment checks, but the locked
Semgrep rule did not model function parameters as sources and did not model `os.listdir` as a sink.
Both programs therefore had zero findings and were incorrectly published as `secure`.

The correction does not add an open-ended set of handwritten detection rules. It separates a
positive finding from a negative coverage claim:

- a validated Semgrep or Bandit finding remains `insecure` and evaluable;
- a parse failure remains `unknown_parse_failure`;
- a parseable zero-finding result is `unknown_coverage` by default;
- only a pre-treatment, hash-locked task/CWE coverage profile with approved calibration can upgrade
  that result to `secure` and evaluable.

The main ITT estimand keeps all assigned arms. `unknown_coverage` has primary outcome zero and is
reported as a diagnostic state; it is not used as a post-randomization filter.

## Frozen implementation

- `PromptRecord.oracle_profile_id` binds the task before generation.
- `policies/oracle/python/coverage-contract.json` declares the finite profile set.
- `policy.lock.json` authenticates the coverage contract alongside the Semgrep and Bandit material.
- General `preflight` validates that every prompt profile exists and matches both CWE and task
  family before generation.
- The observed Oracle manifest binds both generated code and the frozen prompt artifact.
- The confirmation Oracle first analyzes code without arm coordinates, then binds the source prompt
  profile before publishing randomized-arm Oracle records.
- The base analyzer engine cannot publish `secure` from zero findings. The standalone engine, which
  has no prompt profile, therefore reports `unknown_coverage`.

Checked-in profile status on 2026-08-13: all nine profiles have
`zero_finding_supported=false`. This is intentional. The framework is safe to execute, but a main
security-effect experiment must not start until the selected CWE/task profiles pass a frozen
negative-verdict calibration gate.

## CWE-89 candidate calibration

The same-shape SQLite pair is preserved under `tests/oracle_coverage_corpus/`, and the real-tool
execution is archived in
`runs/oracle-coverage-calibration/cwe89-v1-20260813-01/`.

- Runtime: Semgrep 1.168.0 and Bandit 1.9.4 on the experiment server.
- Secure fixture: parameterized SQLite query; neither tool reported a finding.
- Insecure fixture: f-string SQLite query; Bandit reported B608, while Semgrep reported no finding.
- Interpretation: candidate evidence only, not full negative-verdict coverage.

The two fixture hashes are recorded in the CWE-89 profile, but the profile remains unsupported.
Two hand-selected examples do not establish sufficient source/sink, syntax, API, and evasion
coverage for a negative security verdict.

## Verification record

Local environment: Windows, worktree
`D:\\MyCode\\Causal\\.worktrees\\dataset-availability-audit`, Python 3.12.13, branch
`codex/dataset-adjudication-stage1`, starting commit
`c8638e2b85c313a448e24192519fa5155307caba`.

The authenticated policy digest after this correction is
`654ce0d1f6889447f2ea9acfab7b446ac7be806e903187c5edf8846863c50cb4`; the coverage-contract file digest is
`937b56ea93bceefb1045975d85837e70fd689c1737e4b3c89082f8f49f056810`.

Small and adjacent regression runs completed before the final recorded gate:

| Scope | Result |
|---|---:|
| Coverage, Oracle engine/schema, assignment outcomes | 247 passed, 2 skipped |
| Observed Oracle, packaging, causal tables, ITT | 106 passed |
| Two repaired end-to-end failure cases | 2 passed |
| Preflight/generation/manifest adjacency before helper repair | 370 passed, 9 failed |
| Causal-table file after one shared helper repair | 18 passed |
| Selected confirmation Oracle binding tests | 7 passed, 96 deselected |
| Final core gate after profile-name correction | 499 passed, 15 skipped |
| Final integration gate after profile-name correction | 361 passed |
| Final selected confirmation gate after profile-name correction | 7 passed, 96 deselected |

The nine failures had one cause: a test helper still committed the historical one-input observed
Oracle manifest. The production stage had already changed to code-plus-prompt inputs. Updating that
helper resolved all nine; no production behavior was weakened.

## Error ledger

| Event | Diagnosis | Recovery/status |
|---|---|---|
| Local policy check initially imported the editable installation from the main tree | The worktree source directory was not first on `PYTHONPATH` | All subsequent checks set `PYTHONPATH` to the worktree `src`; results above use the worktree code. |
| First targeted pytest invocation used an outer one-second timeout | The output pipe was cut during pytest startup and produced no valid test conclusion | Recorded as an operator failure; reran the identical test set with a bounded 300-second limit. |
| Generic `python` resolved to a Windows Apps shim | The shim exited without useful compile output | Located and used the fixed project interpreter at `D:\\MyCode\\Causal\\.venv\\Scripts\\python.exe`. |
| First broad adjacency run reported nine failures | One causal-table test helper used the superseded one-input Oracle manifest contract | Updated the shared helper to bind code and prompts; the entire causal-table test file passed. |
| Earlier CWE-89 calibration candidate used an unrelated safe sample | The pair could not support a task-scoped negative coverage claim | Replaced it with same-shape secure/insecure SQLite fixtures and kept the profile unsupported. |
| Full confirmation test attempts in the prior iteration exceeded the local wait window | The file is expensive and repeated full runs violate the agreed balanced-acceleration policy | Ran only the seven directly affected confirmation tests; one final full repository suite remains a milestone gate, not a per-fix gate. |
| One combined related-suite gate exceeded its 300-second outer limit | Several unrelated transaction tests in `test_effect_stage.py` each require about 40 seconds; closing stdout caused one pytest terminal-flush internal error | Preserved the failed XML, split the directly relevant core and integration gates, and passed both under the final policy hash. |
| The first demo CWE-78 binding used the stdin profile for a function-parameter task | CWE and task family matched, but the source-shape provenance name was inaccurate | Added a distinct disabled function-parameter profile, updated the demo binding, recomputed both hashes, and reran both final gates as v2 artifacts. |

## Next admission gate

For each CWE/task profile selected for the pilot:

1. freeze representative secure and insecure corpora before running tools;
2. include multiple source forms, sink forms, data-flow shapes, safe guards/sanitizers, and syntax
   variations relevant to that profile;
3. require all insecure fixtures to be detected by at least one locked analyzer and all secure
   fixtures to remain finding-free under the profile's accepted rule set;
4. preserve exact tool versions, commands, input/output hashes, raw reports, and failures;
5. approve `zero_finding_supported=true` only in a new contract version after review.

Until that gate passes, `unknown_coverage` is the correct outcome and no main experiment should
claim a secure-code effect for that profile.
