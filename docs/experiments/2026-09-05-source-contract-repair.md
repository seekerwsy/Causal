# Source-contract representation repair — 2026-09-05

## Scope and status

Author-approved development repair only. The active candidate is
`prompt-tsg-catalog-source-contract-v1.json` with v6 proposer/reviewer prompts.
Old catalogs, prompts, gold and failed runs are not overwritten. There is no
new compiler, rule engine, CLI command, retry policy or test framework.

The archive query composes input, extraction, destination and flow, excluding
an explicit member-trust guarantee. A trusted administrator alone is not that
guarantee. Feature presence is independent. Unspecified trust is not a claim
of attacker control. Existing consensus and evidence normalization are unchanged.

The source-only development review checked archive, SQL and command-execution
tasks before new extraction. The archive reference remains present under the
approved new definition, but its rationale no longer asserts attacker control.
Other context/realization labels and thresholds are unchanged. This was an
exposed review by the current agent, not new independent or human gold.
No QUAL_ACCEPT input or output is required for this repair.

## Bounded validation

The existing plan format is used in
`data/method/prompt-contract-source-contract-v1-plan.json`:
two schema-only calls on the old positive anchor, then 24 boundary calls and
56 full-development calls with the frozen new candidate. Contract/semantic
failures do not stop later development batches; provider failures stop later
batches. No hidden retry, candidate editing or selection of winning repetitions.

The per-call ceiling is conservatively enlarged to 32,768 input tokens
(including the task-specific Schema), with unchanged 4,096 output tokens.
The frozen repository pricing basis gives 9,831 micro-CNY per call after
rounding up, or CNY 0.806142 for at most 82 calls. This is conservative budget
accounting, not an invoice. Existing total authorization remains CNY 100.

Offline validation on Windows/Python 3.12.13:
`python -m pytest tests/test_prompt_contract.py tests/test_prompt_tsg.py -q -o addopts=`
passed 59 tests; the default reviewer suite passed 94 tests.
Only one parametrized archive-composition test was added; existing schema/parser
tests were extended. These supplied-fact tests do not test model accuracy.
The historical replay hash check now binds to its frozen implementation and is
outside the default reviewer suite.

## Exact remote execution

Use the plan's existing Python 3.12.11 image and remote credential file.
Mount the frozen deployment at `/work:ro`, its fresh output directory at
`/output`, set `PYTHONPATH=/work/src` and `PYTHONDONTWRITEBYTECODE=1`.
Credentials are supplied only with the existing remote `--env-file`; never
copy its contents. No package installation is needed.

The following is the execution code, not an additional repository runner:

```python
from pathlib import Path
import json
from prompt_mechanism_study.artifact_io import read_json, file_sha256, write_bundle
from prompt_mechanism_study.prompt_contract_extract import extract_contract_task_file, PromptContractExtractionError
from prompt_mechanism_study.prompt_contract_qualification import qualify_prompt_contract_extractor
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.records import canonical_json

root, out = Path("/work"), Path("/output")
m = root / "data/method"
plan_path = m / "prompt-contract-source-contract-v1-plan.json"
plan = read_json(plan_path)
for path, digest in plan["input_sha256"].items():
    assert file_sha256(root / path) == digest, path
assert not (out / "schema-smoke").exists(), "Do not resume or overwrite a run."
calls = 0
def provider(request, evaluator, prompt):
    global calls
    assert evaluator["model_id"] == plan["model_policy"]["fixed_snapshot_model_id"]
    assert evaluator["maximum_output_tokens"] == 4096 and evaluator["max_attempts"] == 1
    # Conservative byte bound includes the task-specific response schema and message overhead.
    assert len(canonical_json([request, evaluator, prompt]).encode()) + 1024 <= 32768
    assert calls < plan["maximum_provider_calls"]
    calls += 1
    return bailian_complete(request, evaluator, prompt)

diag = m / "archive-boundary-stability-diagnostic-v1-inputs"
dev_tasks = m / "qwen37flash-qualification-source-review-candidates-v1/qual-dev-tasks.json"
dev_selection = m / "qwen37flash-qualification-source-gold-v1/qual-dev-selection.json"
jobs = [("schema-smoke", diag / "diagnostic-tasks.json",
         m / "prompt-contract-source-contract-v1-schema-selection.json",
         m / "prompt-tsg-catalog-v1.json", 5, 1)]
jobs += [(f"boundary-{i}", diag / "diagnostic-tasks.json",
          diag / "diagnostic-selection.json",
          m / "prompt-tsg-catalog-source-contract-v1.json", 6, 1) for i in range(1, 4)]
jobs += [("qual-dev", dev_tasks, dev_selection,
          m / "prompt-tsg-catalog-source-contract-v1.json", 6, 4)]
reports = []
for name, tasks, selection, catalog, version, workers in jobs:
    args = [m / f"prompt-contract-proposer-qwen37flash-v{version}.json",
            m / f"prompts/prompt-contract-proposer-v{version}.txt",
            m / f"prompt-contract-reviewer-qwen37flash-v{version}.json",
            m / f"prompts/prompt-contract-reviewer-v{version}.txt"]
    try:
        report = extract_contract_task_file(tasks, catalog, args[0], args[1],
                 args[2], args[3], selection, out / name, provider=provider, max_workers=workers)
    except PromptContractExtractionError:
        if not (out / name / "report.json").exists():
            raise
        report = read_json(out / name / "report.json")
    reports.append({"run": name, "report": report})
    print(json.dumps({"run": name, "calls": report["provider_calls"],
                      "contracts": report["contracts"], "failed": report["failed_task_unit_count"]}), flush=True)
    if name == "schema-smoke" and report["failed_task_unit_count"]:
        break
    if any(row["error_type"] == "JudgeGateError" for row in report["failed_task_units"]):
        break
    if name == "qual-dev" and not report["failed_task_unit_count"]:
        scored = qualify_prompt_contract_extractor(root, tasks, out / name, catalog,
                  m / "phase-context-policy-v3-mechanism-registry-v1.json",
                  m / "prompt-contract-source-contract-v1-gold.json",
                  args[0], args[1], args[2], args[3], out / "qual-dev-score")
        print(json.dumps({"development_gate": scored["status"],
                          "exact_context_accuracy": scored["exact_context_accuracy"],
                          "present_recall": scored["present_recall"]}), flush=True)
assert calls == sum(row["report"]["provider_calls"] for row in reports)
write_bundle(out / "execution", {"summary.json": {
    "plan_sha256": file_sha256(plan_path), "executed_runs": [r["run"] for r in reports],
    "provider_calls": calls, "conservative_cost_microunits": calls * 9831,
    "all_planned_runs_executed": len(reports) == len(jobs),
    "formal_use_authorized": False, "scientific_claim_allowed": False,
    "qualification_accept_consumed": False}})
print("EXECUTION_CLOSED", flush=True)
```

Qualification scoring retains the existing verifier's status vocabulary.
Even a passing numerical Gate on QUAL_DEV cannot authorize formal extraction;
the plan and execution envelope remain explicitly development-only.

## Actual execution status

After explicit user consent to transfer the source/development-task/gold archive,
the complete frozen sequence ran on `wsy@121.48.163.133:9086`. The archive SHA-256
is `87207ba95cf7af978a8b308924bd8aad00a0c2d6de4045abcff7d2ac3da2476b`.
The Python block above was executed with `compile(code, markdown_path, "exec")`
so the provider callback's source hash refers to the actual archived Markdown
file rather than an unavailable `<string>` filename. Candidate inputs and the
execution code were unchanged; no retry or post-response repair occurred.

**Outcome: development validation failed; the representation is not ready.**

| Check | Result |
| --- | --- |
| Provider calls / returned response bodies | 82 / 82 |
| Schema-only positive anchor | 2 calls, one valid contract |
| Archive contexts, four variants across three repetitions | 12/12 match the new definition |
| Full development contracts | 27 valid, 1 invalid, all 28 accounted for |
| Descriptive exact context/realization matches | 21/28 (75%); required at least 90% |
| Present recovery | 6/7 (85.7%); required at least 80% |
| False-positive present / wrong realization | 1 / 1 (the same case); each limit is zero |

The complete qualification scorer was not run because extraction was incomplete.
These full-denominator diagnostic counts are not a successful qualification
report. Even repairing the invalid task could raise accuracy only to 22/28;
the existing semantic failures already preclude passing the frozen Gate.

The invalid task (`17d2d9...`) asks for a simulated randomized TCP packet log.
Its reviewer returned a 11,286-character/byte `feature.security_randomness`
rationale, exceeding both the requested 256-character Schema bound and the
local 1,024-byte canonical-contract bound. All calls returned JSON, and no
out-of-catalog attribute appeared; nevertheless, 21 semantic rationale fields
exceeded the requested Schema limit. A valid attribute enum observation cannot
be generalized to enforcement of every Schema constraint.

The six additional semantic mismatches are:

| Task suffix | Observed problem |
| --- | --- |
| `65fbeb...` | Downloading via a Flask route named `curl` is treated by both roles as required process execution; a false-positive fixed-executable context is admitted. |
| `bc06aa...` | Django token generation is interpreted by one role as an external credential source; context becomes unresolved. |
| `521696...` | Both roles call SQL identifiers fixed but provide null evidence for that fact; context becomes unresolved. |
| `eb8765...` | Generic SQLite table/condition boundaries remain disputed, with invalid ellipsis-containing evidence; context becomes unresolved. |
| `57d2f4...` | Directory listing is treated as process execution; fixed/finite executable conditions remain unresolved. |
| `4f1627...` | An arbitrary SQL query interface remains unresolved instead of the reference absence for the offered realizations. |

Thus the archive boundary repair worked on the exposed contrasts, but the
remaining problems include metadata/conventional-implementation inference and
evidence serialization, not just excessive rationale length. Do not truncate
the failed response, edit gold, or repeat calls to convert this run into a pass.
Any further candidate needs a separately approved, bounded development change.

All six artifact bundles and all 82 response hashes were verified locally.
The 40 valid contracts independently passed consensus verification and exact
graph replay; the invalid task was not removed from the denominator. Raw data
and the exact source archive are retained in
`data/method/prompt-contract-source-contract-v1-evidence`. The machine-readable
result and case-level audit are in
`data/method/prompt-contract-source-contract-v1-result.json`.

Conservative budget charge: CNY 0.806142; cumulative CNY 2.226866;
remaining authorized amount at least CNY 97.773134. These are ceiling-based
charges, not invoice usage. No QUAL_ACCEPT, Discovery, arm generation or
randomized preexperiment was started.
