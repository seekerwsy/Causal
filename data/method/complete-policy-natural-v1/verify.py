"""Replay the six actual requests and both local projection diagnostics, offline."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from prompt_mechanism_study.artifact_io import read_json, file_sha256

base = Path(__file__).resolve().parent
repo = base.parents[2]
summary = read_json(base / "analysis/summary.json")
for name, key in [("source/execution-source.tar.gz", "source_execution_sha256"),
                  ("source/results.tar.gz", "source_results_sha256"),
                  ("proposal-canonical-inputs.tar.gz", "proposal_execution_sha256"),
                  ("proposal-canonical-results.tar.gz", "proposal_results_sha256")]:
    assert file_sha256(base / name) == summary["identity"][key]
subprocess.run([sys.executable, str(repo / "data/method/atomic-candidate-interface-development-v1/current-workflow/replay.py"),
    str(base / "source")], cwd=repo, check=True)
with TemporaryDirectory(prefix="complete-policy-natural-replay-") as folder:
    tmp = Path(folder)
    for archive, destination in [("source/execution-source.tar.gz", "current"),
                                  ("baseline-source.tar.gz", "baseline"),
                                  ("proposal-canonical-inputs.tar.gz", "proposal")]:
        with tarfile.open(base / archive) as bundle:
            bundle.extractall(tmp / destination, filter="data")
    current_env = {**os.environ, "PYTHONPATH": str(tmp / "current/src")}
    subprocess.run([sys.executable, str(tmp / "proposal/data/method/complete-policy-natural-v1/propose.py"),
        str(base), str(tmp / "candidate-replay"), str(base / "proposal-result")],
        cwd=repo, env=current_env, check=True)
    for version in ("baseline", "current"):
        output = tmp / (version + "-comparison")
        subprocess.run([sys.executable, str(base / "compare.py"), str(base), str(output)],
            cwd=repo, env={**os.environ, "PYTHONPATH": str(tmp / version / "src")}, check=True)
        for name in ("request.json", "full.json", "per-factor-diagnostics.json", "leading-factors-diagnostic-only.json"):
            assert read_json(output / name) == read_json(base / "comparison" / version / name)
with tarfile.open(base / "source/results.tar.gz") as bundle:
    import json
    source = json.load(bundle.extractfile("./run/summary/report.json"))
proposal = read_json(base / "proposal-result/summary/report.json")
assert source["actual_provider_calls"] + proposal["provider_calls"] == summary["actual_provider_calls"] == 6
assert source["actual_conservative_cost_microunits"] + proposal["actual_conservative_cost_microunits"] == summary["actual_conservative_cost_microunits"] == 1926796
assert 6830308 - summary["actual_conservative_cost_microunits"] == summary["remaining_authorized_microunits"] == 4903512
assert summary["actual_prompt_edits"] == summary["eligible_automatic_factors"] == 0
print("Verified six retained requests, both projection diagnostics and budget; no network or semantic certification.")
