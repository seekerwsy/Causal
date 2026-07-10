import time
from pathlib import Path

from typer.testing import CliRunner

from secaware.cli import app
from secaware.pipeline.manifest import read_stage_manifest


STAGE_OUTPUTS = {
    "extract-prompt-tsg": ["tsg/prompt_tsg.jsonl"],
    "generate-observed": ["generation/observed_code.jsonl"],
    "extract-code-tsg-observed": ["tsg/observed_code_tsg.jsonl"],
    "run-oracle-observed": ["oracle/observed_oracle.jsonl"],
    "discover": [
        "discovery/hypotheses_all.jsonl",
        "discovery/hypotheses_selected.jsonl",
    ],
    "intervene": [
        "interventions/interventions.jsonl",
        "interventions/paired_prompts.jsonl",
    ],
    "generate-counterfactual": ["generation/counterfactual_code.jsonl"],
    "extract-code-tsg-counterfactual": ["tsg/counterfactual_code_tsg.jsonl"],
    "run-oracle-counterfactual": ["oracle/counterfactual_oracle.jsonl"],
    "confirm": [
        "analysis/pair_results.jsonl",
        "analysis/hypothesis_effects.jsonl",
    ],
    "report": [
        "reports/funnel.csv",
        "reports/effects.csv",
        "reports/failures.csv",
        "reports/mechanism_cards.jsonl",
        "reports/summary.md",
    ],
}

STAGE_INPUTS = {
    "extract-prompt-tsg": ["inputs/prompts.jsonl"],
    "generate-observed": ["inputs/prompts.jsonl"],
    "extract-code-tsg-observed": ["generation/observed_code.jsonl"],
    "run-oracle-observed": ["generation/observed_code.jsonl"],
    "discover": [
        "inputs/prompts.jsonl",
        "tsg/prompt_tsg.jsonl",
        "tsg/observed_code_tsg.jsonl",
        "oracle/observed_oracle.jsonl",
    ],
    "intervene": [
        "inputs/prompts.jsonl",
        "tsg/prompt_tsg.jsonl",
        "discovery/hypotheses_selected.jsonl",
    ],
    "generate-counterfactual": [
        "inputs/prompts.jsonl",
        "interventions/interventions.jsonl",
    ],
    "extract-code-tsg-counterfactual": ["generation/counterfactual_code.jsonl"],
    "run-oracle-counterfactual": ["generation/counterfactual_code.jsonl"],
    "confirm": [
        "interventions/interventions.jsonl",
        "oracle/observed_oracle.jsonl",
        "oracle/counterfactual_oracle.jsonl",
        "discovery/hypotheses_selected.jsonl",
    ],
    "report": [
        "inputs/prompts.jsonl",
        "discovery/hypotheses_all.jsonl",
        "discovery/hypotheses_selected.jsonl",
        "interventions/interventions.jsonl",
        "analysis/pair_results.jsonl",
        "analysis/hypothesis_effects.jsonl",
    ],
}


def test_run_all_demo_creates_required_reports(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "demo"

    result = runner.invoke(
        app,
        ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir), "--force"],
    )

    assert result.exit_code == 0, result.output
    assert (run_dir / "reports" / "funnel.csv").exists()
    assert (run_dir / "reports" / "effects.csv").exists()
    assert (run_dir / "reports" / "failures.csv").exists()
    assert (run_dir / "reports" / "mechanism_cards.jsonl").exists()
    assert (run_dir / "reports" / "summary.md").exists()

    for stage, outputs in STAGE_OUTPUTS.items():
        manifest_path = run_dir / ".stages" / f"{stage}.json"
        manifest = read_stage_manifest(manifest_path)
        assert manifest.stage == stage
        assert set(manifest.inputs) == set(STAGE_INPUTS[stage])
        assert manifest.outputs == outputs
        assert all("\\" not in path and not Path(path).is_absolute() for path in manifest.inputs)

    effects_text = (run_dir / "reports" / "effects.csv").read_text(encoding="utf-8")
    assert "confirmed" in effects_text or "directional" in effects_text

    stage_outputs = {
        relative_path: run_dir / relative_path
        for outputs in STAGE_OUTPUTS.values()
        for relative_path in outputs
    }
    before = {
        relative_path: (path.read_bytes(), path.stat().st_mtime_ns)
        for relative_path, path in stage_outputs.items()
    }
    time.sleep(0.02)

    second_result = runner.invoke(
        app,
        ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir)],
    )

    assert second_result.exit_code == 0, second_result.output
    after = {
        relative_path: (path.read_bytes(), path.stat().st_mtime_ns)
        for relative_path, path in stage_outputs.items()
    }
    assert after == before
