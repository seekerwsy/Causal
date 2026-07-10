from pathlib import Path

from typer.testing import CliRunner

from secaware.cli import app


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
    assert (run_dir / "reports" / "summary.md").exists()

    effects_text = (run_dir / "reports" / "effects.csv").read_text(encoding="utf-8")
    assert "confirmed" in effects_text or "directional" in effects_text
