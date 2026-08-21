from __future__ import annotations

import json
from pathlib import Path

import pytest

from secaware.dataset_adjudication.config import AdjudicationConfig
from secaware.dataset_adjudication.run import (
    AdjudicationRunConflictError,
    PrepareAdjudicationRequest,
    prepare_adjudication_run,
)
from secaware.dataset_audit.schema import (
    CweEvidence,
    FunctionalState,
    NeutralityState,
    RecordAudit,
    SourceCoordinate,
)


def _record(source: str, line: int, prompt: str, neutrality: NeutralityState) -> RecordAudit:
    return RecordAudit(
        schema_version="1.0",
        coordinate=SourceCoordinate(
            source_id=source,
            relative_path=f"{source}.jsonl",
            line_number=line,
            record_id=f"{source}-{line}",
        ),
        prompt=prompt,
        language="python",
        cwe_ids=("CWE-89",),
        cwe_evidence=CweEvidence.EXPLICIT_FIELD,
        exact_prompt_sha256=f"exact-{source}-{line}",
        normalized_prompt_sha256=f"normalized-{source}-{line}",
        neutrality=neutrality,
        neutrality_rule_version="neutrality-prescreen-v1",
        functional_state=FunctionalState.ABSENT,
        task_cluster_id=f"cluster-{source}-{line}",
        cluster_independence_resolved=True,
    )


def _source_run(path: Path) -> Path:
    path.mkdir(parents=True)
    records = [
        _record("alpha", 1, "Validate a user token.", NeutralityState.UNRESOLVED),
        _record("beta", 2, "Prevent SQL injection.", NeutralityState.OBVIOUS_CONFLICT),
        _record(
            "gamma",
            3,
            "Implement a function to read a user supplied file safely.",
            NeutralityState.CANDIDATE_NEUTRAL,
        ),
        _record(
            "gamma",
            4,
            "Implement a function to read the user supplied file safely.",
            NeutralityState.CANDIDATE_NEUTRAL,
        ),
    ]
    (path / "record-audit.jsonl").write_text(
        "".join(item.model_dump_json() + "\n" for item in records),
        encoding="utf-8",
    )
    (path / "report.json").write_text(
        json.dumps(
            {
                "status": "COMPLETE",
                "stable_digest": "d" * 64,
                "progress": {"total": len(records), "failed": 0, "pending": 0},
            }
        ),
        encoding="utf-8",
    )
    return path


def _config() -> AdjudicationConfig:
    return AdjudicationConfig(
        schema_version="1.0",
        adjudication_version="adjudication-v1",
        rubric_version="adjudication-rubric-v1",
        packet_version="adjudication-packets-v1",
        audit_sample_version="human-audit-sample-v1",
        source_audit_run_id="source-run",
        source_stable_digest="d" * 64,
        expected_source_records=4,
        expected_neutrality_packets=2,
        expected_cluster_packets=1,
        pilot_per_dimension=1,
        human_audit_fraction=0.2,
        seed=20260812,
    )


def test_prepare_run_writes_complete_blinded_packet_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (workspace / "src" / "secaware").mkdir(parents=True)
    source = _source_run(workspace / "runs" / "dataset-audit" / "source-run")

    result = prepare_adjudication_run(
        PrepareAdjudicationRequest(
            config=_config(),
            workspace_root=workspace,
            source_run_dir=source,
            run_id="packet-run",
            command_argv=("secaware", "prepare-dataset-adjudication"),
        )
    )

    assert result.status == "PACKETS_READY"
    expected = {
        "config.json",
        "commands.jsonl",
        "environment.json",
        "source-manifest.json",
        "packet-metadata.jsonl",
        "pass-a-packets.jsonl",
        "pass-b-packets.jsonl",
        "pilot-packet-ids.json",
        "failures.jsonl",
        "report.json",
        "report.md",
    }
    assert {item.name for item in result.run_dir.iterdir()} == expected
    report = json.loads((result.run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["counts"] == {
        "cluster_relation": 1,
        "neutrality": 2,
        "total": 3,
    }
    pilot = json.loads(
        (result.run_dir / "pilot-packet-ids.json").read_text(encoding="utf-8")
    )
    assert len(pilot["neutrality"]) == 1
    assert len(pilot["cluster_relation"]) == 1
    assert not (workspace / "runs" / "dataset-adjudication" / ".packet-run.staging").exists()


def test_prepare_run_refuses_overwrite_and_stale_source_digest(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (workspace / "src" / "secaware").mkdir(parents=True)
    source = _source_run(workspace / "runs" / "dataset-audit" / "source-run")
    request = PrepareAdjudicationRequest(
        config=_config(),
        workspace_root=workspace,
        source_run_dir=source,
        run_id="packet-run",
        command_argv=("secaware", "prepare-dataset-adjudication"),
    )

    prepare_adjudication_run(request)
    with pytest.raises(AdjudicationRunConflictError, match="already exists"):
        prepare_adjudication_run(request)

    stale = _config().model_copy(update={"source_stable_digest": "e" * 64})
    with pytest.raises(ValueError, match="stable digest"):
        prepare_adjudication_run(
            PrepareAdjudicationRequest(
                config=stale,
                workspace_root=workspace,
                source_run_dir=source,
                run_id="stale-run",
                command_argv=("secaware", "prepare-dataset-adjudication"),
            )
        )


def test_adjudication_config_rejects_provider_or_model_fields() -> None:
    value = _config().model_dump(mode="json")
    value["model"] = "provider-model"
    with pytest.raises(ValueError):
        AdjudicationConfig.model_validate(value)
