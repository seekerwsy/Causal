from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path

from secaware.dataset_adjudication.config import AdjudicationConfig
from secaware.dataset_adjudication.packets import build_adjudication_packets
from secaware.dataset_adjudication.run import (
    ReconcileAdjudicationRequest,
    reconcile_adjudication_run,
)
from secaware.dataset_adjudication.schema import (
    AdjudicationDimension,
    ClusterAdjudicationLabel,
    ClusterCodexDecision,
    DecisionConfidence,
    NeutralityAdjudicationLabel,
    NeutralityCodexDecision,
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


def _parent_run(path: Path):
    records = [
        _record("alpha", 1, "Validate a token.", NeutralityState.UNRESOLVED),
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
    packets = build_adjudication_packets(records, seed=20260812)
    path.mkdir(parents=True)
    config = _config()
    (path / "config.json").write_text(config.model_dump_json(indent=2), encoding="utf-8")
    (path / "source-manifest.json").write_text(
        json.dumps({"manifest_sha256": "a" * 64}), encoding="utf-8"
    )
    (path / "report.json").write_text(
        json.dumps({"status": "PACKETS_READY", "source_manifest_sha256": "a" * 64}),
        encoding="utf-8",
    )
    (path / "packet-metadata.jsonl").write_text(
        "".join(item.model_dump_json() + "\n" for item in packets.metadata), encoding="utf-8"
    )
    (path / "pass-a-packets.jsonl").write_text(
        "".join(item.model_dump_json() + "\n" for item in packets.pass_a), encoding="utf-8"
    )
    (path / "pass-b-packets.jsonl").write_text(
        "".join(item.model_dump_json() + "\n" for item in packets.pass_b), encoding="utf-8"
    )
    pilot = {
        dimension.value: [
            next(
                item.packet_id
                for item in packets.metadata
                if item.dimension is dimension
            )
        ]
        for dimension in AdjudicationDimension
    }
    (path / "pilot-packet-ids.json").write_text(json.dumps(pilot), encoding="utf-8")
    return config, packets, set(pilot["neutrality"] + pilot["cluster_relation"])


def _write_decisions(path: Path, packets, selected: set[str], pass_id: str) -> None:
    source = packets.pass_a if pass_id == "A" else packets.pass_b
    values = []
    for packet in source:
        if packet.packet_id not in selected:
            continue
        visible_quote = (
            packet.prompt
            if packet.dimension is AdjudicationDimension.NEUTRALITY
            else packet.prompt_a
        )
        common = dict(
            packet_id=packet.packet_id,
            pass_id=pass_id,
            packet_digest=packet.packet_digest,
            confidence=DecisionConfidence.HIGH,
            evidence_quotes=(visible_quote,),
            rationale="The visible prompt supports this frozen rubric label.",
            rubric_version="adjudication-rubric-v1",
            annotator_kind="CODEX",
            annotator_id="codex-primary",
            decision_timestamp=datetime(2026, 8, 12, tzinfo=UTC),
            input_manifest_sha256="a" * 64,
        )
        if packet.dimension is AdjudicationDimension.NEUTRALITY:
            values.append(NeutralityCodexDecision(
                dimension=AdjudicationDimension.NEUTRALITY,
                label=NeutralityAdjudicationLabel.SECURITY_FEATURE_PRESENT,
                **common,
            ))
        else:
            values.append(ClusterCodexDecision(
                dimension=AdjudicationDimension.CLUSTER_RELATION,
                label=ClusterAdjudicationLabel.SAME_TASK_VARIANT,
                **common,
            ))
    path.write_text("".join(item.model_dump_json() + "\n" for item in values), encoding="utf-8")


def test_pilot_reconciliation_run_is_immutable_and_leaves_human_fields_blank(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "src" / "secaware").mkdir(parents=True)
    (workspace / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    parent = workspace / "runs" / "dataset-adjudication" / "packet-run"
    config, packets, selected = _parent_run(parent)
    pass_a = tmp_path / "pass-a.jsonl"
    pass_b = tmp_path / "pass-b.jsonl"
    _write_decisions(pass_a, packets, selected, "A")
    _write_decisions(pass_b, packets, selected, "B")

    result = reconcile_adjudication_run(ReconcileAdjudicationRequest(
        config=config,
        workspace_root=workspace,
        parent_run_dir=parent,
        pass_a_decisions_path=pass_a,
        pass_b_decisions_path=pass_b,
        run_id="pilot-reconciliation",
        scope="pilot",
        command_argv=("secaware", "reconcile-dataset-adjudication"),
    ))

    assert result.status == "AWAITING_HUMAN_AUDIT"
    report = json.loads((result.run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["scope"] == "pilot"
    assert report["counts"]["total"] == 2
    template_lines = (result.run_dir / "human-review-template.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    templates = [json.loads(line) for line in template_lines]
    assert templates
    assert all(item["human_label"] is None for item in templates)
    assert all(item["reviewer_id"] is None for item in templates)
    assert not (result.run_dir / "human-decisions.jsonl").exists()
