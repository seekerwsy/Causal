"""Task-cluster bootstrap replication of the frozen independent Z-to-Y edge."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from secaware.causal.paths import edge_allows_possible_direction, endpoint_marks_compatible
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.independent_validation_analysis_fci import (
    _matches_frozen_edge,
    _validated_config,
)
from secaware.exploratory.randomized_discovery_bootstrap import (
    _closed_replicate,
    _environment,
    _failure_reason,
    _manifest,
    _validated_pag,
    _write_json,
)
from secaware.exploratory.randomized_discovery_v2_fci import _base_background, _config, _read_json
from secaware.exploratory.randomized_discovery_v3_functional_bootstrap import _draw
from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    _table_and_matrix_for_population,
    _validated_analysis,
)
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.causal import EndpointMark, PAGEdgeRecord, PAGRecord, PAGRunKind

_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-independent-validation-mechanism-function-bootstrap-v1"
_MODEL = "phi-4-14b"
_VIEW = "full_jci_functional"
_SOURCE = "z.target_mechanism_realized"
_TARGET = "y.discovery_functional"
_EXPECTED_TASKS = 55
_EXPECTED_ROWS = 220


def _validated_bootstrap_config(repo_root: Path, path: Path) -> dict[str, object]:
    config = _read_json(path)
    expected = {
        "schema_version": _SCHEMA_VERSION,
        "bootstrap_id": "five_cwe_independent_validation_mechanism_function_bootstrap_v1",
        "status": "FROZEN_EDGE_REPLICATION_NO_HYPOTHESIS_SELECTION",
        "model_id": _MODEL,
        "view_id": _VIEW,
        "source_variable": _SOURCE,
        "target_variable": _TARGET,
        "reference_marks": ["tail", "arrow"],
        "global_seed": 2026081922,
        "bootstrap_samples": 200,
        "bootstrap_unit": "complete_task_block",
        "stability_threshold": 0.8,
        "max_failed_bootstrap_fraction": 0.1,
        "analysis_config": {
            "path": "configs/e2e-pilot/five-cwe-independent-validation-analysis-fci-v1.json",
            "sha256": "a494277b29e9cea0520fe66b35e6e5cc23ef97e2469b56c19b29ef52d2aa94c3",
        },
    }
    if config != expected:
        raise ValueError("independent validation bootstrap config failed validation")
    analysis_path = (repo_root / str(config["analysis_config"]["path"])).resolve()
    try:
        analysis_path.relative_to(repo_root)
    except ValueError:
        raise ValueError("independent validation bootstrap config escaped repository") from None
    if (
        not analysis_path.is_file()
        or sha256_file(analysis_path) != config["analysis_config"]["sha256"]
    ):
        raise ValueError("independent validation bootstrap config digest failed validation")
    return config


def _edge(pag: PAGRecord) -> PAGEdgeRecord | None:
    for candidate in pag.edges:
        if {candidate.left, candidate.right} == {_SOURCE, _TARGET}:
            return candidate
    return None


def _matches_marks(edge: PAGEdgeRecord) -> bool:
    frozen = (EndpointMark.TAIL, EndpointMark.ARROW)
    return edge_allows_possible_direction(edge, _SOURCE, _TARGET) and all(
        endpoint_marks_compatible(reference, observed)
        for reference, observed in zip(frozen, edge.marks_from(_SOURCE, _TARGET), strict=True)
    )


def run_independent_validation_analysis_bootstrap(
    *,
    repo_root: Path,
    table_dir: Path,
    reference_dir: Path,
    analysis_config_path: Path,
    bootstrap_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    engineering_replicates: int | None = None,
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    table_dir = table_dir.resolve()
    reference_dir = reference_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    bootstrap_config_path = bootstrap_config_path.resolve()
    output_dir = output_dir.resolve()
    analysis, inherited_path, runtime_path = _validated_config(repo_root, analysis_config_path)
    bootstrap = _validated_bootstrap_config(repo_root, bootstrap_config_path)
    if bootstrap["analysis_config"]["sha256"] != sha256_file(analysis_config_path):
        raise ValueError("independent validation bootstrap analysis binding failed validation")
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    reference_manifest_sha256 = _verify_directory_manifest(reference_dir)
    reference_report = _read_json(reference_dir / "report.json")
    if (
        reference_report.get("status") != "INDEPENDENT_VALIDATION_REFERENCE_FCI_COMPLETE"
        or reference_report.get("model_id") != _MODEL
        or reference_report.get("view_id") != _VIEW
        or reference_report.get("independent_tasks") != _EXPECTED_TASKS
    ):
        raise ValueError("independent validation bootstrap reference failed validation")
    matrix_path = table_dir / "matrix-phi14b-full_jci_functional.json"
    payload = _read_json(matrix_path)
    producer_sha256 = canonical_sha256(
        {
            "policy": "five-cwe-independent-validation-mechanism-function-fci-v1",
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "inherited_fci_config_sha256": sha256_file(inherited_path),
            "runtime_freeze_manifest_sha256": sha256_file(runtime_path / "artifact-manifest.json"),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, full_matrix, bindings = _table_and_matrix_for_population(
        payload,
        producer_sha256=producer_sha256,
        expected_tasks=_EXPECTED_TASKS,
        scope_id="scope.five_cwe_independent_mechanism_function_v1",
    )
    stored_table = type(table).model_validate(_read_json(reference_dir / "causal-table.json"))
    knowledge = _base_background(table)
    stored_knowledge = type(knowledge).model_validate(
        _read_json(reference_dir / "base-background-knowledge.json")
    )
    reference_pag = PAGRecord.model_validate(_read_json(reference_dir / "raw-pag.json"))
    inherited_analysis = _validated_analysis(inherited_path)
    fci_config = _config(inherited_analysis)
    if (
        table != stored_table
        or knowledge != stored_knowledge
        or full_matrix.shape != (_EXPECTED_ROWS, 3)
        or reference_pag.run_kind is not PAGRunKind.JCI_RAW
        or reference_pag.table_id != table.table_id
        or fci_config.bootstrap_samples != 200
        or fci_config.stability_threshold != 0.8
        or fci_config.max_failed_bootstrap_fraction != 0.1
        or fci_config.bootstrap_samples != bootstrap["bootstrap_samples"]
        or fci_config.stability_threshold != bootstrap["stability_threshold"]
        or fci_config.max_failed_bootstrap_fraction != bootstrap["max_failed_bootstrap_fraction"]
    ):
        raise ValueError("independent validation bootstrap inputs failed validation")
    arm_index = tuple(item.variable_id for item in table.variables).index("c.arm")
    grouped: dict[str, list[dict[str, object]]] = {}
    for binding in bindings:
        grouped.setdefault(str(binding["task_id"]), []).append(binding)
    blocks = []
    for task_id in sorted(grouped):
        block = tuple(sorted(grouped[task_id], key=lambda item: item["values"][arm_index]))
        if tuple(item["values"][arm_index] for item in block) != (0, 1, 2, 3):
            raise ValueError("independent validation bootstrap task block failed validation")
        blocks.append((task_id, block))
    if len(blocks) != _EXPECTED_TASKS:
        raise ValueError("independent validation bootstrap task population failed validation")
    sampling_frame_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "model_id": _MODEL,
            "view_id": _VIEW,
            "blocks": [
                {
                    "task_id": task_id,
                    "assignments": [
                        {"assignment_id": item["assignment_id"], "arm": item["values"][arm_index]}
                        for item in block
                    ],
                }
                for task_id, block in blocks
            ],
        }
    )
    provenance: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "policy": _POLICY,
        "table_manifest_sha256": table_manifest_sha256,
        "reference_manifest_sha256": reference_manifest_sha256,
        "analysis_config_sha256": sha256_file(analysis_config_path),
        "bootstrap_config_sha256": sha256_file(bootstrap_config_path),
        "inherited_fci_config_sha256": sha256_file(inherited_path),
        "runtime_freeze_manifest_sha256": sha256_file(runtime_path / "artifact-manifest.json"),
        "matrix_artifact_sha256": sha256_file(matrix_path),
        "table_sha256": table.table_sha256,
        "reference_pag_id": reference_pag.pag_id,
        "background_knowledge_sha256": knowledge.knowledge_sha256,
        "sampling_frame_sha256": sampling_frame_sha256,
        "global_seed": bootstrap["global_seed"],
    }
    if engineering_replicates is None:
        planned = fci_config.bootstrap_samples
        eligible_for_decision = True
    elif type(engineering_replicates) is int and 1 <= engineering_replicates <= 10:
        planned = engineering_replicates
        eligible_for_decision = False
    else:
        raise ValueError("independent validation bootstrap engineering bound failed validation")
    run_config = {
        **provenance,
        "planned_replicates": planned,
        "configured_bootstrap_samples": fci_config.bootstrap_samples,
        "eligible_for_replication_decision": eligible_for_decision,
        "stability_threshold": fci_config.stability_threshold,
        "max_failed_bootstrap_fraction": fci_config.max_failed_bootstrap_fraction,
        "source_variable": _SOURCE,
        "target_variable": _TARGET,
        "frozen_reference_marks": analysis["reference_marks"],
        "hypothesis_selection_allowed": False,
    }
    if output_dir.exists():
        if (output_dir / "artifact-manifest.json").exists():
            raise ValueError("independent validation bootstrap output is closed")
        if _read_json(output_dir / "run-config.json") != run_config:
            raise ValueError("independent validation bootstrap resume failed validation")
    else:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "replicates").mkdir()
        _write_json(output_dir / "run-config.json", run_config)
        _write_json(output_dir / "command.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment.json", _environment())
    active_runner = SpawnedFCIRunner() if runner is None else runner
    successful: dict[int, PAGRecord] = {}
    failures: dict[int, str] = {}
    supported = 0
    for replicate_index in range(planned):
        draw, matrix = _draw(
            blocks=tuple(blocks),
            provenance=provenance,
            replicate_index=replicate_index,
        )
        replicate_dir = output_dir / "replicates" / f"replicate-{replicate_index:04d}"
        if replicate_dir.exists():
            restored = _closed_replicate(replicate_dir, draw)
            if isinstance(restored, PAGRecord):
                pag = _validated_pag(restored, table=table, knowledge=knowledge, config=fci_config)
                successful[replicate_index] = pag
                candidate = _edge(pag)
                if candidate is not None and _matches_marks(candidate):
                    supported += 1
            else:
                failures[replicate_index] = restored
            continue
        replicate_dir.mkdir()
        _write_json(replicate_dir / "draw.json", draw)
        try:
            pag = active_runner.run(matrix, table, knowledge, fci_config, PAGRunKind.JCI_RAW)
            pag = _validated_pag(pag, table=table, knowledge=knowledge, config=fci_config)
            _write_json(replicate_dir / "pag.json", pag.model_dump(mode="json"))
            successful[replicate_index] = pag
            candidate = _edge(pag)
            if candidate is not None and _matches_marks(candidate):
                supported += 1
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:  # noqa: BLE001 - preserve bounded failure artifacts.
            reason = _failure_reason(error)
            _write_json(
                replicate_dir / "failure.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "replicate_index": replicate_index,
                    "reason_code": reason,
                },
            )
            failures[replicate_index] = reason
        _manifest(replicate_dir)
        print(
            f"BOOTSTRAP_PROGRESS completed={replicate_index + 1} "
            f"successful={len(successful)} failed={len(failures)} "
            f"supported={supported} pending={planned - replicate_index - 1}",
            flush=True,
        )
    support_fraction = supported / planned
    max_failures = int(fci_config.max_failed_bootstrap_fraction * planned)
    stable = supported >= fci_config.stability_threshold * planned
    valid = len(failures) <= max_failures
    replicated = eligible_for_decision and stable and valid
    write_jsonl(
        output_dir / "edge-support.jsonl",
        [
            {
                "schema_version": _SCHEMA_VERSION,
                "source_variable": _SOURCE,
                "target_variable": _TARGET,
                "reference_marks": analysis["reference_marks"],
                "support_numerator": supported,
                "support_denominator": planned,
                "support_fraction": support_fraction,
            }
        ],
    )
    runtime_policy = _read_json(runtime_path / "runtime-policy.json")
    decision = "engineering_pilot_only"
    if eligible_for_decision:
        decision = "replicated" if replicated else "not_replicated"
    _write_json(
        output_dir / "replication-result.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "frozen_hypothesis_id": runtime_policy["frozen_hypothesis_id"],
            "source_variable": _SOURCE,
            "target_variable": _TARGET,
            "frozen_reference_marks": analysis["reference_marks"],
            "reference_full_sample_match": _matches_frozen_edge(reference_pag),
            "bootstrap_support_numerator": supported,
            "bootstrap_support_denominator": planned,
            "bootstrap_support_fraction": support_fraction,
            "stability_threshold": fci_config.stability_threshold,
            "failed_replicates": len(failures),
            "max_failed_replicates": max_failures,
            "decision": decision,
            "hypothesis_selection_performed": False,
        },
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "INDEPENDENT_VALIDATION_BOOTSTRAP_COMPLETE"
            if eligible_for_decision
            else "INDEPENDENT_VALIDATION_BOOTSTRAP_PILOT_COMPLETE"
        ),
        "model_id": _MODEL,
        "view_id": _VIEW,
        "planned_replicates": planned,
        "successful_replicates": len(successful),
        "failed_replicates": len(failures),
        "pending_replicates": 0,
        "failure_counts": dict(sorted(Counter(failures.values()).items())),
        "support_numerator": supported,
        "support_denominator": planned,
        "support_fraction": support_fraction,
        "stability_threshold": fci_config.stability_threshold,
        "replication_decision": decision,
        "frozen_hypothesis_confirmed": replicated,
        "scientific_result_valid": eligible_for_decision and valid,
        "scientific_claim_allowed": eligible_for_decision and valid,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["run_independent_validation_analysis_bootstrap"]
