"""Audit pre-outcome Prompt-TSG variation in a frozen discover pool."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES, VariableDeclaration
from secaware.config import TSGConfig
from secaware.extractors.factory import extraction_policy, extractor_for_config
from secaware.io.jsonl import write_jsonl
from secaware.schema.causal import VariableRole
from secaware.schema.experiments import PromptRole
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import motif_query_vector
from secaware.tsg.queries import feature_state_vector


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.model_dump(mode="json"),
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _record_sort_key(value: str) -> tuple[int, int | str]:
    return (0, int(value)) if value.isdecimal() else (1, value)


def _declaration_applies(item: VariableDeclaration, cwe: str) -> bool:
    return item.applicable_cwes == ("*",) or cwe in item.applicable_cwes


def _variable_value(
    declaration: VariableDeclaration,
    prompt: PromptRecord,
    features: dict[str, FeatureState],
    motifs: dict[str, bool],
) -> str:
    if declaration.role is VariableRole.W:
        if declaration.variable_id == "w.language_family":
            return "python" if prompt.language.casefold() == "python" else "other"
        if declaration.variable_id == "w.task_family":
            return (
                prompt.task_family
                if prompt.task_family in declaration.states[:-1]
                else declaration.states[-1]
            )
        raise ValueError("unknown pre-outcome task variable")
    if declaration.role is not VariableRole.X:
        raise ValueError("outcome variable is unavailable in a pre-outcome audit")
    if declaration.variable_id.startswith("x.motif."):
        motif_id = declaration.variable_id.removeprefix("x.motif.")
        return "present" if motifs[motif_id] else "absent"
    feature_id = declaration.variable_id.removeprefix("x.")
    return features[feature_id].value


def _select(
    source_rows: list[dict[str, Any]],
    split_rows: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, object]]]:
    split = next(
        (
            item
            for item in split_rows
            if item.get("seed") == config["split_simulation_seed"]
        ),
        None,
    )
    if split is None:
        raise ValueError("frozen split simulation is unavailable")
    split_by_cluster = {
        item["cluster_id"]: item["split"] for item in split["assignments"]
    }
    target_cwes = set(config["target_cwes"])
    candidates_by_cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exclusions: list[dict[str, object]] = []
    for item in source_rows:
        coordinate = item["coordinate"]
        target_membership = sorted(target_cwes.intersection(item["cwe_ids"]))
        reason = None
        if coordinate["source_id"] != config["source_id"]:
            continue
        if item["language"] != config["language"]:
            reason = "language_mismatch"
        elif item["neutrality"] != config["neutrality"]:
            reason = "neutrality_mismatch"
        elif item["cluster_independence_resolved"] is not True:
            reason = "independence_unresolved"
        elif not target_membership:
            continue
        elif len(target_membership) != 1:
            reason = "ambiguous_target_cwe"
        elif split_by_cluster.get(item["task_cluster_id"]) != "discover":
            reason = "not_in_frozen_discover_split"
        if reason is not None:
            exclusions.append(
                {
                    "record_id": str(coordinate["record_id"]),
                    "task_cluster_id": item["task_cluster_id"],
                    "reason": reason,
                    "target_cwes": target_membership,
                }
            )
            continue
        candidates_by_cluster[item["task_cluster_id"]].append(item)

    selected: list[dict[str, Any]] = []
    for cluster_id, members in sorted(candidates_by_cluster.items()):
        members.sort(key=lambda item: _record_sort_key(str(item["coordinate"]["record_id"])))
        selected.append(members[0])
        for duplicate in members[1:]:
            exclusions.append(
                {
                    "record_id": str(duplicate["coordinate"]["record_id"]),
                    "task_cluster_id": cluster_id,
                    "reason": "same_source_cluster_duplicate",
                    "target_cwes": sorted(target_cwes.intersection(duplicate["cwe_ids"])),
                }
            )
    selected.sort(
        key=lambda item: (
            next(cwe for cwe in config["target_cwes"] if cwe in item["cwe_ids"]),
            _record_sort_key(str(item["coordinate"]["record_id"])),
        )
    )
    exclusions.sort(key=lambda item: (str(item["reason"]), str(item["record_id"])))
    return selected, exclusions


def audit(
    *,
    source_audit: Path,
    split_simulations: Path,
    config_path: Path,
    coverage_contract_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path)
    if config.get("schema_version") != "1.0":
        raise ValueError("identifiability audit config failed validation")
    threshold = config["marginal_min_state_count"]
    if type(threshold) is not int or not 1 <= threshold <= 1000:
        raise ValueError("marginal state threshold failed validation")
    source_rows = _read_jsonl(source_audit)
    split_rows = _read_jsonl(split_simulations)
    selected, exclusions = _select(source_rows, split_rows, config)
    if not selected:
        raise ValueError("identifiability audit selected no discover prompts")

    tsg_config = TSGConfig.model_validate(
        {
            "prompt_extractor": PromptExtractorBackend(config["prompt_extractor"]),
        },
        strict=True,
    )
    policy = extraction_policy(tsg_config)
    extractor = extractor_for_config(tsg_config)
    prompts: list[PromptRecord] = []
    proposals = []
    graphs = []
    variable_rows: list[dict[str, object]] = []
    for item in selected:
        record_id = str(item["coordinate"]["record_id"])
        cwe = next(value for value in config["target_cwes"] if value in item["cwe_ids"])
        task_family = "command_execution" if cwe == "CWE-78" else "sql_query"
        prompt = PromptRecord(
            prompt_id=f"csev2-{record_id}-discover-audit",
            task_id=item["task_cluster_id"],
            split="discover",
            language="python",
            task_family=task_family,
            cwe=cwe,
            prompt=item["prompt"],
            prompt_role=PromptRole.NEUTRAL_BASELINE,
            counterpart_prompt_id=None,
            oracle_profile_id=config["oracle_profiles"][cwe],
        )
        proposal = extractor.extract(prompt, policy)
        graph_record = build_prompt_tsg(proposal, prompt)
        graph = record_to_multidigraph(graph_record)
        features = dict(feature_state_vector(graph))
        motifs = {motif.value: present for motif, present in motif_query_vector(graph)}
        values = {
            declaration.variable_id: _variable_value(
                declaration,
                prompt,
                features,
                motifs,
            )
            for declaration in PROMPT_CAUSAL_VARIABLES
            if declaration.role is not VariableRole.Y and _declaration_applies(declaration, cwe)
        }
        prompts.append(prompt)
        proposals.append(proposal)
        graphs.append(graph_record)
        variable_rows.append(
            {
                "record_id": record_id,
                "task_cluster_id": prompt.task_id,
                "prompt_id": prompt.prompt_id,
                "cwe": cwe,
                "task_family": task_family,
                "oracle_profile_id": prompt.oracle_profile_id,
                "oracle_profile_semantic_review": "required",
                "values": values,
            }
        )

    distributions: list[dict[str, object]] = []
    for cwe in config["target_cwes"]:
        scope_rows = [item for item in variable_rows if item["cwe"] == cwe]
        variable_ids = sorted(
            {
                variable_id
                for item in scope_rows
                for variable_id in dict(item["values"])
            }
        )
        for variable_id in variable_ids:
            counts = Counter(str(dict(item["values"])[variable_id]) for item in scope_rows)
            observed_counts = dict(sorted(counts.items()))
            varying = len(counts) >= 2
            minimum = min(counts.values())
            distributions.append(
                {
                    "cwe": cwe,
                    "variable_id": variable_id,
                    "task_count": len(scope_rows),
                    "state_counts": observed_counts,
                    "observed_state_count": len(counts),
                    "varying": varying,
                    "minimum_observed_state_count": minimum,
                    "marginal_screen_pass": varying and minimum >= threshold,
                }
            )

    coverage = _read_json(coverage_contract_path)
    coverage_by_profile = {item["profile_id"]: item for item in coverage["profiles"]}
    oracle_profiles = []
    for cwe in config["target_cwes"]:
        profile_id = config["oracle_profiles"][cwe]
        profile = coverage_by_profile[profile_id]
        oracle_profiles.append(
            {
                "cwe": cwe,
                "profile_id": profile_id,
                "zero_finding_supported": profile["zero_finding_supported"],
                "calibration_fixture_count": len(profile["calibration_fixture_ids"]),
                "semantic_task_binding": "review_required",
            }
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "selected-prompts.jsonl", prompts)
    write_jsonl(output_dir / "prompt-extraction-proposals.jsonl", proposals)
    write_jsonl(output_dir / "prompt-tsg.jsonl", graphs)
    write_jsonl(output_dir / "variable-rows.jsonl", variable_rows)
    write_jsonl(output_dir / "variable-distributions.jsonl", distributions)
    write_jsonl(output_dir / "selection-exclusions.jsonl", exclusions)
    _write_json(output_dir / "config.json", config)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(
        output_dir / "environment.json",
        {
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "working_directory": os.getcwd(),
        },
    )
    selected_counts = Counter(prompt.cwe for prompt in prompts)
    varying_counts = Counter(
        item["cwe"] for item in distributions if item["varying"] is True
    )
    marginal_pass_counts = Counter(
        item["cwe"] for item in distributions if item["marginal_screen_pass"] is True
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "audit_id": config["audit_id"],
        "status": "COMPLETE",
        "interpretation": config["interpretation"],
        "counts": {
            "selected_independent_discover_tasks": dict(sorted(selected_counts.items())),
            "selected_total": len(prompts),
            "selection_exclusions": len(exclusions),
            "extraction_failures": 0,
            "pending": 0,
        },
        "pre_outcome_variation": {
            "varying_variables": dict(sorted(varying_counts.items())),
            "marginal_screen_pass_variables": dict(sorted(marginal_pass_counts.items())),
            "marginal_min_state_count": threshold,
            "conditional_gsquare_validity_established": False,
        },
        "oracle_profiles": oracle_profiles,
        "policy_sha256": policy.policy_sha256,
        "source_sha256": hashlib.sha256(source_audit.read_bytes()).hexdigest(),
        "split_simulations_sha256": hashlib.sha256(split_simulations.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
    }
    _write_json(output_dir / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-audit", type=Path, required=True)
    parser.add_argument("--split-simulations", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--coverage-contract", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        source_audit=args.source_audit,
        split_simulations=args.split_simulations,
        config_path=args.config,
        coverage_contract_path=args.coverage_contract,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
