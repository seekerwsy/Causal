"""Offline, evidence-linked Prompt TSG and assigned-arm result inspection."""
from __future__ import annotations

import json
import hashlib
import zipfile
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import read_json, verify_bundle, bundle_digest, confined_path
from prompt_mechanism_study.prompt_contract_qualification import open_graph_assertions
from prompt_mechanism_study.prompt_tsg import (
    _occurrence_span, load_catalog, prompt_tsg_from_record, validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.task_input import prepare_task_input, generation_input_for_prompt


ARM_LABELS = {"BASELINE": "原始基线", "NOOP": "任务重述对照", "STYLE": "等词数风格提示",
              "GENERIC": "一般安全提醒", "TARGET": "目标要求干预"}


def _prompt_comparisons(tasks: dict, assignments: list[dict], plan: dict | None = None) -> list[dict]:
    """Group identical saved prompt texts for reading, preserving every assignment ID."""
    comparisons = []
    generation_tasks = {task["task_id"]: task for task in (plan or {}).get("tasks", [])}
    system = (plan or {}).get("generation_system_prompt")
    for number, (task_id, task) in enumerate(tasks.items(), 1):
        rows = [row for row in assignments if row["task_id"] == task_id]
        if not rows:
            continue
        generation_task = generation_tasks.get(task_id, task)
        prepared = "generation_input" in generation_task
        baseline = generation_task["prompt"]
        if prepared:
            prepare_task_input(generation_task, generation_system_prompt=system)
            if generation_task["source_prompt"] != task.get("source_prompt", task["prompt"]):
                raise ValueError("prepared input differs from the viewer's original source")
        baseline_prompt = (generation_task["generation_input"]["request"]["task"]
                           if prepared else baseline)
        variants = []
        for arm in ARM_LABELS:
            grouped = {}
            for row in rows:
                if row["arm"] != arm:
                    continue
                if row["prompt_sha256"] != content_hash(row["prompt"]):
                    raise ValueError("saved prompt differs from its assignment identity")
                if arm == "BASELINE" and row["prompt"] != baseline:
                    raise ValueError("saved baseline differs from its frozen generation input")
                actual = (generation_input_for_prompt(generation_task, row["prompt"]) if prepared else
                          {"system_prompt": system, "request": {
                              "language": generation_task.get("language"), "task": row["prompt"]}})
                prompt = actual["request"]["task"]
                variant = grouped.setdefault((row["policy_id"], row["prompt"]), {
                    "arm": arm, "label": ARM_LABELS[arm], "policy_id": row["policy_id"],
                    "prompt": prompt, "prompt_sha256": content_hash(prompt),
                    "assignment_prompt_sha256": row["prompt_sha256"],
                    "generation_input": actual, "assignments": [],
                })
                variant["assignments"].append({"assignment_id": row["assignment_id"], "seed": row["seed"]})
            variants.extend(grouped.values())
        comparisons.append({"case_number": task.get("case_number", number), "task_id": task_id,
                            "original_prompt": task.get("source_prompt", task["prompt"]), "baseline_prompt": baseline_prompt,
                            "language": generation_task.get("language"),
                            "input_alignment": "prepared_baseline" if prepared else "legacy_source_only",
                            "prepared_baseline_preview": ({"status": "NOT_EXECUTED_INPUT_PREVIEW",
                                "generation_input": prepare_task_input(generation_task,
                                    generation_system_prompt=system)["generation_input"]}
                                if not prepared and system is not None else None),
                            "variants": variants})
    return comparisons


def _experiment_counts(assignments: list[dict]) -> dict:
    """Count assignments before any outcome filtering; seeds never create task units."""
    def counts(rows):
        return {"task_units": len({r["task_unit_id"] for r in rows}),
                "arms": list(dict.fromkeys(r["arm"] for r in rows)),
                "seeds": sorted({r["seed"] for r in rows}), "assignments": len(rows)}
    return {**counts(assignments), "by_policy": [
        {"policy_id": policy, **counts([r for r in assignments if r["policy_id"] == policy])}
        for policy in sorted({r["policy_id"] for r in assignments})]}


def _export_prompts(comparisons: list[dict], output: Path, generation_system_prompt: str | None) -> dict:
    """Readable companions to the same saved run; no prompt rewriting or new requests."""
    stem = output.with_suffix("")
    json_path = stem.with_name(stem.name + "-prompts.json")
    md_path = stem.with_name(stem.name + "-prompts.md")
    zip_path = stem.with_name(stem.name + "-prompts.zip")
    payload = {"source": "exact_saved_assignment_prompts", "generation_system_prompt": generation_system_prompt,
               "task_count": len(comparisons), "cases": comparisons,
               "prompt_version_count": sum(len(c["variants"]) for c in comparisons),
               "assignment_count": sum(len(v["assignments"]) for c in comparisons for v in c["variants"])}
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sections = ["# 导出范围内的全部五臂 Prompt 对照\n",
                f"本文件包含 {payload['task_count']} 个独立任务、{payload['prompt_version_count']} 个提示版本，对应 {payload['assignment_count']} 次已保存分配。\n",
                "以下为已保存分配的全部五臂文本：原始基线、任务重述、等词数风格、一般安全提醒、目标要求。相同文本按版本展示一次；种子不增加独立任务数。\n",
                "模型实际收到共用系统提示及含 language、task 的用户请求。下列文本是 task 字段；JSON/ZIP 同时包含完整请求。旧批次的占位符与输入限制保留原样。\n"]
    if generation_system_prompt is not None:
        sections += ["## 所有生成请求共用的系统提示\n", "````text\n" + generation_system_prompt + "\n````\n"]
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        if generation_system_prompt is not None:
            archive.writestr("generation-system.txt", generation_system_prompt.encode("utf-8"))
        for case in comparisons:
            # Display numbers can come from different source subsets. Bind archive
            # paths to the independent task as well, so unzipping cannot lose a case.
            folder = f"case-{case['case_number']:02d}-{case['task_id'][-12:]}"
            sections += [f"## CASE {case['case_number']:02d}\n", f"任务标识：`{case['task_id']}`\n",
                         f"用户请求的 language：`{case['language']}`；表示输入状态：`{case['input_alignment']}`。\n"]
            if case["original_prompt"] != case["baseline_prompt"]:
                sections += ["### 未修改的来源原文\n", "````text\n" + case["original_prompt"] + "\n````\n"]
            for i, variant in enumerate(case["variants"], 1):
                seeds = ", ".join(str(a["seed"]) for a in variant["assignments"])
                sections += [f"### {variant['label']} · {variant['arm']}\n",
                             f"种子：{seeds}；Prompt 标识：`{variant['prompt_sha256']}`\n",
                             "````text\n" + variant["prompt"] + "\n````\n"]
                archive.writestr(f"{folder}/{i:02d}-{variant['arm'].lower()}.txt",
                                 variant["prompt"].encode("utf-8"))
                archive.writestr(f"{folder}/{i:02d}-{variant['arm'].lower()}-request.json",
                                 json.dumps(variant["generation_input"], ensure_ascii=False, indent=2).encode("utf-8"))
        archive.writestr("prompts.json", json_path.read_bytes())
    md_path.write_text("\n".join(sections), encoding="utf-8")
    return {"markdown": md_path.name, "json": json_path.name, "zip": zip_path.name}


def _graph_edge_evidence(raw_graph: dict | None, contract: dict | None, prompt: str, catalog: dict | None) -> dict:
    """Validate each displayed graph against its own source and concept catalog."""
    edges = {}
    if raw_graph is None:
        return edges
    graph = prompt_tsg_from_record(raw_graph)
    if catalog is None:
        raise ValueError("graph's exact catalog is required for evidence verification")
    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    if contract and contract["schema_version"] == "3.0":
        local_nodes = {}
        for fact in contract["facts"]:
            start, end = _occurrence_span(prompt, fact["evidence_text"], fact["occurrence"])
            local_nodes[fact["local_id"]] = next(node.node_id for node in graph.nodes
                if node.semantic_id == fact["semantic_id"] and node.evidence_start == start and node.evidence_end == end)
        for row in contract["relations"]:
            edge = next(edge for edge in graph.edges if edge.source_id == local_nodes[row["source"]]
                        and edge.target_id == local_nodes[row["target"]] and edge.edge_type == row["edge_type"])
            start, end = _occurrence_span(prompt, row["evidence_text"], row["occurrence"])
            edges[edge.edge_id] = {"start": start, "end": end}
    return edges


def build_tsg_viewer(
    tasks_path: Path, extraction_roots: tuple[Path, ...], output: Path,
    *, results_root: Path | None = None, catalog_path: Path | None = None,
    review_root: Path | None = None,
) -> dict[str, Any]:
    """Export verified extraction bundles; no provider calls, filtering, or estimators."""
    tasks = {task["task_id"]: task for task in read_json(tasks_path)}
    cases: dict[str, dict] = {}
    reports = []
    for root in extraction_roots:
        verify_bundle(root)
        reports.append(read_json(root / "report.json"))
        catalogs = read_json(root / "catalogs.json") if (root / "catalogs.json").exists() else {}
        prepared_tasks = {task["task_id"]: task for task in read_json(root / "tasks.json")} if (root / "tasks.json").exists() else {}
        graphs = {row["task_id"]: row for row in read_json(root / "graphs.json")}
        contracts = {row["task_id"]: row for row in read_json(root / "contracts.json")}
        requests = ({row["task_id"]: row["request"] for row in read_json(root / "requests.json")}
                    if (root / "requests.json").exists() else {})
        comparisons = read_json(root / "comparison.json") if (root / "comparison.json").exists() else {}
        for response in read_json(root / "responses.json"):
            task_id = response["task_id"]
            if task_id in cases or task_id not in tasks:
                raise ValueError("viewer requires one extraction version per known task")
            task = prepared_tasks.get(task_id, tasks[task_id])
            if "generation_input" in task:
                prepare_task_input(task)
                if task["source_prompt"] != tasks[task_id].get("source_prompt", tasks[task_id]["prompt"]):
                    raise ValueError("represented prepared input has a different original source")
            raw_graph = graphs.get(task_id)
            contract = contracts.get(task_id)
            catalog = None
            if raw_graph:
                graph = prompt_tsg_from_record(raw_graph)
                catalog = catalogs.get(graph.catalog_sha256) or (contract or {}).get("catalog")
                if catalog is None and catalog_path is not None:
                    catalog = load_catalog(catalog_path)
            edges = _graph_edge_evidence(raw_graph, contract, task["prompt"], catalog)
            cases[task_id] = {"task_id": task_id, "prompt": task["prompt"],
                              "case_number": task.get("case_number", list(tasks).index(task_id) + 1),
                              "source_prompt": task.get("source_prompt", task["prompt"]),
                              "language": task.get("language", "unknown"), "source_label": task.get("cwe", ""),
                              "graph": raw_graph, "contract": contract, "catalog": catalog,
                              "edge_evidence": edges, "error": response.get("error_message"),
                              "annotation_response": response,
                              "inventory_request": requests.get(task_id),
                              "generation_input": task.get("generation_input"),
                              "graph_state": ("NO_GRAPH" if not raw_graph else
                                  ("BOUND_PARTIAL" if response.get("scope_assessment") else "INTERMEDIATE")
                                  if response.get("status") == "failed" else "COMPILED"),
                              "representation_status": response.get("representation_status", "automatic_extraction")}
            if raw_graph and contract and contract.get("schema_version") == "3.0":
                local_ids = {}
                for fact in contract["facts"]:
                    start, end = _occurrence_span(task["prompt"], fact["evidence_text"], fact["occurrence"])
                    local_ids[fact["local_id"]] = next(n["node_id"] for n in raw_graph["nodes"]
                        if n["semantic_id"] == fact["semantic_id"]
                        and n["evidence_start"] == start and n["evidence_end"] == end)
                cases[task_id]["local_node_ids"] = local_ids
                layers = contract.get("source_inventory", {}).get("layers", {})
                cases[task_id]["generation_node_ids"] = [node_id for local_id, node_id in local_ids.items()
                    if layers.get(local_id) == "generation" or local_id.startswith("template.")]
            if task_id in comparisons:
                comparison = comparisons[task_id]
                for version in comparison["versions"]:
                    version["edge_evidence"] = _graph_edge_evidence(
                        version["graph"], version["contract"], version["prompt"], version["catalog"])
                cases[task_id]["graph_comparison"] = comparison
    results = None
    if results_root is not None:
        verify_bundle(results_root)
        results = {"report": read_json(results_root / "report.json"),
                   "effects": read_json(results_root / "effects.json"),
                   "assignments": read_json(results_root / "assignments.json")}
        # Unrepresented tasks remain inspectable in the assigned-arm denominator.
        for row in results["assignments"]:
            task_id = row["task_id"]
            if task_id not in cases:
                task = tasks.get(task_id)
                if task is None:
                    raise ValueError("assigned task has no source prompt in the viewer input")
                cases[task_id] = {"task_id": task_id, "prompt": task["prompt"],
                                  "language": task.get("language", "unknown"), "source_label": task.get("cwe", ""),
                                  "graph": None, "contract": None, "catalog": None,
                                  "edge_evidence": {}, "error": "This task has no compiled graph in the selected extraction bundles."}
    payload = {"cases": list(cases.values()), "extraction_reports": reports, "results": results,
               "source_tasks_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest()}
    if review_root is not None:
        payload["debug_review"] = _attach_development_review(cases, review_root, extraction_roots)
    output.parent.mkdir(parents=True, exist_ok=True)
    if results is not None:
        system_prompt = None
        plan = None
        preoutcome = results_root.parent / "preoutcome"
        if preoutcome.is_dir():
            verify_bundle(preoutcome)
            plan = read_json(preoutcome / "plan.json")
            system_prompt = plan.get("generation_system_prompt")
            for task in plan["tasks"]:
                shown = cases[task["task_id"]]
                if shown.get("representation_status") == "source_reviewed_full_task_graph" and (
                    shown["prompt"] != task["prompt"] or shown["graph"] != task["graph"]
                ):
                    raise ValueError("displayed source-reviewed graph differs from the executed representation")
        comparisons = _prompt_comparisons(tasks, results["assignments"], plan)
        payload["experiment_counts"] = _experiment_counts(results["assignments"])
        payload["prompt_comparisons"] = comparisons
        payload["generation_system_prompt"] = system_prompt
        payload["prompt_exports"] = _export_prompts(comparisons, output, system_prompt)
    template = (Path(__file__).parent / "fixtures" / "tsg-viewer.html").read_text(encoding="utf-8")
    layout = (Path(__file__).parent / "fixtures" / "dagre.min.js").read_text(encoding="utf-8")
    template = template.replace("__DAGRE_SOURCE__", layout)
    layout = (Path(__file__).parent / "fixtures" / "dagre.min.js").read_text(encoding="utf-8")
    template = template.replace("__DAGRE_SOURCE__", layout)
    data = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(template.replace("__TSG_DATA__", data), encoding="utf-8")
    return {"status": "OFFLINE_TSG_VIEWER_WRITTEN", "output": str(output.resolve()),
            "tasks": len(cases), "compiled_graphs": sum(bool(row["graph"]) for row in cases.values()),
            "assigned_rows": len(results["assignments"]) if results else 0, "provider_calls": 0}


def _attach_development_review(cases: dict, root: Path, extraction_roots: tuple[Path, ...]) -> dict:
    """Attach saved judgments to their exact source/graph; never regrade an artifact.

    The existing development analysis bundle carries both directions of review:
    required source coverage and support for every generated assertion. Raw drafts
    stay separate from compiled graphs, including when a later stage failed.
    """
    verify_bundle(root)
    summary = read_json(root / "summary.json")
    if summary["execution_bundle_sha256"] not in {bundle_digest(p) for p in extraction_roots}:
        raise ValueError("review belongs to a different extraction bundle")
    results = {r["task_id"]: r for r in read_json(root / "case-results.json")}
    assertions = {r["task_id"]: r for r in read_json(root / "assertion-review.json")}
    sources = {r["task_id"]: r for r in read_json(root / "source-review.json")}
    reference = confined_path(root.parent, summary["calculation"]["reference"])
    if bundle_digest(reference.parent) != summary["input_bundle_sha256"]:
        raise ValueError("review reference differs from its frozen input bundle")
    expected = {r["task_id"]: r for r in read_json(reference)}
    for task_id, result in results.items():
        if task_id not in cases:
            raise ValueError("review contains a task not shown by the selected extraction")
        case, audit, source = cases[task_id], assertions[task_id], sources[task_id]
        if (audit["graph_sha256"] != content_hash(case["graph"])
                or audit["source_prompt_sha256"] != content_hash(case["prompt"])
                or source["source_prompt_sha256"] != content_hash(case["prompt"])
                or source["response_sha256"] != case["annotation_response"].get("response_sha256")):
            raise ValueError("review source, response or graph identity does not match")
        statements = open_graph_assertions(case["graph"])
        if set(audit["assertions"]) - set(statements):
            raise ValueError("review refers to an assertion absent from the displayed graph")
        items = [{"assertion_id": key, **statement,
                  "review": audit["assertions"].get(key, {"status": "UNREVIEWED"})}
                 for key, statement in statements.items()]
        checks = []
        expected_nodes = {n["key"]: n for n in expected[task_id]["nodes"]}
        for check in result["coverage"]["checks"]:
            row = dict(check)
            if check["kind"] == "node":
                node = expected_nodes[check["key"]]
                start, end = _occurrence_span(case["prompt"], node["evidence_text"], node["occurrence"])
                row["expected"] = node
                row["source_span"] = {"start": start, "end": end}
            checks.append(row)
        case["debug_review"] = {"result": result, "checks": checks,
                                "assertions": items, "source_review": source,
                                "reference": expected[task_id]}
    return {"summary": summary, "review_bundle_sha256": bundle_digest(root),
            "interpretation": "Saved development judgments; not independent qualification or a new evaluation."}
