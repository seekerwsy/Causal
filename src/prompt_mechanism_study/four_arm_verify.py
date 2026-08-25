"""Independent verifier for the closed four-arm analysis bundle."""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle

ARMS = ("absent", "specific", "generic", "placebo")
CONTRASTS = (("specific", "placebo"), ("specific", "absent"), ("specific", "generic"))
METRICS = ("secure_yield", "code_valid", "oracle_evaluable", "functionality", "joint")


def verify_analysis(config_path: Path, tasks_path: Path, analysis_root: Path) -> dict[str, Any]:
    """Recompute all reported arm counts, paired effects, and simultaneous intervals."""

    verify_bundle(analysis_root)
    config = read_json(config_path)
    report = read_json(analysis_root / "report.json")
    measurements = read_json(analysis_root / "measurements.json")
    tasks = [json.loads(line) for line in tasks_path.read_text(encoding="utf-8").splitlines()]
    expected = {(task["task_id"], arm) for task in tasks for arm in ARMS}
    observed = {(row["task_id"], row["arm"]) for row in measurements}
    if observed != expected or len(measurements) != len(expected):
        raise ValueError("analysis ledger is incomplete or duplicated")
    by_key = {(row["task_id"], row["arm"]): row for row in measurements}

    arms = {}
    for arm in ARMS:
        arms[arm] = {}
        for metric in METRICS:
            values = [_metric(by_key[task["task_id"], arm], metric) for task in tasks]
            arms[arm][metric] = {
                "point": _mean(item[0] for item in values),
                "lower": _mean(item[1] for item in values),
                "upper": _mean(item[2] for item in values),
            }
            _same(arms[arm][metric], report["arms"][arm][metric])

    secure_series = []
    for treatment, control in CONTRASTS:
        name = f"{treatment}_minus_{control}"
        stored = next(row for row in report["contrasts"] if row["contrast"] == name)
        for metric in METRICS:
            differences = [
                _metric(by_key[task["task_id"], treatment], metric)[0]
                - _metric(by_key[task["task_id"], control], metric)[0]
                for task in tasks
            ]
            expected_metric = {
                "difference": _mean(differences),
                "improved": sum(value > 0 for value in differences),
                "harmed": sum(value < 0 for value in differences),
                "unchanged": sum(value == 0 for value in differences),
            }
            _same(expected_metric, stored["metrics"][metric])
            if metric == "secure_yield":
                secure_series.append(differences)

    intervals, critical = _simultaneous_intervals(secure_series, config["analysis"])
    _same(critical, report["simultaneous_critical_value"])
    for stored, interval in zip(report["contrasts"], intervals, strict=True):
        _same(interval, stored["metrics"]["secure_yield"]["simultaneous_interval"])
    if (
        report["tasks"] != len(tasks)
        or report["assignments"] != len(measurements)
        or report["cwe_counts"] != dict(sorted(Counter(task["cwe"] for task in tasks).items()))
    ):
        raise ValueError("analysis population summary drifted")
    return {
        "status": "FOUR_ARM_ANALYSIS_VERIFIED",
        "tasks": len(tasks),
        "assignments": len(measurements),
        "analysis_bundle_sha256": bundle_digest(analysis_root),
    }


def _metric(row: Mapping[str, Any], metric: str) -> tuple[int, int, int]:
    code = int(row["code_status"] == "valid")
    evaluable = int(row["oracle_status"] in {"secure", "insecure"})
    secure = int(row["oracle_status"] == "secure")
    unknown = int(row["oracle_status"] == "unknown")
    functional = int(row["functional_status"] == "pass")
    return {
        "code_valid": (code, code, code),
        "oracle_evaluable": (evaluable, evaluable, evaluable),
        "secure_yield": (secure, secure, secure + unknown),
        "functionality": (functional, functional, functional),
        "joint": (secure * functional, secure * functional, (secure + unknown) * functional),
    }[metric]


def _simultaneous_intervals(
    series: Sequence[Sequence[float]], config: Mapping[str, Any]
) -> tuple[list[list[float]], float]:
    points = [_mean(values) for values in series]
    rng = random.Random(config["bootstrap_seed"])
    draws = [[] for _ in series]
    for _ in range(config["bootstrap_draws"]):
        indexes = [rng.randrange(len(series[0])) for _ in series[0]]
        for position, values in enumerate(series):
            draws[position].append(_mean(values[index] for index in indexes))
    standard_errors = [_stdev(values) for values in draws]
    maxima = [
        max(
            (
                abs(draws[index][draw] - points[index]) / standard_errors[index]
                for index in range(len(series))
                if standard_errors[index] > 0
            ),
            default=0.0,
        )
        for draw in range(config["bootstrap_draws"])
    ]
    critical = _quantile(maxima, 1.0 - config["familywise_alpha"])
    return [
        [max(-1.0, point - critical * error), min(1.0, point + critical * error)]
        for point, error in zip(points, standard_errors, strict=True)
    ], critical


def _mean(values: Sequence[float] | Any) -> float:
    materialized = list(values)
    return sum(materialized) / len(materialized)


def _stdev(values: Sequence[float]) -> float:
    mean = _mean(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


def _same(expected: Any, observed: Any) -> None:
    if isinstance(expected, Mapping):
        for key, value in expected.items():
            _same(value, observed[key])
    elif isinstance(expected, list):
        if len(expected) != len(observed):
            raise ValueError("analysis sequence length drifted")
        for left, right in zip(expected, observed, strict=True):
            _same(left, right)
    elif isinstance(expected, float):
        if not math.isclose(expected, observed, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("analysis numeric value drifted")
    elif expected != observed:
        raise ValueError("analysis value drifted")


__all__ = ["verify_analysis"]
