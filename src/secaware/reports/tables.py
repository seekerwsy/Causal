import csv
from collections import Counter, defaultdict
from pathlib import Path

from secaware.io.jsonl import write_jsonl
from secaware.reports.mechanism_cards import build_mechanism_card
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import PromptRecord
from secaware.schema.results import EffectRecord, PairResult


def write_reports(
    report_dir: str | Path,
    *,
    prompts: list[PromptRecord],
    hypotheses_all: list[HypothesisRecord],
    hypotheses_selected: list[HypothesisRecord],
    interventions: list[InterventionRecord],
    pairs: list[PairResult],
    effects: list[EffectRecord],
) -> None:
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    write_funnel(report_dir / "funnel.csv", hypotheses_selected, interventions, pairs, effects)
    write_effects(report_dir / "effects.csv", hypotheses_selected, effects)
    write_failures(report_dir / "failures.csv", interventions, pairs)
    write_cards(report_dir / "mechanism_cards.jsonl", hypotheses_selected, interventions, effects)
    write_summary(
        report_dir / "summary.md",
        prompts=prompts,
        hypotheses_all=hypotheses_all,
        hypotheses_selected=hypotheses_selected,
        interventions=interventions,
        effects=effects,
    )


def write_funnel(
    path: Path,
    hypotheses: list[HypothesisRecord],
    interventions: list[InterventionRecord],
    pairs: list[PairResult],
    effects: list[EffectRecord],
) -> None:
    effect_by_h = {effect.hypothesis_id: effect for effect in effects}
    pairs_by_h: dict[str, list[PairResult]] = defaultdict(list)
    interventions_by_h: dict[str, list[InterventionRecord]] = defaultdict(list)
    for pair in pairs:
        pairs_by_h[pair.hypothesis_id].append(pair)
    for intervention in interventions:
        interventions_by_h[intervention.hypothesis_id].append(intervention)
    rows = []
    for hypothesis in hypotheses:
        h_interventions = interventions_by_h[hypothesis.hypothesis_id]
        h_pairs = pairs_by_h[hypothesis.hypothesis_id]
        effect = effect_by_h.get(hypothesis.hypothesis_id)
        rows.append(
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "factor_type": hypothesis.factor_type.value,
                "attempted_interventions": len(h_interventions),
                "patch_success": sum(1 for item in h_interventions if item.patch_success),
                "round_trip_valid": sum(1 for item in h_interventions if item.round_trip_valid),
                "semantic_valid": sum(1 for item in h_interventions if item.semantic_valid),
                "target_changed": sum(1 for item in h_interventions if item.target_changed),
                "functional_preserved": sum(
                    1 for pair in h_pairs if pair.functional_observed and pair.functional_counterfactual
                ),
                "eligible_pairs": effect.eligible_pairs if effect else 0,
                "confirmed_pairs": sum(1 for pair in h_pairs if pair.flip_type == "secure_flip"),
                "status": effect.status if effect else "unsupported",
            }
        )
    _write_csv(path, rows)


def write_effects(
    path: Path,
    hypotheses: list[HypothesisRecord],
    effects: list[EffectRecord],
) -> None:
    hypothesis_by_id = {hypothesis.hypothesis_id: hypothesis for hypothesis in hypotheses}
    rows = []
    for effect in effects:
        hypothesis = hypothesis_by_id.get(effect.hypothesis_id)
        rows.append(
            {
                "hypothesis_id": effect.hypothesis_id,
                "factor_type": effect.factor_type,
                "scope_cwe": hypothesis.scope.get("cwe", "") if hypothesis else effect.scope_cwe,
                "scope_task_family": (
                    hypothesis.scope.get("task_family", "") if hypothesis else effect.scope_task_family
                ),
                "eligible_pairs": effect.eligible_pairs,
                "per_protocol_risk_difference": effect.per_protocol_risk_difference,
                "ci_low": effect.ci_low,
                "ci_high": effect.ci_high,
                "itt_risk_difference": effect.itt_risk_difference,
                "secure_flip_rate": effect.secure_flip_rate,
                "insecure_flip_rate": effect.insecure_flip_rate,
                "side_effect_rate": effect.side_effect_rate,
                "status": effect.status,
                "main_failure_reason": effect.main_failure_reason or "",
            }
        )
    _write_csv(path, rows)


def write_failures(
    path: Path,
    interventions: list[InterventionRecord],
    pairs: list[PairResult],
) -> None:
    examples: dict[tuple[str, str], tuple[str, str]] = {}
    counts: Counter[tuple[str, str]] = Counter()
    for intervention in interventions:
        if intervention.failure_reason:
            key = (intervention.failure_reason.value, intervention.factor_type.value)
            counts[key] += 1
            examples.setdefault(key, (intervention.prompt_id, intervention.hypothesis_id))
    for pair in pairs:
        if pair.failure_reason:
            key = (pair.failure_reason, pair.factor_type)
            counts[key] += 1
            examples.setdefault(key, (pair.prompt_id, pair.hypothesis_id))
    rows = [
        {
            "failure_reason": reason,
            "count": count,
            "factor_type": factor_type,
            "example_prompt_id": examples[(reason, factor_type)][0],
            "example_hypothesis_id": examples[(reason, factor_type)][1],
        }
        for (reason, factor_type), count in counts.items()
    ]
    _write_csv(path, rows)


def write_cards(
    path: Path,
    hypotheses: list[HypothesisRecord],
    interventions: list[InterventionRecord],
    effects: list[EffectRecord],
) -> None:
    effect_by_h = {effect.hypothesis_id: effect for effect in effects}
    attempted = Counter(intervention.hypothesis_id for intervention in interventions)
    cards = [
        build_mechanism_card(
            hypothesis,
            effect_by_h.get(hypothesis.hypothesis_id),
            attempted=attempted[hypothesis.hypothesis_id],
        )
        for hypothesis in hypotheses
    ]
    write_jsonl(path, cards)


def write_summary(
    path: Path,
    *,
    prompts: list[PromptRecord],
    hypotheses_all: list[HypothesisRecord],
    hypotheses_selected: list[HypothesisRecord],
    interventions: list[InterventionRecord],
    effects: list[EffectRecord],
) -> None:
    discover_count = sum(1 for prompt in prompts if prompt.split == "discover")
    confirm_count = sum(1 for prompt in prompts if prompt.split == "confirm")
    confirmed = sum(1 for effect in effects if effect.status == "confirmed")
    directional = sum(1 for effect in effects if effect.status == "directional")
    unsupported = sum(1 for effect in effects if effect.status == "unsupported")
    lines = [
        "# SecAware Run Summary",
        "",
        "## Dataset",
        f"number of prompts: {len(prompts)}",
        f"discover prompts: {discover_count}",
        f"confirm prompts: {confirm_count}",
        "",
        "## Discovery",
        f"number of candidate hypotheses: {len(hypotheses_all)}",
        f"number of selected hypotheses: {len(hypotheses_selected)}",
        "",
        "## Intervention",
        f"attempted interventions: {len(interventions)}",
        f"semantic-valid interventions: {sum(1 for item in interventions if item.semantic_valid)}",
        f"target-changing interventions: {sum(1 for item in interventions if item.target_changed)}",
        "",
        "## Confirmation",
        f"confirmed mechanisms: {confirmed}",
        f"directional mechanisms: {directional}",
        f"unsupported mechanisms: {unsupported}",
        "",
        "## Main Effects",
        "| hypothesis_id | factor_type | risk_difference | CI | status |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for effect in effects:
        lines.append(
            f"| {effect.hypothesis_id} | {effect.factor_type} | "
            f"{effect.per_protocol_risk_difference:.3f} | "
            f"[{effect.ci_low:.3f}, {effect.ci_high:.3f}] | {effect.status} |"
        )
    lines.extend(["", "## Main Failures"])
    failure_counts = Counter(effect.main_failure_reason for effect in effects if effect.main_failure_reason)
    if failure_counts:
        for reason, count in failure_counts.most_common():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("- none")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if rows:
        fields = list(rows[0].keys())
    else:
        fields = ["empty"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
