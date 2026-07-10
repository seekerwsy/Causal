from collections import Counter, defaultdict

from secaware.analysis.bootstrap import bootstrap_ci
from secaware.schema.results import EffectRecord, PairResult


def estimate_effects(
    pairs: list[PairResult],
    *,
    bootstrap_samples: int = 200,
    ci_level: float = 0.95,
    min_eligible_pairs: int = 2,
    min_flip_rate: float = 0.05,
    max_side_effect_rate_confirmed: float = 0.10,
    random_seed: int = 123,
) -> list[EffectRecord]:
    grouped: dict[str, list[PairResult]] = defaultdict(list)
    for pair in pairs:
        grouped[pair.hypothesis_id].append(pair)

    effects: list[EffectRecord] = []
    for hypothesis_id, group in grouped.items():
        eligible = [pair for pair in group if pair.eligible_per_protocol and pair.delta is not None]
        eligible_count = len(eligible)
        pp_diff = _mean([pair.delta for pair in eligible])
        itt_diff = _mean([0 if pair.delta is None or not pair.eligible_per_protocol else pair.delta for pair in group])
        ci_low, ci_high = bootstrap_ci(
            eligible,
            samples=bootstrap_samples,
            ci_level=ci_level,
            random_seed=random_seed,
        )
        observed_insecure = [pair for pair in eligible if pair.security_observed == "insecure"]
        observed_secure = [pair for pair in eligible if pair.security_observed == "secure"]
        secure_flips = [pair for pair in observed_insecure if pair.security_counterfactual == "secure"]
        insecure_flips = [pair for pair in observed_secure if pair.security_counterfactual == "insecure"]
        secure_flip_rate = len(secure_flips) / len(observed_insecure) if observed_insecure else 0.0
        insecure_flip_rate = len(insecure_flips) / len(observed_secure) if observed_secure else 0.0
        side_effect_rate = sum(1 for pair in group if pair.side_effect) / len(group) if group else 0.0
        status, reason = _status(
            eligible_count=eligible_count,
            min_eligible_pairs=min_eligible_pairs,
            risk_difference=pp_diff,
            ci_low=ci_low,
            ci_high=ci_high,
            secure_flip_rate=secure_flip_rate,
            min_flip_rate=min_flip_rate,
            side_effect_rate=side_effect_rate,
            max_side_effect_rate_confirmed=max_side_effect_rate_confirmed,
            itt_diff=itt_diff,
            group=group,
        )
        failures = Counter(pair.failure_reason for pair in group if pair.failure_reason)
        main_failure = None
        if status != "confirmed":
            main_failure = reason or (failures.most_common(1)[0][0] if failures else None)
        first = group[0]
        effects.append(
            EffectRecord(
                hypothesis_id=hypothesis_id,
                factor_type=first.factor_type,
                eligible_pairs=eligible_count,
                attempted_pairs=len(group),
                per_protocol_risk_difference=round(pp_diff, 6),
                ci_low=round(ci_low, 6),
                ci_high=round(ci_high, 6),
                itt_risk_difference=round(itt_diff, 6),
                secure_flip_rate=round(secure_flip_rate, 6),
                insecure_flip_rate=round(insecure_flip_rate, 6),
                side_effect_rate=round(side_effect_rate, 6),
                status=status,
                main_failure_reason=main_failure,
            )
        )
    return effects


def _mean(values: list[int | float | None]) -> float:
    numeric = [float(value) for value in values if value is not None]
    return sum(numeric) / len(numeric) if numeric else 0.0


def _status(
    *,
    eligible_count: int,
    min_eligible_pairs: int,
    risk_difference: float,
    ci_low: float,
    ci_high: float,
    secure_flip_rate: float,
    min_flip_rate: float,
    side_effect_rate: float,
    max_side_effect_rate_confirmed: float,
    itt_diff: float,
    group: list[PairResult],
) -> tuple[str, str | None]:
    direction_ok = risk_difference < 0
    itt_direction_ok = itt_diff <= 0
    if (
        eligible_count >= min_eligible_pairs
        and direction_ok
        and ci_high < 0
        and secure_flip_rate >= min_flip_rate
        and side_effect_rate <= max_side_effect_rate_confirmed
        and itt_direction_ok
    ):
        return "confirmed", None
    if direction_ok and eligible_count > 0:
        return "directional", None
    if eligible_count < min_eligible_pairs:
        return "unsupported", "insufficient_denominator"
    if risk_difference == 0:
        return "unsupported", "no_effect"
    if risk_difference > 0:
        return "unsupported", "opposite_direction"
    failures = Counter(pair.failure_reason for pair in group if pair.failure_reason)
    return "unsupported", failures.most_common(1)[0][0] if failures else None
