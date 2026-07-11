import math
from collections import Counter, defaultdict

from secaware.discovery.candidate_enum import FactorSpec
from secaware.schema.records import PromptRecord
from secaware.schema.results import LegacyOracleRecord, SecurityLabel
from secaware.schema.tsg import TSGRecord


def _risk_rate(records: list[LegacyOracleRecord]) -> float:
    known = [record for record in records if record.security_label != SecurityLabel.UNKNOWN]
    if not known:
        return 0.0
    insecure = sum(1 for record in known if record.security_label == SecurityLabel.INSECURE)
    return insecure / len(known)


def association_score(
    spec: FactorSpec,
    prompt_tsgs: list[TSGRecord],
    oracle_by_prompt: dict[str, list[LegacyOracleRecord]],
) -> tuple[float, float, dict[str, int]]:
    present_ids = [tsg.prompt_id for tsg in prompt_tsgs if bool(tsg.features.get(spec.prompt_factor))]
    absent_ids = [tsg.prompt_id for tsg in prompt_tsgs if not bool(tsg.features.get(spec.prompt_factor))]
    present_oracles = [record for pid in present_ids for record in oracle_by_prompt.get(pid, [])]
    absent_oracles = [record for pid in absent_ids for record in oracle_by_prompt.get(pid, [])]
    raw = _risk_rate(absent_oracles) - _risk_rate(present_oracles)
    support = {
        "n_total": len(prompt_tsgs),
        "n_present": len(present_ids),
        "n_absent": len(absent_ids),
        "n_insecure": sum(
            1
            for records in oracle_by_prompt.values()
            for record in records
            if record.security_label == SecurityLabel.INSECURE
        ),
    }
    return max(0.0, raw), raw, support


def path_score(
    spec: FactorSpec,
    prompt_tsgs: list[TSGRecord],
    code_tsg_by_prompt: dict[str, list[TSGRecord]],
    oracle_by_prompt: dict[str, list[LegacyOracleRecord]],
) -> float:
    absent = [tsg for tsg in prompt_tsgs if not bool(tsg.features.get(spec.prompt_factor))]
    if not absent:
        return 0.0
    prompt_motif_key = f"motif.{spec.prompt_motif}"
    motif_absent = [tsg for tsg in absent if bool(tsg.features.get(prompt_motif_key))]
    p_motif_given_absent = len(motif_absent) / len(absent)
    motif_prompt_ids = {
        tsg.prompt_id
        for tsg in absent
        if tsg.features.get(prompt_motif_key)
        or any(code_tsg.features.get(spec.code_motif) for code_tsg in code_tsg_by_prompt.get(tsg.prompt_id, []))
    }
    motif_oracles = [record for pid in motif_prompt_ids for record in oracle_by_prompt.get(pid, [])]
    p_insecure_given_motif = _risk_rate(motif_oracles)
    score = p_motif_given_absent * p_insecure_given_motif
    if spec.cwe != "generic" and any(
        finding.cwe == spec.cwe for record in motif_oracles for finding in record.findings
    ):
        score += 0.1
    return min(1.0, score)


def stability_score(
    spec: FactorSpec,
    prompts: list[PromptRecord],
    prompt_tsg_by_id: dict[str, TSGRecord],
    oracle_by_prompt: dict[str, list[LegacyOracleRecord]],
) -> float:
    groups: dict[str, list[TSGRecord]] = defaultdict(list)
    for prompt in prompts:
        groups[prompt.task_family].append(prompt_tsg_by_id[prompt.prompt_id])
    if len(groups) <= 1:
        return 0.5
    expected = 0
    for tsgs in groups.values():
        _, raw, support = association_score(spec, tsgs, oracle_by_prompt)
        if support["n_present"] and support["n_absent"] and raw > 0:
            expected += 1
    return expected / len(groups)


def nuisance_penalty(
    spec: FactorSpec,
    prompts: list[PromptRecord],
    prompt_tsg_by_id: dict[str, TSGRecord],
) -> float:
    if not prompts:
        return 0.0
    values = [1.0 if prompt_tsg_by_id[p.prompt_id].features.get(spec.prompt_factor) else 0.0 for p in prompts]
    lengths = [float(len(p.prompt.split())) for p in prompts]
    if len(set(values)) <= 1 or len(set(lengths)) <= 1:
        length_corr_abs = 0.0
    else:
        mean_v = sum(values) / len(values)
        mean_l = sum(lengths) / len(lengths)
        cov = sum(
            (value - mean_v) * (length - mean_l)
            for value, length in zip(values, lengths, strict=True)
        )
        var_v = sum((v - mean_v) ** 2 for v in values)
        var_l = sum((length - mean_l) ** 2 for length in lengths)
        length_corr_abs = abs(cov / math.sqrt(var_v * var_l)) if var_v and var_l else 0.0
    family_counts = Counter(p.task_family for p, value in zip(prompts, values, strict=True) if value)
    present_count = sum(family_counts.values())
    concentration = max(family_counts.values()) / present_count if present_count else 0.0
    scope_concentration_penalty = max(0.0, concentration - 0.8)
    return min(1.0, 0.5 * length_corr_abs + scope_concentration_penalty)
