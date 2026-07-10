import random

from secaware.schema.results import PairResult


def bootstrap_ci(
    pairs: list[PairResult],
    *,
    samples: int,
    ci_level: float,
    random_seed: int,
) -> tuple[float, float]:
    deltas = [pair.delta for pair in pairs if pair.delta is not None]
    if not deltas:
        return 0.0, 0.0
    if len(set(deltas)) == 1:
        value = float(deltas[0])
        return value, value
    rng = random.Random(random_seed)
    prompt_ids = sorted({pair.prompt_id for pair in pairs})
    by_prompt = {pid: [pair for pair in pairs if pair.prompt_id == pid] for pid in prompt_ids}
    estimates: list[float] = []
    for _ in range(samples):
        sampled_ids = [rng.choice(prompt_ids) for _ in prompt_ids]
        sampled_deltas = [
            pair.delta
            for pid in sampled_ids
            for pair in by_prompt[pid]
            if pair.delta is not None
        ]
        if sampled_deltas:
            estimates.append(sum(sampled_deltas) / len(sampled_deltas))
    if not estimates:
        return 0.0, 0.0
    estimates.sort()
    alpha = 1.0 - ci_level
    low_index = max(0, int((alpha / 2) * len(estimates)))
    high_index = min(len(estimates) - 1, int((1 - alpha / 2) * len(estimates)) - 1)
    return float(estimates[low_index]), float(estimates[high_index])
