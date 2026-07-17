"""Small discrete SCMs with fixed domains and explicit latent structure."""

from __future__ import annotations

import numpy as np
import pandas as pd


def true_chain_scm(n: int, seed: int) -> pd.DataFrame:
    """Return observations from X -> Z -> Y with independent bit-flip noise."""
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 2, size=n)
    z = np.bitwise_xor(x, rng.binomial(1, 0.10, size=n))
    y = np.bitwise_xor(z, rng.binomial(1, 0.10, size=n))
    return pd.DataFrame(
        {
            "x.feature": x,
            "x.prompt_motif": z,
            "y.secure_functional": y,
        }
    )


def latent_confounding_scm(n: int, seed: int) -> pd.DataFrame:
    """Return two same-tier prompt proxies with a shared unobserved binary parent."""
    rng = np.random.default_rng(seed)
    u = rng.integers(0, 2, size=n)
    x = np.bitwise_xor(u, rng.binomial(1, 0.10, size=n))
    y = np.bitwise_xor(u, rng.binomial(1, 0.10, size=n))
    return pd.DataFrame({"x.feature": x, "x.peer": y})


def null_factor_scm(n: int, seed: int) -> pd.DataFrame:
    """Return an independent prompt factor and outcome."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "x.null": rng.integers(0, 2, size=n),
            "y.secure_functional": rng.integers(0, 2, size=n),
        }
    )


def deterministic_context_scm(n_per_arm: int, seed: int) -> pd.DataFrame:
    """Return four randomized arms with a deterministic target-feature relation."""
    rng = np.random.default_rng(seed)
    context = np.repeat(np.arange(4, dtype=np.int64), n_per_arm)
    target_feature = (context == 0).astype(np.int64)
    noise = rng.binomial(1, 0.10, size=context.size)
    outcome = np.bitwise_xor(target_feature, noise)
    return pd.DataFrame(
        {
            "c.arm": context,
            "x.target_feature": target_feature,
            "y.secure_functional": outcome,
        }
    )
