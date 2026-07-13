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
