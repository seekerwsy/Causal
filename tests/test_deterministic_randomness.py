from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest


def test_rng_has_exact_golden_vectors() -> None:
    from secaware.randomness import DeterministicRNG, RNG_VERSION

    rng = DeterministicRNG(b"golden-seed")

    assert RNG_VERSION == "sha256-rejection-fisher-yates-v1"
    assert [rng.randbelow(upper) for upper in (2, 3, 10, 257, 2**255 + 1)] == [
        1,
        0,
        2,
        9,
        35293522378306970534453866118909997435314398998646297089768606943955178498543,
    ]
    assert DeterministicRNG(b"shuffle-seed").shuffle(tuple(range(8))) == (
        4,
        7,
        3,
        6,
        5,
        2,
        1,
        0,
    )


@pytest.mark.parametrize("seed_material", ("bytes-only", bytearray(b"no"), memoryview(b"no")))
def test_rng_rejects_non_exact_bytes(seed_material: object) -> None:
    from secaware.randomness import DeterministicRNG

    with pytest.raises(ValueError, match="seed material"):
        DeterministicRNG(seed_material)  # type: ignore[arg-type]


@pytest.mark.parametrize("upper", (True, False, 0, -1, 1.0, 2**256 + 1))
def test_randbelow_rejects_non_integer_or_unrepresentable_bounds(upper: object) -> None:
    from secaware.randomness import DeterministicRNG

    with pytest.raises(ValueError, match="upper bound"):
        DeterministicRNG(b"bounds").randbelow(upper)  # type: ignore[arg-type]


def test_choice_and_shuffle_are_bounded_and_do_not_mutate_input() -> None:
    from secaware.randomness import DeterministicRNG

    values = ["a", "b", "c"]
    rng = DeterministicRNG(b"sequences")

    assert rng.choice(values) in values
    shuffled = rng.shuffle(values)
    assert sorted(shuffled) == values
    assert values == ["a", "b", "c"]
    with pytest.raises(ValueError, match="empty"):
        rng.choice(())
    with pytest.raises(ValueError, match="too many"):
        rng.shuffle(_OverlongSequence())


@pytest.mark.parametrize("counter", (-1, True, 1.0, 2**128))
def test_counter_overflow_fails_closed_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
    counter: object,
) -> None:
    import secaware.randomness as randomness

    rng = randomness.DeterministicRNG(b"counter")
    rng._counter = counter  # type: ignore[attr-defined]
    calls: list[object] = []
    monkeypatch.setattr(randomness.hashlib, "sha256", lambda value: calls.append(value))

    with pytest.raises(ValueError, match="counter exhausted"):
        rng.randbelow(2)
    assert calls == []


def test_randomness_module_never_imports_python_random() -> None:
    source = Path("src/secaware/randomness.py").read_text(encoding="utf-8")

    assert "import random" not in source
    assert "from random" not in source


class _OverlongSequence(Sequence[int]):
    def __len__(self) -> int:
        return 100_001

    def __getitem__(self, index: int) -> int:
        if not 0 <= index < len(self):
            raise IndexError
        return index
