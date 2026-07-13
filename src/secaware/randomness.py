"""Versioned deterministic randomness for persisted experiment manifests."""

from __future__ import annotations

from collections.abc import Sequence
import hashlib
from typing import TypeVar


RNG_VERSION = "sha256-rejection-fisher-yates-v1"

_BLOCK_SPACE = 1 << 256
_COUNTER_LIMIT = 1 << 128
_MAX_SEED_MATERIAL_BYTES = 1024 * 1024
_MAX_SEQUENCE_ITEMS = 100_000

T = TypeVar("T")


class DeterministicRNG:
    """SHA-256 counter RNG with rejection sampling and Fisher-Yates shuffle."""

    def __init__(self, seed_material: bytes) -> None:
        if (
            type(seed_material) is not bytes
            or not seed_material
            or len(seed_material) > _MAX_SEED_MATERIAL_BYTES
        ):
            raise ValueError("seed material must be non-empty bounded bytes")
        self._seed = hashlib.sha256(seed_material).digest()
        self._counter = 0

    def _next_block(self) -> int:
        if type(self._counter) is not int or self._counter < 0 or self._counter >= _COUNTER_LIMIT:
            raise ValueError("deterministic RNG counter exhausted")
        block = hashlib.sha256(self._seed + self._counter.to_bytes(16, "big")).digest()
        self._counter += 1
        return int.from_bytes(block, "big")

    def randbelow(self, upper: int) -> int:
        if type(upper) is not int or not 0 < upper <= _BLOCK_SPACE:
            raise ValueError("upper bound must be a positive representable integer")
        limit = _BLOCK_SPACE - (_BLOCK_SPACE % upper)
        while True:
            value = self._next_block()
            if value < limit:
                return value % upper

    def choice(self, values: Sequence[T]) -> T:
        size = _validated_size(values)
        if size == 0:
            raise ValueError("cannot choose from an empty sequence")
        return values[self.randbelow(size)]

    def shuffle(self, values: Sequence[T]) -> tuple[T, ...]:
        size = _validated_size(values)
        result = [values[index] for index in range(size)]
        for index in range(size - 1, 0, -1):
            selected = self.randbelow(index + 1)
            result[index], result[selected] = result[selected], result[index]
        return tuple(result)


def _validated_size(values: Sequence[object]) -> int:
    try:
        size = len(values)
    except Exception:
        raise ValueError("sequence failed validation") from None
    if type(size) is not int or size < 0:
        raise ValueError("sequence failed validation")
    if size > _MAX_SEQUENCE_ITEMS:
        raise ValueError("sequence contains too many items")
    return size


__all__ = ["DeterministicRNG", "RNG_VERSION"]
