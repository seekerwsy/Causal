"""Public discovery namespace with lazy optional RFCI exports."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from secaware.discovery.causal_learn_backend import run_causal_learn_fci
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner


_RFCI_EXPORTS = {
    "detect_rfci_capability": ("secaware.discovery.rfci_backend", "detect_rfci_capability"),
    "run_rfci_sensitivity": ("secaware.discovery.rfci_backend", "run_rfci_sensitivity"),
    "validate_rfci_sensitivity_result": (
        "secaware.discovery.rfci_backend",
        "validate_rfci_sensitivity_result",
    ),
}

__all__ = [
    "FCIRunner",
    "SpawnedFCIRunner",
    "detect_rfci_capability",
    "run_causal_learn_fci",
    "run_rfci_sensitivity",
    "validate_rfci_sensitivity_result",
]


def __getattr__(name: str) -> Any:
    target = _RFCI_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))
