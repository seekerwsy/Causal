"""Frozen identities for replaceable external method components."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.records import content_id, require_text


class AdapterKind(StrEnum):
    REPRESENTATION = "representation"
    SELECTOR = "selector"
    INTERVENTION_EXECUTOR = "intervention_executor"
    GENERATOR = "generator"
    SECURITY_ORACLE = "security_oracle"
    FUNCTIONAL_EVALUATOR = "functional_evaluator"


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    kind: AdapterKind
    name: str
    version: str
    policy_sha256: str

    def __post_init__(self) -> None:
        if type(self.kind) is not AdapterKind:
            raise TypeError("kind must be an AdapterKind")
        require_text(self.name, "adapter name")
        require_text(self.version, "adapter version")
        if len(self.policy_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.policy_sha256
        ):
            raise ValueError("policy_sha256 must be a lowercase SHA-256 digest")

    @property
    def adapter_id(self) -> str:
        return content_id("adapter_", self)


@dataclass(frozen=True, slots=True)
class AdapterBundle:
    representation: AdapterSpec
    selector: AdapterSpec
    intervention_executor: AdapterSpec
    generator: AdapterSpec
    security_oracle: AdapterSpec
    functional_evaluator: AdapterSpec

    def __post_init__(self) -> None:
        expected = (
            AdapterKind.REPRESENTATION,
            AdapterKind.SELECTOR,
            AdapterKind.INTERVENTION_EXECUTOR,
            AdapterKind.GENERATOR,
            AdapterKind.SECURITY_ORACLE,
            AdapterKind.FUNCTIONAL_EVALUATOR,
        )
        actual = tuple(
            item.kind
            for item in (
                self.representation,
                self.selector,
                self.intervention_executor,
                self.generator,
                self.security_oracle,
                self.functional_evaluator,
            )
        )
        if actual != expected:
            raise ValueError("adapter bundle kinds are not exact")

    @property
    def adapter_bundle_id(self) -> str:
        return content_id("adapters_", self)


__all__ = ["AdapterBundle", "AdapterKind", "AdapterSpec"]
