"""Content-addressed graph-native intervention intents.

The transitions in this module are experimental intents over Prompt-TSG feature
states.  They are not causal edges and they never mutate the source Prompt TSG.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiments import (
    AllowedDeltaRecord,
    ArmRole,
    FeatureTransition,
)


class IntendedGraphPatchRecord(SafeValidationMixin, StrictModel):
    """One immutable intended feature-state patch, frozen before rendering."""

    _safe_validation_message: ClassVar[str] = "intended graph patch validation failed"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    schema_version: Literal["1.0"]
    patch_id: str = Field(pattern=r"^patch_[0-9a-f]{64}$")
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    target_instance_id: str = Field(pattern=r"^target_instance_[0-9a-f]{64}$")
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    protocol_instance_id: str = Field(pattern=r"^protocol_instance_[0-9a-f]{64}$")
    arm_role: ArmRole
    before_graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_delta_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_transitions: tuple[FeatureTransition, ...]

    @field_validator("arm_role", mode="before")
    @classmethod
    def parse_arm_role(cls, value: object) -> object:
        if type(value) is str:
            for role in ArmRole:
                if value == role.value:
                    return role
        return value

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload = {"schema_version": "1.0", **content}
        try:
            digest_payload = {
                "schema_version": "1.0",
                "target_spec_id": payload["target_spec_id"],
                "target_instance_id": payload["target_instance_id"],
                "arm_protocol_id": payload["arm_protocol_id"],
                "protocol_instance_id": payload["protocol_instance_id"],
                "arm_role": payload["arm_role"].value,
                "before_graph_sha256": payload["before_graph_sha256"],
                "allowed_delta_sha256": payload["allowed_delta_sha256"],
                "intended_transitions": [
                    item.model_dump(mode="json") for item in payload["intended_transitions"]
                ],
            }
            return cls(
                **payload,
                patch_id="patch_" + canonical_sha256(digest_payload),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            content.clear()
            payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        payload = self.model_dump(mode="json", exclude={"patch_id"})
        if self.patch_id != "patch_" + canonical_sha256(payload):
            raise ValueError(self._safe_validation_message)
        feature_ids = tuple(item.feature_id for item in self.intended_transitions)
        if feature_ids != tuple(sorted(feature_ids)) or len(feature_ids) != len(set(feature_ids)):
            raise ValueError(self._safe_validation_message)
        return self

    def __repr__(self) -> str:
        return "IntendedGraphPatchRecord()"

    def __str__(self) -> str:
        return "IntendedGraphPatchRecord()"


def allowed_delta_sha256(delta: AllowedDeltaRecord) -> str:
    """Digest one fully revalidated AllowedDelta without shadow clause data."""

    try:
        checked = AllowedDeltaRecord.model_validate(
            delta.model_dump(mode="python", round_trip=True, warnings=False)
        )
        return canonical_sha256(
            {
                "schema_version": "1.0",
                "kind": "allowed_delta",
                "allowed_delta": checked.model_dump(mode="json"),
            }
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise IntendedGraphPatchRecord._safe_error() from None


__all__ = ["IntendedGraphPatchRecord", "allowed_delta_sha256"]
