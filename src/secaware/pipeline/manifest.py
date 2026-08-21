import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator

from secaware.pipeline.artifact import _atomic_write_text, canonical_sha256, sha256_path
from secaware.schema.common import VersionedModel


def _normalize_path(value: str | os.PathLike[str]) -> str:
    return Path(os.path.normpath(os.fspath(value))).as_posix()


_SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StageManifest(VersionedModel):
    stage: str
    fingerprint: str
    inputs: dict[str, str]
    config_sha256: str
    code_version: str
    policy_sha256: _SHA256 | None = None
    catalog_sha256: _SHA256 | None = None
    outputs: list[str] = Field(min_length=1)
    output_sha256: dict[str, _SHA256] = Field(default_factory=dict)

    @field_validator("inputs", mode="before")
    @classmethod
    def _normalize_input_paths(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        return {_normalize_path(path): digest for path, digest in value.items()}

    @field_validator("outputs", mode="before")
    @classmethod
    def _normalize_output_paths(cls, value: Any) -> Any:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return value
        return [_normalize_path(path) for path in value]

    @field_validator("output_sha256", mode="before")
    @classmethod
    def _normalize_output_hash_paths(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        return {_normalize_path(path): digest for path, digest in value.items()}

    @model_validator(mode="after")
    def _validate_output_hash_coverage(self) -> "StageManifest":
        policy_stage = self.stage.startswith("run-oracle-") or self.stage in {
            "extract-prompt-tsg",
            "build-confirmation-variants",
            "judge-functionality",
        }
        if policy_stage != (self.policy_sha256 is not None):
            raise ValueError("stage manifest policy binding is invalid")
        catalog_stage = self.stage in {
            "extract-prompt-tsg",
            "build-confirmation-variants",
        }
        if catalog_stage != (self.catalog_sha256 is not None):
            raise ValueError("stage manifest catalog binding is invalid")
        if len(set(self.outputs)) != len(self.outputs):
            raise ValueError("stage manifest outputs must be unique")
        if self.output_sha256 and set(self.output_sha256) != set(self.outputs):
            raise ValueError("stage manifest output hashes must cover every output")
        return self


def build_stage_fingerprint(
    stage: str,
    inputs: Mapping[str, str],
    config: Any,
    *,
    policy_sha256: str | None = None,
    catalog_sha256: str | None = None,
    stage_contract_sha256: str | None = None,
    code_version: str,
) -> str:
    return canonical_sha256(
        {
            "stage": stage,
            "inputs": inputs,
            "config_sha256": canonical_sha256(config),
            "policy_sha256": policy_sha256,
            "catalog_sha256": catalog_sha256,
            "stage_contract_sha256": stage_contract_sha256,
            "code_version": code_version,
        }
    )


def write_stage_manifest(path: str | Path, manifest: StageManifest) -> None:
    content = json.dumps(
        manifest.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    _atomic_write_text(path, content + "\n")


def read_stage_manifest(path: str | Path) -> StageManifest:
    return StageManifest.model_validate_json(Path(path).read_text(encoding="utf-8"))


def manifest_allows_skip(
    manifest_path: str | Path,
    expected_fingerprint: str,
    output_paths: Sequence[str | Path],
    *,
    force: bool = False,
    policy_sha256: str | None = None,
    catalog_sha256: str | None = None,
    manifest_outputs: Sequence[str | Path] | None = None,
) -> bool:
    if force or not output_paths:
        return False
    try:
        manifest = read_stage_manifest(manifest_path)
        normalized_outputs = [
            _normalize_path(path)
            for path in (output_paths if manifest_outputs is None else manifest_outputs)
        ]
    except (OSError, UnicodeError, TypeError, ValueError):
        return False
    if manifest.fingerprint != expected_fingerprint:
        return False
    if manifest.policy_sha256 != policy_sha256:
        return False
    if manifest.catalog_sha256 != catalog_sha256:
        return False
    if manifest.outputs != normalized_outputs:
        return False
    try:
        current_output_sha256 = {
            normalized_path: sha256_path(path)
            for normalized_path, path in zip(
                normalized_outputs,
                output_paths,
                strict=True,
            )
        }
    except (OSError, TypeError, ValueError):
        return False
    return manifest.output_sha256 == current_output_sha256
