import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from secaware.pipeline.artifact import _atomic_write_text, canonical_sha256
from secaware.schema.common import VersionedModel


def _normalize_path(value: str | os.PathLike[str]) -> str:
    return Path(os.path.normpath(os.fspath(value))).as_posix()


class StageManifest(VersionedModel):
    stage: str
    fingerprint: str
    inputs: dict[str, str]
    config_sha256: str
    code_version: str
    outputs: list[str] = Field(min_length=1)

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


def build_stage_fingerprint(
    stage: str,
    inputs: Mapping[str, str],
    config: Any,
    *,
    policy_sha256: str | None = None,
    catalog_sha256: str | None = None,
    code_version: str,
) -> str:
    return canonical_sha256(
        {
            "stage": stage,
            "inputs": inputs,
            "config_sha256": canonical_sha256(config),
            "policy_sha256": policy_sha256,
            "catalog_sha256": catalog_sha256,
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
) -> bool:
    if force or not output_paths:
        return False
    try:
        manifest = read_stage_manifest(manifest_path)
        normalized_outputs = [_normalize_path(path) for path in output_paths]
    except (OSError, UnicodeError, TypeError, ValueError):
        return False
    if manifest.fingerprint != expected_fingerprint:
        return False
    if manifest.outputs != normalized_outputs:
        return False
    return all(Path(path).exists() for path in output_paths)
