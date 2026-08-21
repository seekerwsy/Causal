"""Legacy import bridge for the shared artifact closure implementation."""

from secaware.artifact_io import (
    build_closed_manifest,
    verify_closed_manifest,
    write_closed_manifest_atomic,
    write_json_atomic_exclusive,
)

__all__ = [
    "build_closed_manifest",
    "verify_closed_manifest",
    "write_closed_manifest_atomic",
    "write_json_atomic_exclusive",
]
