"""Legacy import bridge; active artifact mechanics live in :mod:`secaware.artifact_io`."""

from secaware.artifact_io import (
    atomic_write_text as _atomic_write_text,
)
from secaware.artifact_io import (
    canonical_sha256,
    sha256_file,
    sha256_path,
)

__all__ = ["_atomic_write_text", "canonical_sha256", "sha256_file", "sha256_path"]
