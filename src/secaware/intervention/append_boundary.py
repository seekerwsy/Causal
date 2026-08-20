from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass

LEGACY_DIRECT_CONCAT_POLICY = "legacy_direct_concat_v1"
PYTHON_COMMENT_BOUNDARY_POLICY = "python_comment_boundary_v1"
APPEND_BOUNDARY_POLICIES = frozenset(
    {
        LEGACY_DIRECT_CONCAT_POLICY,
        PYTHON_COMMENT_BOUNDARY_POLICY,
    }
)


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AppendBoundaryRender:
    policy: str
    raw_semantic_suffix: str
    rendered_append: str
    candidate_text: str

    def metadata(self) -> dict[str, object]:
        return {
            "append_boundary_policy": self.policy,
            "raw_semantic_suffix": self.raw_semantic_suffix,
            "raw_semantic_suffix_length": len(self.raw_semantic_suffix),
            "raw_semantic_suffix_sha256": _text_sha256(self.raw_semantic_suffix),
            "rendered_append": self.rendered_append,
            "rendered_append_length": len(self.rendered_append),
            "rendered_append_sha256": _text_sha256(self.rendered_append),
        }


@dataclass(frozen=True, slots=True)
class PythonParsePreservation:
    source_parse_ok: bool
    candidate_parse_ok: bool
    source_parse_error: dict[str, object] | None
    candidate_parse_error: dict[str, object] | None

    @property
    def passed(self) -> bool:
        return not self.source_parse_ok or self.candidate_parse_ok

    def metadata(self) -> dict[str, object]:
        return {
            "python_source_parse_ok": self.source_parse_ok,
            "python_candidate_parse_ok": self.candidate_parse_ok,
            "python_parse_preservation_passed": self.passed,
            "python_source_parse_error": self.source_parse_error,
            "python_candidate_parse_error": self.candidate_parse_error,
        }


def _parse_status(value: str) -> tuple[bool, dict[str, object] | None]:
    try:
        ast.parse(value)
    except SyntaxError as error:
        return False, {
            "error_type": "SyntaxError",
            "message": error.msg,
            "line": error.lineno,
            "offset": error.offset,
        }
    except ValueError as error:
        return False, {
            "error_type": "ValueError",
            "message": str(error),
            "line": None,
            "offset": None,
        }
    return True, None


def python_parse_preservation(
    source_prompt: str,
    candidate_text: str,
) -> PythonParsePreservation:
    if type(source_prompt) is not str or type(candidate_text) is not str:
        raise ValueError("Python parse preservation input failed validation")
    source_ok, source_error = _parse_status(source_prompt)
    candidate_ok, candidate_error = _parse_status(candidate_text)
    return PythonParsePreservation(
        source_parse_ok=source_ok,
        candidate_parse_ok=candidate_ok,
        source_parse_error=source_error,
        candidate_parse_error=candidate_error,
    )


def _python_comment_boundary(source_prompt: str, raw_semantic_suffix: str) -> str:
    semantic_text = raw_semantic_suffix.strip()
    if not semantic_text:
        raise ValueError("append-boundary semantic suffix failed validation")
    comment_lines = tuple("#" if not line else f"# {line}" for line in semantic_text.splitlines())
    if source_prompt.endswith(("\r\n\r\n", "\n\n", "\r\r")):
        separator = ""
    elif source_prompt.endswith(("\r\n", "\n", "\r")):
        separator = "\n"
    else:
        separator = "\n\n"
    return separator + "\n".join(comment_lines)


def render_append_boundary(
    source_prompt: str,
    raw_semantic_suffix: str,
    *,
    policy: str = LEGACY_DIRECT_CONCAT_POLICY,
) -> AppendBoundaryRender:
    if (
        type(source_prompt) is not str
        or type(raw_semantic_suffix) is not str
        or not raw_semantic_suffix.strip()
        or policy not in APPEND_BOUNDARY_POLICIES
    ):
        raise ValueError("append-boundary input failed validation")
    rendered_append = (
        raw_semantic_suffix
        if policy == LEGACY_DIRECT_CONCAT_POLICY
        else _python_comment_boundary(source_prompt, raw_semantic_suffix)
    )
    return AppendBoundaryRender(
        policy=policy,
        raw_semantic_suffix=raw_semantic_suffix,
        rendered_append=rendered_append,
        candidate_text=source_prompt + rendered_append,
    )


__all__ = [
    "APPEND_BOUNDARY_POLICIES",
    "LEGACY_DIRECT_CONCAT_POLICY",
    "PYTHON_COMMENT_BOUNDARY_POLICY",
    "AppendBoundaryRender",
    "PythonParsePreservation",
    "python_parse_preservation",
    "render_append_boundary",
]
