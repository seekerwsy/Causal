"""Deterministic source extraction for multilingual code-generation responses."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

_SCHEMA_VERSION = "1.0"
_MAX_RAW_CHARS = 1_048_576
_MAX_FILES = 32
_MAX_PATH_CHARS = 1024
_FENCE = re.compile(
    r"\A\s*```(?P<label>[A-Za-z0-9_+#.-]*)[ \t]*\r?\n(?P<body>[\s\S]*?)\r?\n```\s*\Z"
)
_XML_FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

SOURCE_EXTRACTION_POLICY = {
    "schema_version": _SCHEMA_VERSION,
    "policy_id": "plain_single_fence_or_result_xml_v1",
    "accepted_envelopes": ["plain_source", "single_markdown_fence", "result_code_xml"],
    "xml_root": "result",
    "xml_code_fields": ["path", "content"],
    "maximum_files": _MAX_FILES,
    "multiple_file_projection": "content_in_declared_order_joined_by_two_newlines",
    "normalization": "strip_outer_whitespace_and_require_nonempty_utf8",
    "reject_commentary_outside_envelope": True,
    "reject_xml_dtd_and_entities": True,
}
SOURCE_EXTRACTION_POLICY_SHA256 = hashlib.sha256(
    json.dumps(
        SOURCE_EXTRACTION_POLICY,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
).hexdigest()

SourceEnvelope = Literal["plain_source", "single_markdown_fence", "result_code_xml"]


@dataclass(frozen=True, slots=True)
class GeneratedSourceFile:
    path: str
    content: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class GeneratedSourceExtraction:
    schema_version: Literal["1.0"]
    policy_sha256: str
    envelope: SourceEnvelope
    fence_label: str | None
    raw_response_sha256: str
    source_sha256: str
    source: str
    files: tuple[GeneratedSourceFile, ...]


def _normalized_source(value: str) -> str:
    result = value.strip()
    if not result:
        raise ValueError("generated source is empty")
    result.encode("utf-8")
    return result


def _safe_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or len(normalized) > _MAX_PATH_CHARS
        or normalized.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
    ):
        raise ValueError("generated source path failed validation")
    return normalized


def _xml_files(value: str) -> tuple[GeneratedSourceFile, ...]:
    if _XML_FORBIDDEN.search(value):
        raise ValueError("generated source XML contains a forbidden declaration")
    try:
        root = ET.fromstring(value)
    except ET.ParseError:
        raise ValueError("generated source XML failed validation") from None
    children = list(root)
    if root.tag != "result" or not 1 <= len(children) <= _MAX_FILES:
        raise ValueError("generated source XML failed validation")
    if root.attrib or (root.text is not None and root.text.strip()):
        raise ValueError("generated source XML failed validation")
    files: list[GeneratedSourceFile] = []
    seen_paths: set[str] = set()
    for code in children:
        fields = list(code)
        if (
            code.tag != "code"
            or code.attrib
            or (code.text is not None and code.text.strip())
            or len(fields) != 2
            or [item.tag for item in fields] != ["path", "content"]
            or any(item.attrib or list(item) for item in fields)
            or (code.tail is not None and code.tail.strip())
        ):
            raise ValueError("generated source XML failed validation")
        path_node, content_node = fields
        if any(item.tail is not None and item.tail.strip() for item in fields):
            raise ValueError("generated source XML failed validation")
        path = _safe_path("" if path_node.text is None else path_node.text)
        content = _normalized_source("" if content_node.text is None else content_node.text)
        if path in seen_paths:
            raise ValueError("generated source XML contains a duplicate path")
        seen_paths.add(path)
        files.append(
            GeneratedSourceFile(
                path=path,
                content=content,
                content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
        )
    return tuple(files)


def extract_generated_source(raw_response: str) -> GeneratedSourceExtraction:
    """Extract one deterministic source projection while preserving raw-response provenance."""

    if type(raw_response) is not str or not raw_response or len(raw_response) > _MAX_RAW_CHARS:
        raise ValueError("generated response failed validation")
    raw_response.encode("utf-8")
    raw_sha256 = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
    candidate = raw_response.strip()
    fence = _FENCE.fullmatch(raw_response)
    label: str | None = None
    if fence is not None:
        label = fence.group("label") or None
        candidate = fence.group("body")
        if "```" in candidate:
            raise ValueError("generated response contains nested or multiple fences")

    xml_candidate = candidate.lstrip()
    if xml_candidate.startswith("<"):
        files = _xml_files(candidate)
        source = "\n\n".join(item.content for item in files)
        envelope: SourceEnvelope = "result_code_xml"
    else:
        if "```" in candidate or "<result" in candidate.casefold():
            raise ValueError("generated response envelope failed validation")
        source = _normalized_source(candidate)
        files = ()
        envelope = "single_markdown_fence" if fence is not None else "plain_source"

    return GeneratedSourceExtraction(
        schema_version=_SCHEMA_VERSION,
        policy_sha256=SOURCE_EXTRACTION_POLICY_SHA256,
        envelope=envelope,
        fence_label=label,
        raw_response_sha256=raw_sha256,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        source=source,
        files=files,
    )


__all__ = [
    "SOURCE_EXTRACTION_POLICY",
    "SOURCE_EXTRACTION_POLICY_SHA256",
    "GeneratedSourceExtraction",
    "GeneratedSourceFile",
    "extract_generated_source",
]
