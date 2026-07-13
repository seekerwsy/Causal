"""Transactional Prompt extraction proposal and TSG publication."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.factory import extraction_policy, extractor_for_config
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.llm.structured_transport import StructuredJSONTransport
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "extract-prompt-tsg"
_MAX_PROMPT_INPUT_BYTES = 256_000_000


def _stage_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
    )


def _input_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _path_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        *_input_fingerprint(value),
        value.st_ctime_ns,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _PromptInputSnapshot:
    records: tuple[PromptRecord, ...]
    payload_sha256: str
    fingerprint: tuple[int, int, int, int, int, int, int]


def _read_prompt_input_material(
    path: Path,
) -> tuple[bytes, str, tuple[int, int, int, int, int, int, int]]:
    descriptor = -1
    payload = b""
    buffer = bytearray()
    chunk = b""
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_PROMPT_INPUT_BYTES
        ):
            raise ValueError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _input_fingerprint(opened) != _input_fingerprint(before):
            raise ValueError
        remaining = opened.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError
            buffer.extend(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        payload = bytes(buffer)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            _input_fingerprint(after) != _input_fingerprint(opened)
            or _input_fingerprint(after_path) != _input_fingerprint(opened)
            or _path_fingerprint(after_path) != _path_fingerprint(before)
            or len(payload) != opened.st_size
        ):
            raise ValueError
        return payload, digest.hexdigest(), _path_fingerprint(after_path)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("source prompt snapshot failed validation") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        buffer.clear()
        chunk = b""


def _parse_source_prompt_bytes(payload: bytes) -> tuple[PromptRecord, ...]:
    records: list[PromptRecord] = []
    text = ""
    try:
        if type(payload) is not bytes or not payload:
            raise ValueError
        text = payload.decode("utf-8", errors="strict")
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            records.append(PromptRecord.model_validate(json.loads(stripped)))
        if not records or any(type(record) is not PromptRecord for record in records):
            raise ValueError
        return tuple(records)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("source prompt coverage failed validation") from None
    finally:
        text = ""


def read_source_prompts(
    store: RunStore,
    *,
    payload: bytes | None = None,
) -> tuple[PromptRecord, ...]:
    """Read the immutable source artifact exactly once for one stage build."""
    if payload is not None:
        return _parse_source_prompt_bytes(payload)
    records = read_jsonl(
        store.path("inputs", "prompts.jsonl"),
        PromptRecord,
        required=True,
        allow_empty=False,
        stage=_STAGE,
    )
    if any(type(record) is not PromptRecord for record in records):
        raise _stage_error("source prompt coverage failed validation") from None
    return tuple(records)  # type: ignore[arg-type,return-value]


def validate_exact_extraction_coverage(
    prompts: tuple[PromptRecord, ...],
    proposals: tuple[PromptExtractionProposalRecord, ...],
    graphs: tuple[PromptTSGRecord, ...],
    policy: ExtractionPolicy,
) -> None:
    """Require ordered one-to-one identity and provenance coverage."""
    failed = False
    try:
        if type(policy) is not ExtractionPolicy or not prompts:
            raise ValueError
        if len(prompts) != len(proposals) or len(prompts) != len(graphs):
            raise ValueError
        prompt_ids = tuple(prompt.prompt_id for prompt in prompts)
        proposal_ids = tuple(proposal.proposal_id for proposal in proposals)
        graph_proposal_ids = tuple(graph.proposal_id for graph in graphs)
        if len(set(prompt_ids)) != len(prompt_ids):
            raise ValueError
        if len(set(proposal_ids)) != len(proposal_ids):
            raise ValueError
        if proposal_ids != graph_proposal_ids:
            raise ValueError
        for prompt, proposal, graph in zip(prompts, proposals, graphs, strict=True):
            prompt_sha256 = hashlib.sha256(prompt.prompt.encode("utf-8")).hexdigest()
            if (
                type(prompt) is not PromptRecord
                or type(proposal) is not PromptExtractionProposalRecord
                or type(graph) is not PromptTSGRecord
                or proposal.prompt_id != prompt.prompt_id
                or proposal.task_id != prompt.task_id
                or proposal.prompt_sha256 != prompt_sha256
                or proposal.backend is not policy.backend
                or proposal.policy_sha256 != policy.policy_sha256
                or proposal.catalog_sha256 != policy.catalog_sha256
                or proposal.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or graph.prompt_id != prompt.prompt_id
                or graph.task_id != prompt.task_id
                or graph.task_family != prompt.task_family
                or graph.cwe != prompt.cwe
                or graph.extractor_backend is not policy.backend
                or graph.extractor_policy_sha256 != policy.policy_sha256
                or graph.proposal_id != proposal.proposal_id
            ):
                raise ValueError
    except Exception:
        failed = True
    if failed:
        raise _stage_error("prompt extraction coverage failed validation") from None


def run_prompt_extraction_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    transport: StructuredJSONTransport | None = None,
) -> None:
    """Publish exactly one locked proposal and graph for every source prompt."""
    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _stage_error("prompt extraction configuration failed validation") from None
    policy = extraction_policy(config.tsg)
    prompt_input = store.path("inputs", "prompts.jsonl")
    proposal_output = store.path("tsg", "prompt_extraction_proposals.jsonl")
    graph_output = store.path("tsg", "prompt_tsg.jsonl")
    source_snapshot: _PromptInputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str]:
        nonlocal source_snapshot
        if source_snapshot is not None:
            raise _stage_error("source prompt snapshot failed validation")
        payload, payload_sha256, fingerprint = _read_prompt_input_material(prompt_input)
        source_snapshot = _PromptInputSnapshot(
            records=read_source_prompts(store, payload=payload),
            payload_sha256=payload_sha256,
            fingerprint=fingerprint,
        )
        return (payload_sha256,)

    def verify_input_snapshot() -> None:
        if source_snapshot is None:
            raise _stage_error("source prompt snapshot failed validation")
        _payload, payload_sha256, fingerprint = _read_prompt_input_material(prompt_input)
        if (
            payload_sha256 != source_snapshot.payload_sha256
            or fingerprint != source_snapshot.fingerprint
        ):
            raise _stage_error("source prompts changed during extraction")

    def build() -> tuple[
        tuple[PromptExtractionProposalRecord, ...],
        tuple[PromptTSGRecord, ...],
    ]:
        if source_snapshot is None:
            raise _stage_error("source prompt snapshot failed validation")
        backend = extractor_for_config(config.tsg, transport=transport)
        prompts = source_snapshot.records
        proposals = tuple(backend.extract(prompt, policy) for prompt in prompts)
        graphs = tuple(
            build_prompt_tsg(proposal, prompt)
            for proposal, prompt in zip(proposals, prompts, strict=True)
        )
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        return proposals, graphs

    execute_jsonl_stage_transaction(
        store,
        stage=_STAGE,
        inputs=(prompt_input,),
        outputs=(
            JsonlOutputSpec(
                proposal_output,
                PromptExtractionProposalRecord,
                require_nonempty=True,
            ),
            JsonlOutputSpec(graph_output, PromptTSGRecord, require_nonempty=True),
        ),
        force=force,
        build=build,
        policy_sha256=policy.policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        capture_input_snapshot=capture_input_snapshot,
        verify_input_snapshot=verify_input_snapshot,
    )


__all__ = [
    "read_source_prompts",
    "run_prompt_extraction_stage",
    "validate_exact_extraction_coverage",
]
