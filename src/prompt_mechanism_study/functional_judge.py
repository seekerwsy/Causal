"""Minimal blinded functional-Oracle engineering gate."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.records import canonical_json, content_hash

MEASUREMENT_METHOD = "ast_compile_plus_blind_llm_review_v1"
_RESPONSE_KEYS = {"verdict", "evidence_lines", "reason"}
_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": sorted(_RESPONSE_KEYS),
    "properties": {
        "verdict": {"enum": ["pass", "fail", "unknown"]},
        "evidence_lines": {
            "type": "array",
            "maxItems": 32,
            "uniqueItems": True,
            "items": {"type": "integer", "minimum": 1},
        },
        "reason": {"type": "string"},
    },
}


class JudgeGateError(RuntimeError):
    """A non-retryable gate, input, provider, or response failure."""

    def __init__(self, message: str, *, provider_response: bytes | None = None):
        super().__init__(message)
        self.provider_response = provider_response


@dataclass(frozen=True, slots=True)
class GateInputs:
    repository_root: Path
    gate_path: Path
    gate: dict[str, Any]
    evaluator: dict[str, Any]
    prompt: str
    cases: tuple[dict[str, Any], ...]
    contracts: dict[str, dict[str, Any]]
    pilot_ids: tuple[str, ...]

    @property
    def remaining_ids(self) -> tuple[str, ...]:
        pilot = set(self.pilot_ids)
        return tuple(case["case_id"] for case in self.cases if case["case_id"] not in pilot)


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


def load_gate_inputs(
    repository_root: Path,
    gate_config: Path | None = None,
) -> GateInputs:
    root = repository_root.resolve()
    gate_path = (
        root / "configs/functional-judge/functional-oracle-qwen37flash.json"
        if gate_config is None
        else _inside(root, gate_config)
    )
    gate = _object(read_json(gate_path), "gate")
    candidate = _object(gate.get("candidate"), "candidate")
    holdout = _object(gate.get("holdout"), "holdout")
    evaluator_path = _inside(root, candidate.get("evaluator_config_path"))
    prompt_path = _inside(root, candidate.get("prompt_path"))
    cases_path = _inside(root, holdout.get("cases_path"))
    spec_path = _inside(root, holdout.get("calibration_spec_path"))
    contracts_path = _inside(root, holdout.get("contracts_path"))
    _file_digest(evaluator_path, candidate.get("evaluator_config_sha256"))
    _file_digest(prompt_path, candidate.get("prompt_sha256"))
    _file_digest(cases_path, holdout.get("cases_sha256"))
    _file_digest(spec_path, holdout.get("calibration_spec_sha256"))

    evaluator = _object(read_json(evaluator_path), "evaluator")
    expected_evaluator = {
        "candidate_id": candidate.get("candidate_id"),
        "protocol_version": "functional_oracle_v2",
        "model_id": candidate.get("model_id"),
        "mode": "single_pass",
        "max_attempts": 1,
        "enable_thinking": False,
    }
    if any(evaluator.get(key) != value for key, value in expected_evaluator.items()):
        raise JudgeGateError("evaluator identity does not match the frozen gate")
    if evaluator.get("api_key_env") != "ALI_BAILIAN_API_KEY":
        raise JudgeGateError("unexpected credential coordinate")
    maximum_output_tokens = evaluator.get("maximum_output_tokens")
    if maximum_output_tokens is not None and (
        type(maximum_output_tokens) is not int or maximum_output_tokens <= 0
    ):
        raise JudgeGateError("maximum output tokens must be a positive integer")
    prompt = prompt_path.read_text(encoding="utf-8")
    if not prompt.strip():
        raise JudgeGateError("judge prompt is empty")

    spec = _object(read_json(spec_path), "calibration spec")
    if spec.get("validation_cases_sha256") != holdout.get("cases_sha256") or spec.get(
        "validation_expected_cases"
    ) != holdout.get("cases"):
        raise JudgeGateError("holdout and calibration spec disagree")
    family_specs = {
        item["family"]: item
        for item in (_object(value, "family spec") for value in _list(spec.get("families")))
    }
    if len(family_specs) != gate["acceptance"]["families"]:
        raise JudgeGateError("family closure is incomplete")

    cases = tuple(_json_lines(cases_path))
    _validate_cases(cases, family_specs, holdout.get("cases"))
    contracts = _load_contracts(contracts_path, family_specs)
    pilot_ids = tuple(_strings(holdout.get("pilot_case_ids"), "pilot case ids"))
    case_by_id = {case["case_id"]: case for case in cases}
    if (
        len(pilot_ids) != holdout.get("pilot_cases")
        or len(pilot_ids) != len(set(pilot_ids))
        or not set(pilot_ids) <= set(case_by_id)
        or {case_by_id[case_id]["family"] for case_id in pilot_ids} != set(family_specs)
        or len(cases) - len(pilot_ids) != holdout.get("remaining_cases")
    ):
        raise JudgeGateError("pilot partition is not a four-family partition")
    return GateInputs(root, gate_path, gate, evaluator, prompt, cases, contracts, pilot_ids)


def request_for(
    case: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    task_prompts = tuple(
        dict.fromkeys(item["prompt_evidence_quote"] for item in contract["requirements"])
    )
    if not task_prompts:
        raise JudgeGateError("functional task prompt is unavailable")
    requirements = [
        {
            "requirement_id": item["requirement_id"],
            "criterion": item["criterion"],
        }
        for item in contract["requirements"]
    ]
    return build_review_request(
        case["code_text"],
        "\n".join(task_prompts),
        requirements=requirements,
        environment_dependencies=contract["environment_dependencies"],
        language=contract["language"],
    )


def build_review_request(
    code_text: str,
    functional_task: str,
    *,
    requirements: Sequence[Mapping[str, Any]] = (),
    environment_dependencies: Sequence[str] = (),
    language: str = "python",
    source_scope: str | None = None,
) -> dict[str, Any]:
    """Build the outcome-blind request used by formal measurement adapters."""

    if not code_text.strip() or not functional_task.strip() or not language.strip():
        raise JudgeGateError("functional review input is empty")
    request = {
        "schema_version": "1.0",
        "request_kind": "blind_functional_evaluation",
        "blindness": {
            "arm_withheld": True,
            "cwe_withheld": True,
            "security_outcome_withheld": True,
            "generator_identity_withheld": True,
        },
        "language": language,
        "functional_task": functional_task,
        "requirements": [dict(item) for item in requirements],
        "environment_dependencies": list(environment_dependencies),
        "program_lines": [
            {"line_number": number, "text": line}
            for number, line in enumerate(code_text.splitlines(), start=1)
        ],
        "measurement_method": MEASUREMENT_METHOD,
        "output_schema": _OUTPUT_SCHEMA,
    }
    if source_scope is not None:
        if source_scope not in {"complete", "partial", "unresolved"}:
            raise JudgeGateError("functional source scope is invalid")
        request["source_context"] = {
            "specification_scope": source_scope,
            "scope_is_descriptive_not_a_verdict": True,
        }
    return request


def validate_review_response(raw: bytes, code_text: str) -> dict[str, Any]:
    """Validate a provider response without consulting arm or security outcomes."""

    try:
        maximum = 65_536
        if not raw or len(raw) > maximum:
            raise ValueError
        response = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        response = _object(response, "response")
        if set(response) != _RESPONSE_KEYS:
            raise ValueError
        verdict = response["verdict"]
        if verdict not in {"pass", "fail", "unknown"}:
            raise ValueError
        line_numbers = response["evidence_lines"]
        program_lines = code_text.splitlines()
        if (
            not isinstance(line_numbers, list)
            or len(line_numbers) > 32
            or any(
                type(value) is not int or value < 1 or value > len(program_lines)
                for value in line_numbers
            )
            or len(line_numbers) != len(set(line_numbers))
            or (verdict != "unknown" and not line_numbers)
        ):
            raise ValueError
        _bounded_text(response["reason"], 3000)
        return {
            "status": verdict,
            "evidence_lines": line_numbers,
            "resolved_code_evidence": [program_lines[number - 1] for number in line_numbers],
            "reason": response["reason"],
        }
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - all malformed provider outputs fail closed
        raise JudgeGateError("provider response failed functional review validation") from None


def python_syntax_valid(code_text: str) -> bool:
    """Return whether Python code is non-empty, parseable, and compilable."""

    try:
        tree = ast.parse(code_text)
        if not tree.body:
            return False
        compile(tree, "<generated-code>", "exec")
    except (SyntaxError, TypeError, ValueError):
        return False
    return True


_LANGUAGE_PARSERS = {
    "c": ("tree_sitter_c", "tree-sitter-c", "0.24.1", "language"),
    "cpp": ("tree_sitter_cpp", "tree-sitter-cpp", "0.23.4", "language"),
    "csharp": ("tree_sitter_c_sharp", "tree-sitter-c-sharp", "0.23.1", "language"),
    "go": ("tree_sitter_go", "tree-sitter-go", "0.25.0", "language"),
    "java": ("tree_sitter_java", "tree-sitter-java", "0.23.5", "language"),
    "javascript": ("tree_sitter_javascript", "tree-sitter-javascript", "0.25.0", "language"),
    "php": ("tree_sitter_php", "tree-sitter-php", "0.24.1", "language_php_only"),
    "rust": ("tree_sitter_rust", "tree-sitter-rust", "0.24.0", "language"),
}
SOURCE_LANGUAGES = ("python", *sorted(_LANGUAGE_PARSERS))


def syntax_parser_identity(language: str) -> dict[str, Any]:
    """Check the local parser before generation; this grants no Oracle qualification."""
    import importlib
    import importlib.metadata
    import platform

    if language == "python":
        return {"language": language, "parser": "cpython_ast_compile",
                "version": platform.python_version(), "code_execution": False}
    if language not in _LANGUAGE_PARSERS:
        raise JudgeGateError(f"syntax parser language is not supported: {language}")
    module, package, expected, entrypoint = _LANGUAGE_PARSERS[language]
    try:
        versions = {name: importlib.metadata.version(name)
                    for name in ("tree-sitter", package)}
        if versions != {"tree-sitter": "0.25.2", package: expected}:
            raise JudgeGateError("language parser versions differ from the pinned dependencies")
        importlib.import_module("tree_sitter")
        getattr(importlib.import_module(module), entrypoint)
    except (ImportError, AttributeError) as exc:
        raise JudgeGateError("language parser is unavailable; install the languages extra") from exc
    return {"language": language, "parser": "tree_sitter", "packages": versions,
            "grammar_entrypoint": entrypoint, "code_execution": False}


def code_syntax_valid(code_text: str, language: str) -> bool:
    """Parse the exact source, without executing, wrapping, translating, or repairing it.

    Tree-sitter checks grammar only. Type checking, imports, linking, runtime
    behavior, security and functionality are independent measurement questions.
    Missing parsers are setup errors, never an INVALID label for generated code.
    """
    import importlib

    syntax_parser_identity(language)
    if language == "python":
        return python_syntax_valid(code_text)
    from tree_sitter import Language, Parser

    module, _, _, entrypoint = _LANGUAGE_PARSERS[language]
    grammar = Language(getattr(importlib.import_module(module), entrypoint)())
    tree = Parser(grammar).parse(code_text.encode("utf-8"))
    root = tree.root_node
    return not root.has_error and any(
        child.type not in {"comment", "line_comment", "block_comment", "php_tag"}
        for child in root.named_children
    )


def functional_source_scope(contract: Mapping[str, Any]) -> str:
    """Describe source completeness without predetermining functional judgment."""
    scope = contract.get("measurement_scope", "complete")
    if scope not in {"complete", "partial", "unresolved"}:
        raise JudgeGateError("functional measurement scope is invalid")
    review = contract.get("review", {})
    if not isinstance(review, Mapping):
        raise JudgeGateError("functional source review is invalid")
    source = review.get("source_specification_disposition")
    if source is not None and source not in {"sufficient", "insufficient", "defect"}:
        raise JudgeGateError("functional source specification status is invalid")
    inherited = contract.get("parent_contract_applies_to_current_input", True)
    if type(inherited) is not bool:
        raise JudgeGateError("functional parent contract applicability is invalid")
    if not inherited:
        return "unresolved"
    if source == "defect" or scope == "unresolved" or not contract.get("requirements"):
        return "unresolved"
    if source == "insufficient" or scope == "partial":
        return "partial"
    return "complete"


def preflight(
    repository_root: Path,
    output: Path,
    *,
    gate_config: Path | None = None,
) -> dict[str, Any]:
    inputs = load_gate_inputs(repository_root, gate_config)
    key_name = inputs.evaluator["api_key_env"]
    present = bool(os.environ.get(key_name, "").strip())
    report = {
        "schema_version": "1.0",
        "status": "JUDGE_GATE_PREFLIGHT_COMPLETE",
        "candidate_id": inputs.evaluator["candidate_id"],
        "model_id": inputs.evaluator["model_id"],
        "case_count": len(inputs.cases),
        "pilot_case_ids": list(inputs.pilot_ids),
        "remaining_case_ids": list(inputs.remaining_ids),
        "credential": {
            "environment_variable": key_name,
            "present": present,
            "value_recorded": False,
        },
        "live_ready": present,
        "provider_attempts": 0,
        "input_hashes": _input_hashes(inputs),
        "functional_oracle": inputs.gate["functional_oracle"],
    }
    write_bundle(output, {"report.json": report})
    return report


def run_phase(
    repository_root: Path,
    phase: str,
    output: Path,
    *,
    pilot_root: Path | None = None,
    gate_config: Path | None = None,
    provider: Provider | None = None,
) -> dict[str, Any]:
    inputs = load_gate_inputs(repository_root, gate_config)
    if phase not in {"pilot", "remaining"}:
        raise JudgeGateError("phase must be pilot or remaining")
    if output.exists():
        raise FileExistsError(output)
    if phase == "remaining" and (
        pilot_root is None or load_phase(pilot_root)["status"] != "PILOT_PASSED"
    ):
        raise JudgeGateError("remaining cases require a passed pilot")
    output.mkdir(parents=True)
    selected = set(inputs.pilot_ids if phase == "pilot" else inputs.remaining_ids)
    cases = [case for case in inputs.cases if case["case_id"] in selected]
    provider = provider or bailian_complete
    case_summaries: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        contract = inputs.contracts[case["task_id"]]
        request_payload = request_for(case, contract)
        raw: bytes | None = None
        result: dict[str, Any] | None = None
        error: str | None = None
        try:
            raw = provider(request_payload, inputs.evaluator, inputs.prompt)
            result = validate_review_response(raw, case["code_text"])
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as failure:  # noqa: BLE001 - close the failed case before stopping
            error = type(failure).__name__
        expected = case["expected_status"]
        actual = result["status"] if result is not None else None
        case_report = {
            "schema_version": "1.0",
            "case_id": case["case_id"],
            "family": case["family"],
            "expected_status": expected,
            "actual_status": actual,
            "correct": actual == expected,
            "false_pass": expected == "fail" and actual == "pass",
            "invalid": result is None,
            "error_type": error,
            "provider_attempts": 1,
            "request_sha256": content_hash(request_payload),
            "response_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        }
        case_root = output / f"case-{index:02d}-{case['case_id']}"
        write_bundle(
            case_root,
            {
                "request.json": request_payload,
                "response.json": {
                    "raw_text": raw.decode("utf-8", errors="replace") if raw is not None else None,
                    "validated": result,
                },
                "result.json": case_report,
            },
        )
        case_summaries.append({**case_report, "bundle_sha256": bundle_digest(case_root)})
        if result is None:
            break
    report = _phase_report(inputs, phase, cases, case_summaries)
    write_bundle(
        output / "summary",
        {
            "report.json": report,
            "cases.json": case_summaries,
            "inputs.json": _input_hashes(inputs),
        },
    )
    return report


def load_phase(root: Path) -> dict[str, Any]:
    summary = root.resolve() / "summary"
    verify_bundle(summary)
    report = _object(read_json(summary / "report.json"), "phase report")
    cases = _list(read_json(summary / "cases.json"))
    for index, item in enumerate(cases, start=1):
        row = _object(item, "phase case")
        case_root = root.resolve() / f"case-{index:02d}-{row['case_id']}"
        if bundle_digest(case_root) != row["bundle_sha256"]:
            raise JudgeGateError("phase case bundle drifted")
    return report


def finalize_gate(
    repository_root: Path,
    pilot_root: Path,
    remaining_root: Path,
    output: Path,
    *,
    gate_config: Path | None = None,
) -> dict[str, Any]:
    inputs = load_gate_inputs(repository_root, gate_config)
    pilot = load_phase(pilot_root)
    remaining = load_phase(remaining_root)
    if pilot.get("status") != "PILOT_PASSED" or remaining.get("status") != "REMAINING_COMPLETE":
        raise JudgeGateError("cannot finalize incomplete phases")
    all_rows = _phase_rows(pilot_root) + _phase_rows(remaining_root)
    if {row["case_id"] for row in all_rows} != {case["case_id"] for case in inputs.cases}:
        raise JudgeGateError("final gate does not close all holdout cases")
    by_family = {
        family: _metrics([row for row in all_rows if row["family"] == family])
        for family in sorted({row["family"] for row in all_rows})
    }
    totals = _metrics(all_rows)
    acceptance = inputs.gate["acceptance"]
    passed = (
        totals["correct"] >= acceptance["minimum_correct"]
        and totals["false_pass"] <= acceptance["maximum_false_pass"]
        and totals["invalid"] <= acceptance["maximum_invalid"]
        and all(
            metrics["correct"] >= acceptance["minimum_correct_per_family"]
            for metrics in by_family.values()
        )
    )
    report = {
        "schema_version": "1.0",
        "status": "JUDGE_GATE_PASSED" if passed else "JUDGE_GATE_FAILED",
        "scientific_claim_allowed": False,
        "candidate_id": inputs.evaluator["candidate_id"],
        "totals": totals,
        "families": by_family,
        "acceptance": acceptance,
        "pilot_bundle_sha256": bundle_digest(pilot_root / "summary"),
        "remaining_bundle_sha256": bundle_digest(remaining_root / "summary"),
        "input_hashes": _input_hashes(inputs),
    }
    write_bundle(output, {"report.json": report, "cases.json": all_rows})
    return report


def bailian_complete(
    request_payload: dict[str, Any],
    evaluator: Mapping[str, Any],
    prompt: str,
    *,
    trace: Callable[[str, bytes], None] | None = None,
    continuation: Sequence[Mapping[str, str]] = (),
    source_first_delivery: bool = False,
) -> bytes:
    """Complete the declared chat request through the shared provider client.

    The historical name is retained for frozen reproductions. A local_vllm
    configuration uses the same messages, decoding and response validation,
    without Bailian's thinking parameter or an invented cloud credential.
    Optional tracing retains the credential-free wire body and response envelope
    for development replay and usage accounting; it does not alter either body.
    A continuation appends explicit chat turns after the unchanged source request.
    Source-first development delivery changes JSON presentation order only;
    artifact identities still use canonical JSON. Default delivery is unchanged.
    """
    local = evaluator.get("provider") == "local_vllm"
    key_name = evaluator.get("api_key_env")
    api_key = os.environ.get(key_name, "") if key_name else ""
    if not local and not api_key.strip():
        raise JudgeGateError("provider credential is unavailable")
    endpoint = evaluator["base_url"].rstrip("/") + "/chat/completions"
    response_format = evaluator.get("response_format", {"type": "json_object"})
    if not isinstance(response_format, dict) or response_format.get("type") not in {
        "json_object",
        "json_schema",
    }:
        raise JudgeGateError("provider response format is invalid")
    if source_first_delivery:
        remaining = dict(request_payload)
        ordered = {key: remaining.pop(key) for key in (
            "request_kind", "annotation_phase", "source_prompt", "source_units", "source_tokens"
        ) if key in remaining}
        ordered.update(remaining)
        tokens = ordered.get("source_tokens")
        if isinstance(tokens, dict) and all(isinstance(key, str) and key.isdecimal() for key in tokens):
            ordered["source_tokens"] = {key: tokens[key] for key in sorted(tokens, key=int)}
        source_message = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    else:
        source_message = canonical_json(request_payload)
    body = {
        "model": evaluator["model_id"],
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": source_message},
        ],
        "temperature": evaluator["temperature"],
        "top_p": evaluator["top_p"],
        "seed": evaluator["seed"],
        "n": 1,
        "response_format": response_format,
    }
    body["messages"].extend(dict(message) for message in continuation)
    if evaluator.get("provider") == "deepseek":
        # DeepSeek exposes thinking under its native key and no seeded decoding
        # contract. Keep the provider difference explicit in the retained wire.
        body.pop("seed")
        body.pop("n")
        body["stream"] = False
        body["thinking"] = {"type": "enabled" if evaluator["enable_thinking"] else "disabled"}
    elif not local:
        body["enable_thinking"] = evaluator["enable_thinking"]
        if "thinking_budget" in evaluator:
            body["thinking_budget"] = evaluator["thinking_budget"]
    maximum_output_tokens = evaluator.get("maximum_output_tokens")
    if "maximum_completion_tokens" in evaluator:
        # DeepSeek names its completion limit max_tokens; Bailian uses
        # max_completion_tokens to include reasoning in the same budget.
        limit_field = "max_tokens" if evaluator.get("provider") == "deepseek" else "max_completion_tokens"
        body[limit_field] = evaluator["maximum_completion_tokens"]
    elif maximum_output_tokens is not None:
        body["max_tokens"] = maximum_output_tokens
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    # Canonical sorting is for artifact identity. At delivery it would reorder
    # response-schema properties, putting edges/nodes before the operation
    # inventory and reversing start/end evidence coordinates. Preserve the
    # declared schema sequence; source-message presentation is selected above.
    encoded_request = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    maximum_input_bytes = evaluator.get("maximum_input_bytes")
    if maximum_input_bytes is not None and (
        type(maximum_input_bytes) is not int or maximum_input_bytes <= 0
        or len(encoded_request) + 1024 > maximum_input_bytes
    ):
        raise JudgeGateError("provider request exceeds frozen input byte ceiling; not submitted")
    http_request = Request(
        endpoint,
        data=encoded_request,
        headers=headers,
        method="POST",
    )
    if trace is not None:
        trace("request", encoded_request)
    try:
        with urlopen(http_request, timeout=evaluator["timeout_seconds"]) as response:
            raw_outer = response.read(evaluator["max_response_bytes"] + 1)
        if trace is not None:
            trace("response", raw_outer)
        if len(raw_outer) > evaluator["max_response_bytes"]:
            raise ValueError
        outer = _object(json.loads(raw_outer), "provider response")
        choices = _list(outer.get("choices"))
        if len(choices) != 1:
            raise ValueError
        choice = _object(choices[0], "provider choice")
        message = _object(choice.get("message"), "provider message")
        content = message.get("content")
        if choice.get("finish_reason") != "stop":
            raise JudgeGateError(
                f"provider completion did not finish with stop (finish_reason={choice.get('finish_reason')!r})",
                provider_response=raw_outer,
            )
        if (
            not isinstance(content, str)
            or not content.strip()
        ):
            raise ValueError
        encoded = content.encode("utf-8")
        if len(encoded) > evaluator["max_response_bytes"]:
            raise ValueError
        return encoded
    except HTTPError as error:
        try:
            with error:
                raw_error = error.read(evaluator["max_response_bytes"] + 1)
        except (OSError, ValueError):
            raw_error = b""
        if api_key:
            raw_error = raw_error.replace(api_key.encode("utf-8"), b"[REDACTED]")
        if trace is not None:
            trace("response", raw_error)
        raise JudgeGateError(f"provider HTTP error {error.code}", provider_response=raw_error) from None
    except (URLError, TimeoutError) as error:
        raise JudgeGateError(f"provider transport failed: {type(error).__name__}") from None
    except (ValueError, json.JSONDecodeError):
        raise JudgeGateError("provider response envelope is invalid") from None
    finally:
        api_key = ""


def _validate_cases(
    cases: Sequence[dict[str, Any]],
    family_specs: Mapping[str, Any],
    expected: object,
) -> None:
    if len(cases) != expected or len({case.get("case_id") for case in cases}) != len(cases):
        raise JudgeGateError("holdout case closure is incomplete")
    counts: Counter[tuple[str, str]] = Counter()
    for case in cases:
        required = {
            "schema_version",
            "case_id",
            "code_text",
            "equivalence_group",
            "expected_status",
            "family",
            "fixture_role",
            "seed_id",
            "split",
            "task_id",
        }
        if (
            set(case) != required
            or case["split"] != "validation"
            or case["expected_status"] not in {"pass", "fail"}
        ):
            raise JudgeGateError("holdout case schema failed validation")
        family = family_specs.get(case["family"])
        if family is None or case["task_id"] != family["task_id"]:
            raise JudgeGateError("holdout case family binding failed validation")
        if not python_syntax_valid(case["code_text"]):
            raise JudgeGateError("holdout code is not valid Python") from None
        counts[(case["family"], case["expected_status"])] += 1
    if any(counts[(family, status)] != 2 for family in family_specs for status in ("pass", "fail")):
        raise JudgeGateError("holdout is not balanced within family")


def _load_contracts(
    path: Path,
    family_specs: Mapping[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    wanted = {item["task_id"]: item for item in family_specs.values()}
    contracts: dict[str, dict[str, Any]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        row = _object(_loads(raw_line), "functional contract")
        spec = wanted.get(row.get("task_id"))
        if spec is None:
            continue
        source_digest = hashlib.sha256((raw_line + "\n").encode("utf-8")).hexdigest()
        requirement_ids = [item["requirement_id"] for item in row.get("requirements", [])]
        if (
            row.get("contract_id") != spec["functional_contract_id"]
            or source_digest != spec["functional_contract_source_artifact_sha256"]
            or requirement_ids != spec["functional_requirement_ids"]
            or row["task_id"] in contracts
        ):
            raise JudgeGateError("functional contract binding failed validation")
        contracts[row["task_id"]] = row
    if set(contracts) != set(wanted):
        raise JudgeGateError("functional contracts are incomplete")
    return contracts


def _phase_report(
    inputs: GateInputs,
    phase: str,
    cases: Sequence[dict[str, Any]],
    rows: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    metrics = _metrics(rows)
    complete = len(rows) == len(cases) and metrics["invalid"] == 0
    if phase == "pilot":
        acceptance = inputs.gate["pilot_acceptance"]
        passed = (
            complete
            and metrics["correct"] >= acceptance["minimum_correct"]
            and metrics["false_pass"] <= acceptance["maximum_false_pass"]
            and metrics["invalid"] <= acceptance["maximum_invalid"]
        )
        status = "PILOT_PASSED" if passed else "PILOT_FAILED" if complete else "ERROR"
    else:
        acceptance = None
        status = "REMAINING_COMPLETE" if complete else "ERROR"
    return {
        "schema_version": "1.0",
        "status": status,
        "phase": phase,
        "expected_cases": len(cases),
        "metrics": metrics,
        "acceptance": acceptance,
        "provider_attempt_scope": "closed_case_bundles_only",
        "scientific_claim_allowed": False,
        "candidate_id": inputs.evaluator["candidate_id"],
        "input_hashes": _input_hashes(inputs),
    }


def _phase_rows(root: Path) -> list[dict[str, Any]]:
    summary = root.resolve() / "summary"
    verify_bundle(summary)
    return [_object(item, "phase case") for item in _list(read_json(summary / "cases.json"))]


def _metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "cases": len(rows),
        "correct": sum(row.get("correct") is True for row in rows),
        "false_pass": sum(row.get("false_pass") is True for row in rows),
        "false_fail": sum(
            row.get("expected_status") == "pass" and row.get("actual_status") == "fail"
            for row in rows
        ),
        "unknown": sum(row.get("actual_status") == "unknown" for row in rows),
        "invalid": sum(row.get("invalid") is True for row in rows),
        "provider_attempts": sum(int(row.get("provider_attempts", 0)) for row in rows),
    }


def _input_hashes(inputs: GateInputs) -> dict[str, str]:
    candidate = inputs.gate["candidate"]
    holdout = inputs.gate["holdout"]
    hashes = {
        "gate_config_sha256": hashlib.sha256(inputs.gate_path.read_bytes()).hexdigest(),
        "evaluator_config_sha256": candidate["evaluator_config_sha256"],
        "prompt_sha256": candidate["prompt_sha256"],
        "cases_sha256": holdout["cases_sha256"],
        "calibration_spec_sha256": holdout["calibration_spec_sha256"],
        "output_schema_sha256": content_hash(_OUTPUT_SCHEMA),
    }
    return hashes


def _json_lines(path: Path) -> list[dict[str, Any]]:
    return [
        _object(_loads(line), "JSONL record")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _inside(root: Path, relative: object) -> Path:
    if not isinstance(relative, (str, Path)) or not str(relative):
        raise JudgeGateError("artifact path is invalid")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise JudgeGateError("artifact path escapes or is missing")
    return path


def _file_digest(path: Path, expected: object) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise JudgeGateError(f"frozen artifact digest mismatch: {path.name}")


def _bounded_text(value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError


def _object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise JudgeGateError(f"{name} must be an object")
    return value


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise JudgeGateError("record must be a list")
    return value


def _strings(value: object, name: str) -> list[str]:
    values = _list(value)
    if not all(isinstance(item, str) and item for item in values):
        raise JudgeGateError(f"{name} must contain strings")
    return values


__all__ = [
    "MEASUREMENT_METHOD",
    "JudgeGateError",
    "bailian_complete",
    "build_review_request",
    "finalize_gate",
    "load_gate_inputs",
    "load_phase",
    "preflight",
    "python_syntax_valid",
    "request_for",
    "run_phase",
    "validate_review_response",
]
