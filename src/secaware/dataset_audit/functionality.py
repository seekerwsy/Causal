from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import stat

from secaware.dataset_audit.schema import AdaptedRecord, FunctionalState
from secaware.errors import SecAwareError
from secaware.process_isolation import run_isolated_process


@dataclass(frozen=True, slots=True)
class FunctionalAssessment:
    state: FunctionalState
    harness: str | None
    contract_path: Path | None
    trusted_contract_root: Path | None
    execution_allowed: bool
    evidence_fields: tuple[str, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SmokeLimits:
    python_executable: Path
    timeout_seconds: float = 10.0
    max_stdout_bytes: int = 64 * 1024
    max_stderr_bytes: int = 64 * 1024


def classify_functional_evidence(
    record: AdaptedRecord,
    dataset_root: Path,
) -> FunctionalAssessment:
    root = Path(dataset_root).resolve()
    fields = tuple(span.field for span in record.functional_evidence_spans)
    reference = next(
        (
            span.text
            for span in record.functional_evidence_spans
            if span.field in {"test_path", "test_case_path"}
        ),
        None,
    )
    contract_path = (root / reference).resolve() if reference else None
    return FunctionalAssessment(
        state=record.functional_state,
        harness=None,
        contract_path=contract_path,
        trusted_contract_root=root,
        execution_allowed=False,
        evidence_fields=fields,
        diagnostics=(),
    )


def _safe_contract_path(assessment: FunctionalAssessment) -> tuple[Path | None, str | None]:
    path = assessment.contract_path
    root = assessment.trusted_contract_root
    if path is None or root is None:
        return None, "functional contract path is missing"
    path = path.resolve()
    root = root.resolve()
    if not path.is_relative_to(root):
        return None, "contract path is outside trusted root"
    try:
        metadata = path.lstat()
    except OSError:
        return None, "functional contract file is missing"
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        return None, "functional contract is not a regular file"
    return path, None


def _isolated_environment() -> dict[str, str]:
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
    }
    for key in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def smoke_validate_existing_contract(
    assessment: FunctionalAssessment,
    limits: SmokeLimits,
) -> FunctionalAssessment:
    if assessment.state is not FunctionalState.PRESENT_UNVALIDATED:
        return replace(
            assessment,
            diagnostics=("functional evidence is not executable and unvalidated",),
        )
    if not assessment.execution_allowed:
        return replace(
            assessment,
            diagnostics=("functional contract execution was not explicitly allowed",),
        )
    if assessment.harness != "python_script_v1":
        return replace(assessment, diagnostics=("unsupported functional harness",))
    contract_path, path_error = _safe_contract_path(assessment)
    if path_error is not None or contract_path is None:
        return replace(assessment, diagnostics=(str(path_error),))
    executable = Path(limits.python_executable).resolve()
    if not executable.is_file() or executable.is_symlink():
        return replace(assessment, diagnostics=("Python executable is unavailable",))
    try:
        run_isolated_process(
            [str(executable), "-I", str(contract_path)],
            cwd=contract_path.parent,
            environment=_isolated_environment(),
            timeout_seconds=limits.timeout_seconds,
            max_stdout_bytes=limits.max_stdout_bytes,
            max_stderr_bytes=limits.max_stderr_bytes,
        )
    except SecAwareError as error:
        failure_kind = str(error.details.get("failure_kind", "backend_failure"))
        return replace(
            assessment,
            diagnostics=(f"contract smoke validation failed: {failure_kind}",),
        )
    return replace(
        assessment,
        state=FunctionalState.EXECUTABLE_VALIDATED,
        diagnostics=("contract smoke validation passed",),
    )
