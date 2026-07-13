from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import tempfile
from typing import Any, Literal, Optional, TypeVar, cast

import typer
from pydantic import BaseModel

from secaware.analysis.effects import estimate_effects
from secaware.analysis.pairing import build_pairs
from secaware.commands.common import cli_action
from secaware.config import AppConfig, OpenAICompatibleConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.providers import get_provider
from secaware.generation.openai_compatible_provider import (
    OpenAICompatibleGenerationResult,
    create_openai_compatible_provider,
)
from secaware.generation.request_planner import (
    MAX_GENERATION_AXIS_ITEMS,
    MAX_GENERATION_REQUESTS,
    plan_counterfactual_requests,
    plan_observed_requests,
)
from secaware.generation.result_importer import (
    MAX_OFFLINE_IMPORT_RECORDS,
    canonical_generated_code_from_request,
    import_offline_results,
)
from secaware.intervention.operators import apply_intervention
from secaware.io.jsonl import canonical_jsonl_sha256, read_jsonl, write_jsonl
from secaware.io.run_store import RunStore, StageCommitLease
from secaware.io.transaction import (
    ArtifactTransaction,
    TransactionArtifact,
    TransactionStateError,
    cleanup_committed_transaction,
    recover_transaction,
    resolve_pending_transaction,
)
from secaware.logging_utils import console
from secaware.oracle.aggregator import AnalyzerRunner, run_oracle_batch
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.jsonl_stage import (
    JsonlOutputSpec,
    execute_jsonl_stage_transaction,
)
from secaware.pipeline.preflight import run_oracle_preflight, run_preflight
from secaware.pipeline.stages.prompt_extraction import (
    run_prompt_extraction_stage as extract_prompt_tsg_stage,
)
from secaware.pipeline.stages.causal_tables import assemble_causal_tables_stage
from secaware.pipeline.stages.fci_discovery import (
    FCIDiscoveryTerminalStatus,
    fci_discovery_stage,
)
from secaware.reports.tables import write_reports
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    sha256_text,
)
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import (
    CanonicalGeneratedCodeRecord,
    PromptRecord,
)
from secaware.schema.oracle import OracleRecord
from secaware.schema.results import EffectRecord, PairResult
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256

app = typer.Typer(help="SecAware reproducible prompt-side security mechanism pipeline.")
GenerationCondition = Literal["observed", "counterfactual"]
GenerationMode = Literal["offline", "provider"]
_Record = TypeVar("_Record")
_ActionResult = TypeVar("_ActionResult")
MAX_GENERATION_JSONL_LINE_CHARS = 8 * 1024 * 1024
MAX_GENERATION_JSONL_TOTAL_CHARS = 512 * 1024 * 1024
MAX_PROVIDER_ATTEMPT_RECORDS = MAX_GENERATION_REQUESTS * 10
MAX_ORACLE_RECORDS = MAX_GENERATION_REQUESTS
TRANSACTION_CLEANUP_ATTEMPTS = 3


def _load(config: Path, run_dir: Optional[Path]) -> tuple[AppConfig, RunStore]:
    loaded = load_config(config, run_dir=run_dir)
    return loaded, RunStore(loaded)


def _prepare(config: AppConfig, store: RunStore) -> None:
    run_preflight(config)
    store.prepare()


def _prompt_records(store: RunStore) -> list[PromptRecord]:
    return read_jsonl(store.path("inputs", "prompts.jsonl"), PromptRecord)  # type: ignore[return-value]


def _prompt_tsg_coordinate_error(stage: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.TSG_INVALID,
        stage=stage,
        message="Prompt TSG coordinates failed validation",
    )


def _validated_prompt_tsg_coordinates(
    store: RunStore,
    *,
    stage: str,
) -> tuple[list[PromptRecord], dict[str, PromptTSGRecord]]:
    prompts: list[PromptRecord] = []
    prompt_tsgs: list[PromptTSGRecord] = []
    prompt_ids: list[str] = []
    graph_prompt_ids: list[str] = []
    prompt_tsg_by_id: dict[str, PromptTSGRecord] = {}
    try:
        prompts = _prompt_records(store)
        prompt_tsgs = cast(
            list[PromptTSGRecord],
            read_jsonl(
                store.path("tsg", "prompt_tsg.jsonl"),
                PromptTSGRecord,
                required=True,
                allow_empty=False,
                stage=stage,
            ),
        )
        prompt_ids = [prompt.prompt_id for prompt in prompts]
        graph_prompt_ids = [prompt_tsg.prompt_id for prompt_tsg in prompt_tsgs]
        if (
            not prompt_ids
            or len(prompt_ids) != len(set(prompt_ids))
            or len(graph_prompt_ids) != len(set(graph_prompt_ids))
            or set(prompt_ids) != set(graph_prompt_ids)
        ):
            raise ValueError("invalid Prompt TSG coordinates")
        prompt_tsg_by_id = {prompt_tsg.prompt_id: prompt_tsg for prompt_tsg in prompt_tsgs}
        return prompts, prompt_tsg_by_id
    except (KeyboardInterrupt, SystemExit):
        prompts.clear()
        prompt_tsgs.clear()
        prompt_ids.clear()
        graph_prompt_ids.clear()
        prompt_tsg_by_id.clear()
        raise
    except Exception:
        prompts.clear()
        prompt_tsgs.clear()
        prompt_ids.clear()
        graph_prompt_ids.clear()
        prompt_tsg_by_id.clear()
        raise _prompt_tsg_coordinate_error(stage) from None


def _generation_condition(value: str) -> GenerationCondition:
    if value == "observed" or value == "counterfactual":
        return cast(GenerationCondition, value)
    raise SecAwareError(
        code=ErrorCode.CONFIG,
        stage="generation",
        message="generation condition is invalid",
    )


def _cli_generation_condition(value: str) -> GenerationCondition:
    if value == "observed":
        return cast(GenerationCondition, value)
    raise SecAwareError(
        code=ErrorCode.CONFIG,
        stage="generation",
        message="only the observed condition is reachable before randomized confirmation",
    )


def _generation_mode(value: str) -> GenerationMode:
    if value == "offline" or value == "provider":
        return cast(GenerationMode, value)
    raise SecAwareError(
        code=ErrorCode.CONFIG,
        stage="generation",
        message="generation mode is invalid",
    )


def _openai_provider_config(
    config: AppConfig,
    *,
    stage: str,
) -> OpenAICompatibleConfig:
    try:
        if config.generation.provider != "openai_compatible":
            raise ValueError
        candidate = config.generation.openai_compatible
        if type(candidate) is not OpenAICompatibleConfig:
            raise TypeError
        return OpenAICompatibleConfig.model_validate(candidate)
    except Exception:
        pass
    raise _generation_stage_error(
        ErrorCode.CONFIG,
        stage,
        "provider generation configuration is unavailable",
    )


def _generation_stage_error(
    code: ErrorCode,
    stage: str,
    message: str,
    *,
    retryable: bool = False,
) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=stage,
        message=message,
        retryable=retryable,
    )


def _read_generation_records(
    path: Path,
    model: type[_Record],
    *,
    stage: str,
    allow_empty: bool,
    max_records: int,
) -> list[_Record]:
    try:
        records = read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            max_records=max_records,
            max_line_chars=MAX_GENERATION_JSONL_LINE_CHARS,
            max_total_chars=MAX_GENERATION_JSONL_TOTAL_CHARS,
            stage=stage,
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return cast(list[_Record], records)
    raise _generation_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "generation artifact failed validation",
    )


def _write_generation_records(
    path: Path,
    records: list[object],
    *,
    stage: str,
) -> None:
    try:
        write_jsonl(path, records, stage=stage)
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return
    raise _generation_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "generation artifact could not be published",
    )


def _read_verified_generation_records(
    store: RunStore,
    path: Path,
    model: type[_Record],
    expected: list[_Record],
    outputs: list[Path],
    *,
    stage: str,
    max_records: int,
    mismatch_message: str,
) -> list[_Record]:
    readback_error: SecAwareError | None = None
    try:
        validated = _read_generation_records(
            path,
            model,
            stage=stage,
            allow_empty=False,
            max_records=max_records,
        )
    except SecAwareError as error:
        readback_error = error
    if readback_error is not None:
        store.verify_sealed_outputs(stage, outputs)
        raise readback_error from None
    if validated != expected:
        store.verify_sealed_outputs(stage, outputs)
        raise _generation_stage_error(
            ErrorCode.CONTRACT,
            stage,
            mismatch_message,
        )
    return validated


def _generation_stage_should_skip(
    store: RunStore,
    stage: str,
    inputs: list[Path],
    outputs: list[Path],
    *,
    force: bool,
) -> bool:
    try:
        return store.should_skip_stage(stage, inputs, outputs, force)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    if store.stage_is_active(stage):
        raise _generation_stage_error(
            code,
            stage,
            "generation stage execution is already active",
            retryable=retryable,
        )
    try:
        store.invalidate_stage(stage)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    raise _generation_stage_error(
        code,
        stage,
        "generation stage inputs could not be verified",
        retryable=retryable,
    )


def _invalidate_alternate_generation_stage(
    store: RunStore,
    *,
    stage: str,
    alternate_stage: str,
) -> None:
    _invalidate_alternate_generation_stages(
        store,
        stage=stage,
        alternate_stages=(alternate_stage,),
    )


def _invalidate_alternate_generation_stages(
    store: RunStore,
    *,
    stage: str,
    alternate_stages: tuple[str, ...],
) -> None:
    failure: SecAwareError | None = None
    for alternate_stage in alternate_stages:
        try:
            store.invalidate_stage(alternate_stage)
        except SecAwareError as error:
            failure = error
    if failure is None:
        return
    try:
        store.invalidate_stage(stage)
    except SecAwareError as error:
        failure = error
    raise _generation_stage_error(
        failure.code,
        stage,
        "generation stage manifest could not be invalidated",
        retryable=failure.retryable,
    )


def _validate_offline_results_path(
    store: RunStore,
    *,
    stage: str,
    condition: GenerationCondition,
    results: Path,
) -> None:
    protected = [
        store.path("generation", f"{condition}_requests.jsonl"),
        store.path("generation", f"{condition}_code.jsonl"),
        store.path("generation", f"{condition}_attempts.jsonl"),
        store.path(".stages", f"plan-generation-{condition}.json"),
        store.path(".stages", f"plan-provider-generation-{condition}.json"),
        store.path(".stages", f"import-generation-{condition}.json"),
        store.path(".stages", f"generate-provider-{condition}.json"),
        store.path(".stages", f"generate-{condition}.json"),
        store.path("config.resolved.yaml"),
        store.path("inputs", "prompts.jsonl"),
        store.path("interventions", "interventions.jsonl"),
        Path(store.config.data.prompts_path),
    ]
    invalid = False
    try:
        resolved_results = results.resolve()
        for protected_path in protected:
            if resolved_results == protected_path.resolve():
                invalid = True
                break
            if (
                results.exists()
                and protected_path.exists()
                and os.path.samefile(
                    results,
                    protected_path,
                )
            ):
                invalid = True
                break
    except (OSError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise _generation_stage_error(
            ErrorCode.CONTRACT,
            stage,
            "offline generation results path conflicts with run artifacts",
        )


def _execute_generation_stage(
    store: RunStore,
    stage: str,
    action: Callable[[], _ActionResult],
) -> _ActionResult:
    failure: BaseException
    try:
        return action()
    except SecAwareError as error:
        failure = _generation_stage_error(
            error.code,
            stage,
            "generation stage execution failed",
            retryable=error.retryable,
        )
    except Exception:
        failure = _generation_stage_error(
            ErrorCode.CONTRACT,
            stage,
            "generation stage execution failed",
        )
    except BaseException as error:
        failure = error
    try:
        store.abort_stage(stage)
    except SecAwareError as error:
        if not isinstance(failure, Exception):
            raise failure from None
        code = error.code
        retryable = error.retryable
    else:
        raise failure from None
    raise _generation_stage_error(
        code,
        stage,
        "failed generation stage could not be invalidated",
        retryable=retryable,
    )


def _require_committed_generation_plan(
    store: RunStore,
    *,
    condition: GenerationCondition,
    import_stage: str,
    legacy_stage: str,
    provider_stage: str,
    ledger: Path,
) -> None:
    plan_stage = f"plan-generation-{condition}"
    plan_inputs = [store.path("inputs", "prompts.jsonl")]
    if condition == "counterfactual":
        plan_inputs.append(store.path("interventions", "interventions.jsonl"))
    try:
        store.require_committed_stage(plan_stage, plan_inputs, [ledger])
    except SecAwareError:
        pass
    else:
        return
    cleanup_failed = False
    for stage in (import_stage, legacy_stage, provider_stage):
        try:
            store.invalidate_stage(stage)
        except SecAwareError:
            cleanup_failed = True
    message = (
        "generation producer trust failure could not be cleaned up"
        if cleanup_failed
        else "generation request ledger is not committed"
    )
    raise _generation_stage_error(
        ErrorCode.MANIFEST_CONFLICT,
        import_stage,
        message,
    )


def _require_committed_provider_generation_plan(
    store: RunStore,
    *,
    condition: GenerationCondition,
    generation_stage: str,
    ledger: Path,
) -> str:
    plan_stage = f"plan-provider-generation-{condition}"
    plan_inputs = [store.path("inputs", "prompts.jsonl")]
    if condition == "counterfactual":
        plan_inputs.append(store.path("interventions", "interventions.jsonl"))
    try:
        output_sha256 = store.require_committed_stage(plan_stage, plan_inputs, [ledger])
    except SecAwareError:
        pass
    else:
        if len(output_sha256) == 1:
            return next(iter(output_sha256.values()))
    try:
        store.invalidate_stage(generation_stage)
    except SecAwareError:
        message = "provider generation plan trust failure could not be cleaned up"
    else:
        message = "provider generation request ledger is not committed"
    raise _generation_stage_error(
        ErrorCode.MANIFEST_CONFLICT,
        generation_stage,
        message,
    )


@contextmanager
def _hold_committed_provider_generation_plan(
    store: RunStore,
    *,
    condition: GenerationCondition,
    generation_stage: str,
    ledger: Path,
) -> Iterator[str]:
    plan_stage = f"plan-provider-generation-{condition}"
    plan_inputs = [store.path("inputs", "prompts.jsonl")]
    if condition == "counterfactual":
        plan_inputs.append(store.path("interventions", "interventions.jsonl"))
    entered = False
    try:
        with store.hold_committed_stage(plan_stage, plan_inputs, [ledger]) as output_sha256:
            entered = True
            if len(output_sha256) != 1:
                raise _generation_stage_error(
                    ErrorCode.MANIFEST_CONFLICT,
                    generation_stage,
                    "provider generation request ledger authorization is invalid",
                )
            yield next(iter(output_sha256.values()))
    except SecAwareError:
        if entered:
            raise
        try:
            store.invalidate_stage(generation_stage)
        except SecAwareError:
            message = "provider generation plan trust failure could not be cleaned up"
        else:
            message = "provider generation request ledger is not committed"
        raise _generation_stage_error(
            ErrorCode.MANIFEST_CONFLICT,
            generation_stage,
            message,
        ) from None


def _require_committed_generation_code(
    store: RunStore,
    *,
    condition: str,
    consumer_stage: str,
    code_output: Path,
) -> None:
    for producer_stage in (
        f"import-generation-{condition}",
        f"generate-provider-{condition}",
        f"generate-{condition}",
    ):
        producer_outputs = [code_output]
        if producer_stage.startswith("generate-provider-"):
            producer_outputs.append(store.path("generation", f"{condition}_attempts.jsonl"))
        try:
            store.require_committed_output(producer_stage, producer_outputs)
        except SecAwareError:
            continue
        return
    try:
        store.invalidate_stage(consumer_stage)
    except SecAwareError:
        pass
    raise _generation_stage_error(
        ErrorCode.MANIFEST_CONFLICT,
        consumer_stage,
        "generation code does not have a committed producer",
    )


@contextmanager
def _hold_committed_generation_code(
    store: RunStore,
    *,
    condition: GenerationCondition,
    consumer_stage: str,
    code_output: Path,
) -> Iterator[dict[str, str]]:
    producer_stage: str | None = None
    producer_outputs: list[Path] = []
    for candidate in (
        f"import-generation-{condition}",
        f"generate-provider-{condition}",
        f"generate-{condition}",
    ):
        outputs = [code_output]
        if candidate.startswith("generate-provider-"):
            outputs.append(store.path("generation", f"{condition}_attempts.jsonl"))
        try:
            store.require_committed_output(candidate, outputs)
        except SecAwareError:
            continue
        producer_stage = candidate
        producer_outputs = outputs
        break
    if producer_stage is None:
        try:
            store.invalidate_stage(consumer_stage)
        except SecAwareError:
            pass
        raise _generation_stage_error(
            ErrorCode.MANIFEST_CONFLICT,
            consumer_stage,
            "generation code does not have a committed producer",
        )
    try:
        with store.hold_committed_output(producer_stage, producer_outputs) as hashes:
            yield hashes
    finally:
        producer_stage = None
        producer_outputs.clear()
        producer_outputs = []


def _oracle_stage_error(code: ErrorCode, stage: str, message: str) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=stage,
        message=message,
        details={},
        retryable=False,
    )


def _read_canonical_oracle_input(path: Path, *, stage: str) -> list[CanonicalGeneratedCodeRecord]:
    try:
        records = read_jsonl(
            path,
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
            max_records=MAX_ORACLE_RECORDS,
            max_line_chars=MAX_GENERATION_JSONL_LINE_CHARS,
            max_total_chars=MAX_GENERATION_JSONL_TOTAL_CHARS,
            stage=stage,
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return cast(list[CanonicalGeneratedCodeRecord], records)
    raise _oracle_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "generated code artifact failed canonical validation",
    ) from None


def _read_oracle_output(
    path: Path,
    *,
    stage: str,
    condition: GenerationCondition | None = None,
) -> list[OracleRecord]:
    try:
        records = read_jsonl(
            path,
            OracleRecord,
            required=True,
            allow_empty=False,
            max_records=MAX_ORACLE_RECORDS,
            max_line_chars=MAX_GENERATION_JSONL_LINE_CHARS,
            max_total_chars=MAX_GENERATION_JSONL_TOTAL_CHARS,
            stage=stage,
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        validated = cast(list[OracleRecord], records)
        if condition is not None and any(record.condition != condition for record in validated):
            pass
        elif len({record.request_id for record in validated}) != len(validated):
            pass
        elif len({record.code_id for record in validated}) != len(validated):
            pass
        else:
            return validated
    raise _oracle_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "oracle artifact failed canonical validation",
    ) from None


def _oracle_transaction_path(output: Path, suffix: str) -> Path:
    handle = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{output.name}.",
            suffix=suffix,
            dir=output.parent,
            delete=False,
        )
        path = Path(handle.name)
        handle.close()
        handle = None
        path.unlink()
        return path
    except OSError:
        raise _oracle_stage_error(
            ErrorCode.CONTRACT,
            "oracle",
            "Oracle output transaction is unavailable",
        ) from None
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


def _cleanup_failed_oracle_stage(store: RunStore, stage: str) -> None:
    if not store.stage_is_active(stage):
        return
    try:
        store.abort_stage(stage)
    except SecAwareError:
        pass


def _finalize_stage_commit(
    store: RunStore,
    lease: StageCommitLease,
) -> None:
    failure: BaseException | None = None
    try:
        store.finalize_stage_commit(lease)
    except BaseException as error:
        failure = error
    finally:
        try:
            store.ensure_stage_commit_released(lease)
        except BaseException as error:
            if failure is None or (
                isinstance(error, (KeyboardInterrupt, SystemExit))
                and not isinstance(failure, (KeyboardInterrupt, SystemExit))
            ):
                failure = error
    if failure is not None:
        raise failure


def _cleanup_transaction_paths(
    paths: Sequence[Path | None],
) -> KeyboardInterrupt | SystemExit | None:
    pending = list(dict.fromkeys(path for path in paths if path is not None))
    control: KeyboardInterrupt | SystemExit | None = None
    for _ in range(TRANSACTION_CLEANUP_ATTEMPTS):
        remaining: list[Path] = []
        for path in pending:
            try:
                path.unlink(missing_ok=True)
            except (KeyboardInterrupt, SystemExit) as error:
                if control is None:
                    control = error
                remaining.append(path)
            except Exception:
                remaining.append(path)
        pending = remaining
        if not pending:
            break
    return control


def _stale_transaction_paths(path: Path, *suffixes: str) -> list[Path]:
    stale: list[Path] = []
    for suffix in suffixes:
        try:
            stale.extend(path.parent.glob(f".{path.name}.*{suffix}"))
        except OSError:
            pass
    return stale


def plan_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: GenerationCondition,
    mode: GenerationMode = "offline",
    force: bool,
) -> None:
    condition = _generation_condition(condition)
    mode = _generation_mode(mode)
    if mode == "provider":
        stage = f"plan-provider-generation-{condition}"
        alternate_stage = f"plan-generation-{condition}"
        provider_config = _openai_provider_config(config, stage=stage)
    else:
        stage = f"plan-generation-{condition}"
        alternate_stage = f"plan-provider-generation-{condition}"
        provider_config = None
    prompts_path = store.path("inputs", "prompts.jsonl")
    inputs = [prompts_path]
    if condition == "counterfactual":
        inputs.append(store.path("interventions", "interventions.jsonl"))
    output = store.path("generation", f"{condition}_requests.jsonl")
    outputs = [output]
    _invalidate_alternate_generation_stage(
        store,
        stage=stage,
        alternate_stage=alternate_stage,
    )
    if _generation_stage_should_skip(store, stage, inputs, outputs, force=force):
        return

    def execute() -> None:
        prompts = _read_generation_records(
            prompts_path,
            PromptRecord,
            stage=stage,
            allow_empty=False,
            max_records=MAX_GENERATION_AXIS_ITEMS,
        )
        if provider_config is not None:
            planning_options: dict[str, object] = {
                "endpoint_type": "chat_completions",
                "endpoint_identity": provider_config.base_url,
                "parameters": provider_config.parameters,
                "system_template": provider_config.system_template,
                "system_template_version": provider_config.system_template_version,
            }
        else:
            planning_options = {"endpoint_type": "offline"}
        if condition == "observed":
            records = plan_observed_requests(
                prompts,
                config.generation.models,
                config.generation.seeds,
                **planning_options,  # type: ignore[arg-type]
            )
        else:
            interventions = _read_generation_records(
                inputs[1],
                InterventionRecord,
                stage=stage,
                allow_empty=False,
                max_records=MAX_GENERATION_AXIS_ITEMS,
            )
            records = plan_counterfactual_requests(
                {prompt.prompt_id: prompt for prompt in prompts},
                interventions,
                config.generation.models,
                config.generation.seeds,
                **planning_options,  # type: ignore[arg-type]
            )
        _write_generation_records(output, cast(list[object], records), stage=stage)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            GenerationRequestRecord,
            records,
            outputs,
            stage=stage,
            max_records=MAX_GENERATION_REQUESTS,
            mismatch_message="generation request ledger changed during publication",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def import_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: GenerationCondition,
    results_path: Path,
    force: bool,
) -> None:
    del config
    condition = _generation_condition(condition)
    stage = f"import-generation-{condition}"
    legacy_stage = f"generate-{condition}"
    provider_stage = f"generate-provider-{condition}"
    ledger = store.path("generation", f"{condition}_requests.jsonl")
    output = store.path("generation", f"{condition}_code.jsonl")
    outputs = [output]
    results = Path(results_path)

    _validate_offline_results_path(
        store,
        stage=stage,
        condition=condition,
        results=results,
    )

    if not results.is_file():
        invalidation_failure: SecAwareError | None = None
        for producer_stage in (stage, legacy_stage, provider_stage):
            try:
                store.invalidate_stage(producer_stage)
            except SecAwareError as error:
                invalidation_failure = error
        if invalidation_failure is not None:
            raise _generation_stage_error(
                invalidation_failure.code,
                stage,
                "generation producer trust failure could not be cleaned up",
                retryable=invalidation_failure.retryable,
            )
        raise _generation_stage_error(
            ErrorCode.EXTERNAL_INPUT_REQUIRED,
            stage,
            "offline generation results are required",
            retryable=True,
        )

    _require_committed_generation_plan(
        store,
        condition=condition,
        import_stage=stage,
        legacy_stage=legacy_stage,
        provider_stage=provider_stage,
        ledger=ledger,
    )
    _invalidate_alternate_generation_stages(
        store,
        stage=stage,
        alternate_stages=(legacy_stage, provider_stage),
    )
    inputs = [ledger, results]
    if _generation_stage_should_skip(store, stage, inputs, outputs, force=force):
        return

    def execute() -> None:
        expected = _read_generation_records(
            ledger,
            GenerationRequestRecord,
            stage=stage,
            allow_empty=False,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
        )
        received = _read_generation_records(
            results,
            OfflineGenerationResultRecord,
            stage=stage,
            allow_empty=True,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
        )
        imported = import_offline_results(expected, received)
        _write_generation_records(output, cast(list[object], imported), stage=stage)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            CanonicalGeneratedCodeRecord,
            imported,
            outputs,
            stage=stage,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
            mismatch_message="canonical generation output changed during publication",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def generate_provider_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: GenerationCondition,
    force: bool,
) -> None:
    condition = _generation_condition(condition)
    stage = f"generate-provider-{condition}"
    provider_config = _openai_provider_config(config, stage=stage)
    ledger = store.path("generation", f"{condition}_requests.jsonl")
    code_output = store.path("generation", f"{condition}_code.jsonl")
    attempts_output = store.path("generation", f"{condition}_attempts.jsonl")
    outputs = [code_output, attempts_output]
    _invalidate_alternate_generation_stages(
        store,
        stage=stage,
        alternate_stages=(
            f"import-generation-{condition}",
            f"generate-{condition}",
        ),
    )
    with _hold_committed_provider_generation_plan(
        store,
        condition=condition,
        generation_stage=stage,
        ledger=ledger,
    ) as expected_ledger_sha256:
        inputs = [ledger]
        if _generation_stage_should_skip(store, stage, inputs, outputs, force=force):
            return

        def execute() -> None:
            requests: list[GenerationRequestRecord] = []
            code_records: list[CanonicalGeneratedCodeRecord] = []
            attempt_records: list[GenerationAttemptRecord] = []
            request: GenerationRequestRecord | None = None
            result: OpenAICompatibleGenerationResult | None = None
            provider: object | None = None
            failure: SecAwareError | None = None
            try:
                requests = _read_generation_records(
                    ledger,
                    GenerationRequestRecord,
                    stage=stage,
                    allow_empty=False,
                    max_records=MAX_GENERATION_REQUESTS,
                )
                if canonical_jsonl_sha256(requests, stage=stage) != expected_ledger_sha256:
                    raise _generation_stage_error(
                        ErrorCode.MANIFEST_CONFLICT,
                        stage,
                        "provider generation request ledger changed after authorization",
                    )
                current_ledger_sha256 = _require_committed_provider_generation_plan(
                    store,
                    condition=condition,
                    generation_stage=stage,
                    ledger=ledger,
                )
                if current_ledger_sha256 != expected_ledger_sha256:
                    raise _generation_stage_error(
                        ErrorCode.MANIFEST_CONFLICT,
                        stage,
                        "provider generation request authorization changed during execution",
                    )
                if any(
                    candidate.condition != condition
                    or candidate.endpoint_type != "chat_completions"
                    or candidate.endpoint_sha256 != sha256_text(provider_config.base_url)
                    for candidate in requests
                ):
                    raise _generation_stage_error(
                        ErrorCode.CONTRACT,
                        stage,
                        "provider generation request ledger is incompatible",
                    )
                provider = create_openai_compatible_provider(provider_config)
                for request in requests:
                    api_ledger_sha256 = _require_committed_provider_generation_plan(
                        store,
                        condition=condition,
                        generation_stage=stage,
                        ledger=ledger,
                    )
                    if api_ledger_sha256 != expected_ledger_sha256:
                        raise _generation_stage_error(
                            ErrorCode.MANIFEST_CONFLICT,
                            stage,
                            "provider generation request authorization changed before API use",
                        )
                    candidate = provider.generate(  # type: ignore[attr-defined]
                        request,
                        provider_config.system_template,
                    )
                    if type(candidate) is not OpenAICompatibleGenerationResult:
                        raise _generation_stage_error(
                            ErrorCode.CONTRACT,
                            stage,
                            "provider generation result failed validation",
                        )
                    result = candidate
                    if any(attempt.request_id != request.request_id for attempt in result.attempts):
                        raise _generation_stage_error(
                            ErrorCode.CONTRACT,
                            stage,
                            "provider generation attempt journal failed validation",
                        )
                    code_records.append(
                        canonical_generated_code_from_request(
                            request,
                            result.code,
                            result.provenance,
                        )
                    )
                    attempt_records.extend(result.attempts)
                _write_generation_records(
                    code_output,
                    cast(list[object], code_records),
                    stage=stage,
                )
                _write_generation_records(
                    attempts_output,
                    cast(list[object], attempt_records),
                    stage=stage,
                )
                store.seal_stage_outputs(stage, outputs)
                _read_verified_generation_records(
                    store,
                    code_output,
                    CanonicalGeneratedCodeRecord,
                    code_records,
                    outputs,
                    stage=stage,
                    max_records=MAX_GENERATION_REQUESTS,
                    mismatch_message="provider generation code changed during publication",
                )
                _read_verified_generation_records(
                    store,
                    attempts_output,
                    GenerationAttemptRecord,
                    attempt_records,
                    outputs,
                    stage=stage,
                    max_records=MAX_PROVIDER_ATTEMPT_RECORDS,
                    mismatch_message="provider generation journal changed during publication",
                )
                store.record_stage(stage, inputs, outputs)
            except SecAwareError as error:
                failure = error
            except Exception:
                failure = _generation_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "provider generation failed validation",
                )
            finally:
                requests.clear()
                code_records.clear()
                attempt_records.clear()
                request = None
                result = None
                provider = None
            if failure is not None:
                raise failure from None

        _execute_generation_stage(store, stage, execute)


def generate_observed_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    if config.generation.provider == "openai_compatible":
        plan_generation_stage(
            config,
            store,
            condition="observed",
            mode="provider",
            force=force,
        )
        generate_provider_stage(
            config,
            store,
            condition="observed",
            force=force,
        )
        return
    stage = "generate-observed"
    inputs = [store.path("inputs", "prompts.jsonl")]
    if config.generation.provider == "file" and config.generation.file_provider_dir is not None:
        inputs.append(Path(config.generation.file_provider_dir))
    output = store.path("generation", "observed_code.jsonl")
    outputs = [output]
    _invalidate_alternate_generation_stages(
        store,
        stage=stage,
        alternate_stages=(
            "import-generation-observed",
            "generate-provider-observed",
        ),
    )
    if store.should_skip_stage(stage, inputs, outputs, force):
        return

    def execute() -> None:
        prompts = _prompt_records(store)
        provider = get_provider(
            config.generation.provider,
            file_provider_dir=config.generation.file_provider_dir,
        )
        if config.generation.provider == "mock":
            requests = plan_observed_requests(
                prompts,
                config.generation.models,
                config.generation.seeds,
                endpoint_type="mock",
            )
            producer = "mock"
        elif config.generation.provider == "file":
            requests = plan_observed_requests(
                prompts,
                config.generation.models,
                config.generation.seeds,
                endpoint_type="offline",
                endpoint_identity=config.generation.file_provider_dir,
            )
            producer = "file_provider"
        else:
            raise _generation_stage_error(
                ErrorCode.CONFIG,
                stage,
                "generation provider is unavailable",
            )
        records = [
            canonical_generated_code_from_request(
                request,
                provider.generate(
                    request.prompt,
                    model_id=request.model_id,
                    seed=request.seed_id,
                    language=request.language,
                ),
                GenerationProvenance(
                    producer=producer,
                    producer_version="compatibility-v1",
                ),
            )
            for request in requests
        ]
        write_jsonl(output, records)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            CanonicalGeneratedCodeRecord,
            records,
            outputs,
            stage=stage,
            max_records=MAX_GENERATION_REQUESTS,
            mismatch_message="generated code artifact failed canonical readback",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def _run_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: str,
    force: bool,
    runner: AnalyzerRunner | None = None,
    runtime_validator: Callable[[], object] | None = None,
) -> None:
    validated_condition = _generation_condition(condition)
    runner = run_analyzer_process if runner is None else runner
    runtime_validator = (
        validate_analyzer_runtime if runtime_validator is None else runtime_validator
    )
    stage = f"run-oracle-{validated_condition}"
    source_name = f"{validated_condition}_code.jsonl"
    output_name = f"{validated_condition}_oracle.jsonl"
    inputs = [store.path("generation", source_name)]
    output = store.path("oracle", output_name)
    outputs = [output]
    candidate_output: Path | None = None
    manifest_path = store.path(".stages", f"{stage}.json")
    journal_path = store.path(".stages", f".{stage}.transaction.json")
    try:
        artifacts = (
            TransactionArtifact(output, "oracle"),
            TransactionArtifact(manifest_path, "manifest"),
        )
    except TransactionStateError:
        raise _oracle_stage_error(
            ErrorCode.CONTRACT,
            stage,
            "Oracle output transaction is invalid",
        ) from None
    transaction: ArtifactTransaction | None = None
    stage_commit_lease = None
    commit_point = False

    def recover_or_cleanup_transaction() -> None:
        try:
            resolve_pending_transaction(journal_path, artifacts)
        except (KeyboardInterrupt, SystemExit):
            raise
        except TransactionStateError:
            raise _oracle_stage_error(
                ErrorCode.CONTRACT,
                stage,
                "Oracle output transaction recovery failed",
            ) from None
        stale_paths = _stale_transaction_paths(output, ".oracle.candidate")
        stale_control = _cleanup_transaction_paths(stale_paths)
        if stale_control is not None:
            raise stale_control

    try:
        with _hold_committed_generation_code(
            store,
            condition=validated_condition,
            consumer_stage=stage,
            code_output=inputs[0],
        ) as producer_hashes:
            initial_policy = run_oracle_preflight(
                config.oracle,
                runner=runner,
                runtime_validator=runtime_validator,
            )
            if store.should_skip_stage(
                stage,
                inputs,
                outputs,
                force,
                policy_sha256=initial_policy.combined_sha256,
                preserve_committed=True,
                after_lease_acquired=recover_or_cleanup_transaction,
            ):
                return
            try:
                transaction = ArtifactTransaction.begin(journal_path, artifacts)
                transaction.backup(1)
            except (KeyboardInterrupt, SystemExit):
                raise
            except TransactionStateError:
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "Oracle output transaction could not be started",
                ) from None
            codes = _read_canonical_oracle_input(inputs[0], stage=stage)
            if any(code.condition != validated_condition for code in codes):
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "generated code condition does not match the Oracle stage",
                )
            input_digest = sha256_path(inputs[0])
            expected_input_digest = producer_hashes.get(
                f"generation/{validated_condition}_code.jsonl"
            )
            if input_digest != expected_input_digest:
                raise _oracle_stage_error(
                    ErrorCode.MANIFEST_CONFLICT,
                    stage,
                    "generation producer output changed before Oracle execution",
                )
            execution_policy = run_oracle_preflight(
                config.oracle,
                runner=runner,
                runtime_validator=runtime_validator,
            )
            if execution_policy.combined_sha256 != initial_policy.combined_sha256:
                raise _oracle_stage_error(
                    ErrorCode.POLICY_MISMATCH,
                    stage,
                    "Oracle policy changed before execution",
                )
            records = run_oracle_batch(
                codes,
                execution_policy,
                semgrep_executable=config.oracle.semgrep_executable,
                bandit_executable=config.oracle.bandit_executable,
                timeout_seconds=config.oracle.timeout_seconds,
                max_stdout_bytes=config.oracle.max_stdout_bytes,
                max_stderr_bytes=config.oracle.max_stderr_bytes,
                runner=runner,
            )
            if sha256_path(inputs[0]) != input_digest:
                raise _oracle_stage_error(
                    ErrorCode.MANIFEST_CONFLICT,
                    stage,
                    "generation producer output changed during Oracle execution",
                )
            candidate_output = _oracle_transaction_path(output, ".oracle.candidate")
            write_jsonl(candidate_output, records, stage=stage)
            if (
                _read_oracle_output(
                    candidate_output,
                    stage=stage,
                    condition=validated_condition,
                )
                != records
            ):
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "oracle artifact failed canonical readback",
                )
            try:
                transaction.install(0, candidate_output)
                candidate_output = None
            except (KeyboardInterrupt, SystemExit):
                raise
            except TransactionStateError:
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "oracle artifact could not be committed",
                ) from None
            store.seal_stage_outputs(stage, outputs)
            if (
                _read_oracle_output(
                    output,
                    stage=stage,
                    condition=validated_condition,
                )
                != records
            ):
                store.verify_sealed_outputs(stage, outputs)
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "oracle artifact failed canonical readback",
                )
            store.verify_sealed_outputs(stage, outputs)
            stage_commit_lease = store.begin_stage_commit(stage)
            store.record_stage(
                stage,
                inputs,
                outputs,
                policy_sha256=execution_policy.combined_sha256,
                lease=stage_commit_lease,
            )
            try:
                transaction.mark_postcommit()
            except (KeyboardInterrupt, SystemExit):
                raise
            except TransactionStateError:
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "Oracle stage commit verification failed",
                ) from None
            commit_point = True
            _finalize_stage_commit(store, stage_commit_lease)
            stage_commit_lease = None
            try:
                cleanup_committed_transaction(transaction)
            except (KeyboardInterrupt, SystemExit):
                raise
            except TransactionStateError:
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "Oracle stage commit verification failed",
                ) from None
    except BaseException as error:
        if transaction is not None and not commit_point:
            try:
                recover_transaction(transaction)
            except (KeyboardInterrupt, SystemExit):
                _cleanup_failed_oracle_stage(store, stage)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise error
                raise
            except TransactionStateError:
                _cleanup_failed_oracle_stage(store, stage)
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise error
                raise _oracle_stage_error(
                    ErrorCode.CONTRACT,
                    stage,
                    "Oracle output transaction rollback failed",
                ) from None
        if not commit_point:
            _cleanup_failed_oracle_stage(store, stage)
        raise
    finally:
        if not commit_point:
            _cleanup_transaction_paths([candidate_output])
        runner = None
        runtime_validator = None


def _public_oracle_error(code: ErrorCode, stage: str) -> SecAwareError:
    messages = {
        ErrorCode.CONFIG: "Oracle stage configuration is invalid",
        ErrorCode.CONTRACT: "Oracle stage artifact validation failed",
        ErrorCode.ANALYZER_MISSING: "analyzer executable is unavailable",
        ErrorCode.ANALYZER_FAILED: "analyzer execution failed",
        ErrorCode.ANALYZER_INVALID_OUTPUT: "analyzer output is invalid",
        ErrorCode.POLICY_MISMATCH: "analyzer policy or version does not match",
        ErrorCode.MANIFEST_CONFLICT: "Oracle stage trust verification failed",
    }
    if code not in messages:
        code = ErrorCode.ANALYZER_FAILED
    return _oracle_stage_error(code, stage, messages[code])


def run_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: str,
    force: bool,
    runner: AnalyzerRunner | None = None,
    runtime_validator: Callable[[], object] | None = None,
) -> None:
    failure_code: ErrorCode | None = None
    control: KeyboardInterrupt | SystemExit | None = None
    stage = "oracle"
    try:
        stage = (
            f"run-oracle-{condition}" if condition in {"observed", "counterfactual"} else "oracle"
        )
        _run_oracle_stage(
            config,
            store,
            condition=condition,
            force=force,
            runner=runner,
            runtime_validator=runtime_validator,
        )
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure_code = error.code
    except Exception:
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        config = None  # type: ignore[assignment]
        store = None  # type: ignore[assignment]
        condition = ""
        runner = None
        runtime_validator = None
    if control is not None:
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure_code is not None:
        raise _public_oracle_error(failure_code, stage) from None


def discover_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    assemble_causal_tables_stage(config, store, force=force)
    result = fci_discovery_stage(config, store, force=force)
    if result.status is not FCIDiscoveryTerminalStatus.READY:
        raise SecAwareError(
            code=ErrorCode.ANALYSIS_INVALID,
            stage="discover",
            message=f"FCI discovery terminated: {result.status.value}",
        )


def intervene_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "intervene"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    output = store.path("interventions", "interventions.jsonl")
    paired_output = store.path("interventions", "paired_prompts.jsonl")

    def build() -> Sequence[Sequence[BaseModel | dict[Any, Any]]]:
        all_prompts, prompt_tsg_by_id = _validated_prompt_tsg_coordinates(
            store,
            stage=stage,
        )
        prompts = [prompt for prompt in all_prompts if prompt.split == "confirm"]
        hypotheses = read_jsonl(
            store.path("discovery", "hypotheses_selected.jsonl"),
            HypothesisRecord,
            required=True,
            allow_empty=True,
            stage=stage,
        )
        interventions: list[InterventionRecord] = []
        for hypothesis in hypotheses:
            if "risk_down" not in config.intervention.enabled_directions:
                continue
            for prompt in prompts:
                if not _matches_scope(prompt, hypothesis):
                    continue
                interventions.append(
                    apply_intervention(prompt, prompt_tsg_by_id[prompt.prompt_id], hypothesis)
                )
        paired_prompts = [
            {
                "intervention_id": item.intervention_id,
                "prompt_id": item.prompt_id,
                "hypothesis_id": item.hypothesis_id,
                "original_prompt": item.original_prompt,
                "counterfactual_prompt": item.counterfactual_prompt,
            }
            for item in interventions
        ]
        return [interventions, paired_prompts]

    producer_outputs = {
        "discover": [
            store.path("discovery", "hypotheses_all.jsonl"),
            store.path("discovery", "hypotheses_selected.jsonl"),
        ],
        "extract-prompt-tsg": [
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            store.path("tsg", "prompt_tsg.jsonl"),
        ],
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            if producer_stage == "extract-prompt-tsg":
                producer_context = store.hold_committed_stage(
                    producer_stage,
                    [store.path("inputs", "prompts.jsonl")],
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
                )
            else:
                producer_context = store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                )
            stack.enter_context(producer_context)
        execute_jsonl_stage_transaction(
            store,
            stage=stage,
            inputs=inputs,
            outputs=(
                JsonlOutputSpec(output, InterventionRecord),
                JsonlOutputSpec(paired_output, None),
            ),
            force=force,
            build=build,
        )


def generate_counterfactual_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    if config.generation.provider == "openai_compatible":
        plan_generation_stage(
            config,
            store,
            condition="counterfactual",
            mode="provider",
            force=force,
        )
        generate_provider_stage(
            config,
            store,
            condition="counterfactual",
            force=force,
        )
        return
    stage = "generate-counterfactual"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("interventions", "interventions.jsonl"),
    ]
    if config.generation.provider == "file" and config.generation.file_provider_dir is not None:
        inputs.append(Path(config.generation.file_provider_dir))
    output = store.path("generation", "counterfactual_code.jsonl")
    outputs = [output]
    _invalidate_alternate_generation_stages(
        store,
        stage=stage,
        alternate_stages=(
            "import-generation-counterfactual",
            "generate-provider-counterfactual",
        ),
    )
    if store.should_skip_stage(stage, inputs, outputs, force):
        return

    def execute() -> None:
        prompts = {prompt.prompt_id: prompt for prompt in _prompt_records(store)}
        interventions = read_jsonl(
            store.path("interventions", "interventions.jsonl"), InterventionRecord
        )
        provider = get_provider(
            config.generation.provider,
            file_provider_dir=config.generation.file_provider_dir,
        )
        if config.generation.provider == "mock":
            requests = plan_counterfactual_requests(
                prompts,
                interventions,  # type: ignore[arg-type]
                config.generation.models,
                config.generation.seeds,
                endpoint_type="mock",
            )
            producer = "mock"
        elif config.generation.provider == "file":
            requests = plan_counterfactual_requests(
                prompts,
                interventions,  # type: ignore[arg-type]
                config.generation.models,
                config.generation.seeds,
                endpoint_type="offline",
                endpoint_identity=config.generation.file_provider_dir,
            )
            producer = "file_provider"
        else:
            raise _generation_stage_error(
                ErrorCode.CONFIG,
                stage,
                "generation provider is unavailable",
            )
        records = [
            canonical_generated_code_from_request(
                request,
                provider.generate(
                    request.prompt,
                    model_id=request.model_id,
                    seed=request.seed_id,
                    language=request.language,
                ),
                GenerationProvenance(
                    producer=producer,
                    producer_version="compatibility-v1",
                ),
            )
            for request in requests
        ]
        write_jsonl(output, records)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            CanonicalGeneratedCodeRecord,
            records,
            outputs,
            stage=stage,
            max_records=MAX_GENERATION_REQUESTS,
            mismatch_message="generated code artifact failed canonical readback",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def confirm_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "confirm"
    inputs = [
        store.path("interventions", "interventions.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
        store.path("oracle", "counterfactual_oracle.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    pair_output = store.path("analysis", "pair_results.jsonl")
    effect_output = store.path("analysis", "hypothesis_effects.jsonl")
    outputs = [pair_output, effect_output]
    observed_output = store.path("oracle", "observed_oracle.jsonl")
    counterfactual_output = store.path("oracle", "counterfactual_oracle.jsonl")

    def build() -> Sequence[Sequence[BaseModel | dict[Any, Any]]]:
        interventions = cast(
            list[InterventionRecord],
            read_jsonl(
                store.path("interventions", "interventions.jsonl"),
                InterventionRecord,
            ),
        )
        observed = _read_oracle_output(
            observed_output,
            stage=stage,
            condition="observed",
        )
        counterfactual = _read_oracle_output(
            counterfactual_output,
            stage=stage,
            condition="counterfactual",
        )
        pairs = build_pairs(interventions, observed, counterfactual)
        effects = estimate_effects(
            pairs,
            bootstrap_samples=config.analysis.bootstrap_samples,
            ci_level=config.analysis.ci_level,
            min_eligible_pairs=config.analysis.min_eligible_pairs,
            min_flip_rate=config.analysis.min_flip_rate,
            max_side_effect_rate_confirmed=config.analysis.max_side_effect_rate_confirmed,
            random_seed=config.run.random_seed,
        )
        hypotheses = {
            hypothesis.hypothesis_id: hypothesis
            for hypothesis in read_jsonl(
                store.path("discovery", "hypotheses_selected.jsonl"), HypothesisRecord
            )
        }
        for effect in effects:
            hypothesis = hypotheses.get(effect.hypothesis_id)
            if hypothesis:
                effect.scope_cwe = hypothesis.scope.get("cwe", "")
                effect.scope_task_family = hypothesis.scope.get("task_family", "")
        return [pairs, effects]

    with ExitStack() as stack:
        stack.enter_context(store.hold_committed_output("run-oracle-observed", [observed_output]))
        stack.enter_context(
            store.hold_committed_output(
                "run-oracle-counterfactual",
                [counterfactual_output],
            )
        )
        execute_jsonl_stage_transaction(
            store,
            stage=stage,
            inputs=inputs,
            outputs=(
                JsonlOutputSpec(outputs[0], PairResult),
                JsonlOutputSpec(outputs[1], EffectRecord),
            ),
            force=force,
            build=build,
        )


def report_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    del config
    stage = "report"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
        store.path("interventions", "interventions.jsonl"),
        store.path("analysis", "pair_results.jsonl"),
        store.path("analysis", "hypothesis_effects.jsonl"),
    ]
    outputs = [
        store.path("reports", "funnel.csv"),
        store.path("reports", "effects.csv"),
        store.path("reports", "failures.csv"),
        store.path("reports", "mechanism_cards.jsonl"),
        store.path("reports", "summary.md"),
    ]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    write_reports(
        store.path("reports"),
        prompts=_prompt_records(store),
        hypotheses_all=read_jsonl(
            store.path("discovery", "hypotheses_all.jsonl"), HypothesisRecord
        ),  # type: ignore[arg-type]
        hypotheses_selected=read_jsonl(
            store.path("discovery", "hypotheses_selected.jsonl"), HypothesisRecord
        ),  # type: ignore[arg-type]
        interventions=read_jsonl(
            store.path("interventions", "interventions.jsonl"), InterventionRecord
        ),  # type: ignore[arg-type]
        pairs=read_jsonl(store.path("analysis", "pair_results.jsonl"), PairResult),  # type: ignore[arg-type]
        effects=read_jsonl(store.path("analysis", "hypothesis_effects.jsonl"), EffectRecord),  # type: ignore[arg-type]
    )
    store.record_stage(stage, inputs, outputs)


def _matches_scope(prompt: PromptRecord, hypothesis: HypothesisRecord) -> bool:
    task_family = hypothesis.scope.get("task_family")
    cwe = hypothesis.scope.get("cwe")
    return (not task_family or prompt.task_family == task_family) and (not cwe or prompt.cwe == cwe)


def _safe_id(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)


@app.callback()
def main() -> None:
    """Run SecAware pipeline stages."""


@app.command("preflight")
@cli_action
def preflight_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
) -> None:
    cfg, _store = _load(config, run_dir)
    report = run_preflight(cfg)
    typer.echo(
        "Preflight OK: "
        f"prompts={report.prompt_count} "
        f"discover={report.discover_count} "
        f"confirm={report.confirm_count} "
        f"models={report.model_count} "
        f"seeds={report.seed_count} "
        f"output_dir={report.output_dir}"
    )


@app.command("extract-prompt-tsg")
@cli_action
def extract_prompt_tsg_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    extract_prompt_tsg_stage(cfg, store, force=force)


@app.command("generate-observed")
@cli_action
def generate_observed_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    generate_observed_stage(cfg, store, force=force)


@app.command("plan-generation")
@cli_action
def plan_generation_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    mode: str = typer.Option("offline", "--mode", hidden=True),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _cli_generation_condition(condition)
    validated_mode = _generation_mode(mode)
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    plan_generation_stage(
        cfg,
        store,
        condition=validated_condition,
        mode=validated_mode,
        force=force,
    )


@app.command("generate")
@cli_action
def generate_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _cli_generation_condition(condition)
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    plan_generation_stage(
        cfg,
        store,
        condition=validated_condition,
        mode="provider",
        force=force,
    )
    generate_provider_stage(
        cfg,
        store,
        condition=validated_condition,
        force=force,
    )


@app.command("import-generation")
@cli_action
def import_generation_command(
    config: Path = typer.Option(..., "--config"),
    results: Path = typer.Option(..., "--results"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _cli_generation_condition(condition)
    cfg, store = _load(config, run_dir)
    import_generation_stage(
        cfg,
        store,
        condition=validated_condition,
        results_path=results,
        force=force,
    )


@app.command("run-oracle")
@cli_action
def run_oracle_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _cli_generation_condition(condition)
    cfg, store = _load(config, run_dir)
    run_oracle_stage(cfg, store, condition=validated_condition, force=force)


@app.command("discover")
@cli_action
def discover_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    discover_stage(cfg, store, force=force)


@app.command("run-all")
@cli_action
def run_all_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    extract_prompt_tsg_stage(cfg, store, force=force)
    generate_observed_stage(cfg, store, force=force)
    run_oracle_stage(cfg, store, condition="observed", force=force)
    discover_stage(cfg, store, force=force)
    console.print(f"SecAware discovery complete: {store.root}")


if __name__ == "__main__":
    app()
