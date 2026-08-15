"""Construct the frozen functional judge from independent app configuration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from secaware.config import AppConfig, FunctionalJudgeLLMConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.judge import (
    FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
    LLMFunctionalJudge,
)
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredLLMPolicy,
)


def _error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONFIG,
        stage="functional_judge",
        message="functional judge configuration is unavailable",
        retryable=False,
    )


def _policy(config: FunctionalJudgeLLMConfig, seed: int) -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256=hashlib.sha256(config.base_url.encode("utf-8")).hexdigest(),
        model_id=config.model_id,
        system_template_sha256=FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
        output_schema_sha256=FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
        temperature=config.temperature,
        top_p=config.top_p,
        seed=seed,
        timeout_seconds=config.timeout_seconds,
        max_attempts=config.max_attempts,
        max_response_bytes=config.max_response_bytes,
        enable_thinking=config.enable_thinking,
    )


def create_functional_judge(
    config: AppConfig,
    *,
    transport_factory: Callable[..., object] = OpenAICompatibleStructuredTransport,
) -> LLMFunctionalJudge:
    try:
        judge_config = config.functional_judge
        llm = judge_config.llm
        if not judge_config.enabled or type(llm) is not FunctionalJudgeLLMConfig:
            raise ValueError
        checked = FunctionalJudgeLLMConfig.model_validate(llm.model_dump(mode="python"))
        transport = transport_factory(
            base_url=checked.base_url,
            api_key_env=checked.api_key_env,
            system_template=FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE,
        )
        pass_a = _policy(checked, judge_config.pass_seeds[0])
        pass_b = (
            _policy(checked, judge_config.pass_seeds[1])
            if judge_config.mode == "two_pass_consensus"
            else None
        )
        return LLMFunctionalJudge(
            transport,
            pass_a,
            pass_b,
            mode=judge_config.mode,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None


__all__ = ["create_functional_judge"]
