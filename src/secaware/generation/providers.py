from pathlib import Path
from typing import Protocol

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.api_provider_stub import APIProviderStub
from secaware.generation.file_provider import FileProvider
from secaware.generation.mock_provider import MockProvider


class CodeGeneratorProvider(Protocol):
    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        ...


def get_provider(provider_name: str, *, file_provider_dir: str | None = None) -> CodeGeneratorProvider:
    if provider_name == "mock":
        return MockProvider()
    if provider_name == "file":
        if file_provider_dir is None:
            raise SecAwareError(
                code=ErrorCode.CONFIG,
                stage="generation",
                message="generation provider configuration is invalid",
            )
        return FileProvider(Path(file_provider_dir))
    if provider_name == "api":
        return APIProviderStub()
    raise SecAwareError(
        code=ErrorCode.CONFIG,
        stage="generation",
        message="generation provider configuration is invalid",
    )
