from pathlib import Path

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.file_provider import FileProvider


def _generate(provider: FileProvider, model_id: str) -> str:
    return provider.generate(
        "prompt",
        model_id=model_id,
        seed=7,
        language="python",
    )


@pytest.mark.parametrize("escape_kind", ["traversal", "absolute"])
def test_file_provider_rejects_paths_outside_resolved_root_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    escape_kind: str,
) -> None:
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    if escape_kind == "traversal":
        model_id = "../private/model"
        outside_path = tmp_path / "private" / "model_7.py"
    else:
        outside_stem = tmp_path / "private-absolute" / "model"
        model_id = str(outside_stem)
        outside_path = Path(f"{outside_stem}_7.py")
    outside_path.parent.mkdir(parents=True)
    outside_path.write_text("top-secret outside code\n", encoding="utf-8")
    read_paths: list[Path] = []
    original_read_text = Path.read_text

    def track_read_text(path: Path, *args: object, **kwargs: object) -> str:
        read_paths.append(path)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", track_read_text)

    with pytest.raises(SecAwareError) as exc_info:
        _generate(FileProvider(provider_root), model_id)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "generation"
    assert read_paths == []
    rendered = str(exc_info.value.to_dict())
    assert model_id not in rendered
    assert str(outside_path) not in rendered
    assert "top-secret" not in rendered


def test_file_provider_reads_regular_file_within_root(tmp_path: Path) -> None:
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    (provider_root / "model-a_7.py").write_text("result = 'regular'\n", encoding="utf-8")

    assert _generate(FileProvider(provider_root), "model-a") == "result = 'regular'\n"


def test_file_provider_allows_slash_model_id_within_root(tmp_path: Path) -> None:
    provider_root = tmp_path / "provider"
    nested = provider_root / "org"
    nested.mkdir(parents=True)
    (nested / "model_7.py").write_text("result = 'nested'\n", encoding="utf-8")

    assert _generate(FileProvider(provider_root), "org/model") == "result = 'nested'\n"


def test_file_provider_rejects_symlink_escape_when_supported(tmp_path: Path) -> None:
    provider_root = tmp_path / "provider"
    provider_root.mkdir()
    outside_dir = tmp_path / "private"
    outside_dir.mkdir()
    (outside_dir / "model_7.py").write_text("top-secret symlink code\n", encoding="utf-8")
    link = provider_root / "org"
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(SecAwareError) as exc_info:
        _generate(FileProvider(provider_root), "org/model")

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert str(outside_dir) not in str(exc_info.value.to_dict())
