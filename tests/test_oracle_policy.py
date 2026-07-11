import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
import yaml

import secaware.oracle.policy as policy_module
from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.policy import (
    BANDIT_VERSION,
    LoadedOraclePolicy,
    MAX_POLICY_FILE_BYTES,
    MAX_POLICY_LOCK_BYTES,
    ORACLE_POLICY_SCHEMA_VERSION,
    OraclePolicyLock,
    SEMGREP_VERSION,
    load_policy_bundle,
)
from secaware.pipeline.artifact import canonical_sha256


_SEMGREP_BYTES = b"rules: []\n"
_BANDIT_BYTES = b"tests: [B101]\n"
_CHECKED_IN_POLICY_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "policies" / "oracle" / "python"
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _lock_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": ORACLE_POLICY_SCHEMA_VERSION,
        "policy_name": "secaware-python-v1",
        "language": "python",
        "semgrep_version": SEMGREP_VERSION,
        "bandit_version": BANDIT_VERSION,
        "semgrep_rules": "semgrep.yml",
        "semgrep_sha256": _sha256(_SEMGREP_BYTES),
        "bandit_config": "bandit.yml",
        "bandit_sha256": _sha256(_BANDIT_BYTES),
    }
    payload.update(overrides)
    return payload


def _write_locked_policy(
    directory: Path,
    *,
    lock_overrides: dict[str, object] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath("semgrep.yml").write_bytes(_SEMGREP_BYTES)
    directory.joinpath("bandit.yml").write_bytes(_BANDIT_BYTES)
    payload = _lock_payload(**(lock_overrides or {}))
    lock_path = directory / "policy.lock.json"
    lock_path.write_text(json.dumps(payload), encoding="utf-8")
    return lock_path


def _write_lock_document(directory: Path, payload: dict[str, object]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / "policy.lock.json"
    lock_path.write_text(json.dumps(payload), encoding="utf-8")
    return lock_path


def _symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links unavailable: {type(error).__name__}")


def _validation_surfaces(error: ValidationError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.errors(), default=str, sort_keys=True),
        error.json(),
    )


def _error_surfaces(error: SecAwareError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), default=str, sort_keys=True),
    )


def _secaware_traceback_frames(
    error: BaseException,
) -> list[tuple[str, dict[str, object]]]:
    frames: list[tuple[str, dict[str, object]]] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            frames.append((current.tb_frame.f_code.co_name, dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return frames


def _secaware_traceback_locals(error: BaseException) -> str:
    return "\n".join(repr(locals_) for _, locals_ in _secaware_traceback_frames(error))


def _assert_safe_validation_error(error: ValidationError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    structured = error.errors()
    assert len(structured) == 1
    assert structured[0]["loc"] == ()
    assert structured[0].get("input") is None
    assert "ctx" not in structured[0]
    retained = _secaware_traceback_locals(error)
    for value in hidden:
        assert all(value not in surface for surface in _validation_surfaces(error))
        assert value not in retained


def _assert_safe_policy_error(error: SecAwareError, *hidden: str) -> None:
    assert error.code is ErrorCode.POLICY_MISMATCH
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.details == {}
    retained = _secaware_traceback_locals(error)
    for value in hidden:
        if not value or value.isspace():
            continue
        assert all(value not in surface for surface in _error_surfaces(error))
        assert value not in retained


def test_policy_bundle_requires_exact_hashes_versions_and_byte_snapshots(
    tmp_path: Path,
) -> None:
    lock_path = _write_locked_policy(tmp_path)

    bundle = load_policy_bundle(lock_path)

    assert bundle.schema_version == ORACLE_POLICY_SCHEMA_VERSION
    assert bundle.semgrep_version == SEMGREP_VERSION
    assert bundle.bandit_version == BANDIT_VERSION
    assert bundle.semgrep_rules_bytes == _SEMGREP_BYTES
    assert bundle.bandit_config_bytes == _BANDIT_BYTES
    assert bundle.semgrep_sha256 == _sha256(_SEMGREP_BYTES)
    assert bundle.bandit_sha256 == _sha256(_BANDIT_BYTES)
    assert bundle.combined_sha256 == canonical_sha256(bundle.lock_payload)


def test_changed_policy_is_a_hard_failure(tmp_path: Path) -> None:
    lock_path = _write_locked_policy(tmp_path)
    lock_path.parent.joinpath("semgrep.yml").write_bytes(b"rules: [tampered]\n")

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    assert exc_info.value.code is ErrorCode.POLICY_MISMATCH


def test_oracle_policy_lock_is_strict_frozen_and_repr_safe() -> None:
    payload = _lock_payload(
        policy_name="repr-private-policy",
        semgrep_rules="repr/private-semgrep.yml",
        semgrep_sha256="a" * 64,
        bandit_config="repr/private-bandit.yml",
        bandit_sha256="b" * 64,
    )

    lock = OraclePolicyLock.model_validate(payload)

    assert lock.schema_version == "1.0"
    assert lock.language == "python"
    assert repr(lock) == "OraclePolicyLock()"
    assert all(
        hidden not in repr(lock)
        for hidden in (
            "repr-private-policy",
            "private-semgrep",
            "private-bandit",
            "a" * 64,
            "b" * 64,
        )
    )
    with pytest.raises(ValidationError):
        lock.policy_name = "changed"


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("policy_name", " "),
        ("policy_name", " trailing "),
        ("policy_name", "embedded\x00control"),
        ("language", "javascript"),
        ("semgrep_version", "1.167.0"),
        ("bandit_version", "1.9.3"),
        ("semgrep_sha256", "A" * 64),
        ("semgrep_sha256", "0" * 63),
        ("bandit_sha256", "not-a-digest"),
    ],
)
def test_oracle_policy_lock_rejects_noncanonical_fields(
    field: str,
    invalid: object,
) -> None:
    payload = _lock_payload()
    payload[field] = invalid

    with pytest.raises(ValidationError):
        OraclePolicyLock.model_validate(payload)


@pytest.mark.parametrize("surface", ["constructor", "python", "json", "strings"])
def test_lock_validation_four_surfaces_hide_input_and_frame_locals(surface: str) -> None:
    sentinel = f"lock-{surface}-private-sentinel"
    payload = _lock_payload(private_credential=sentinel)
    operations: dict[str, Callable[[], object]] = {
        "constructor": lambda: OraclePolicyLock(**payload),
        "python": lambda: OraclePolicyLock.model_validate(payload),
        "json": lambda: OraclePolicyLock.model_validate_json(json.dumps(payload)),
        "strings": lambda: OraclePolicyLock.model_validate_strings(
            {"private_credential": sentinel}
        ),
    }

    with pytest.raises(ValidationError) as exc_info:
        operations[surface]()

    _assert_safe_validation_error(
        exc_info.value,
        sentinel,
        "private_credential",
        "semgrep.yml",
        "bandit.yml",
    )


@pytest.mark.parametrize("forgery", ["copy", "construct", "extra"])
def test_lock_revalidation_rejects_model_copy_and_construct_forgery(
    forgery: str,
) -> None:
    valid = OraclePolicyLock.model_validate(_lock_payload())
    if forgery == "copy":
        hidden = ("forged-version",)
        forged: object = valid.model_copy(update={"semgrep_version": hidden[0]})
    elif forgery == "construct":
        hidden = ("semgrep.yml", "bandit.yml")
        payload = valid.model_dump(mode="python")
        payload.pop("bandit_sha256")
        forged = OraclePolicyLock.model_construct(**payload)
    else:
        hidden = ("forged-extra-secret", "private_credential")
        forged = valid.model_copy(update={"private_credential": hidden[0]})

    with pytest.raises(ValidationError) as exc_info:
        OraclePolicyLock.model_validate(forged)

    _assert_safe_validation_error(exc_info.value, *hidden)


def test_loaded_policy_is_frozen_repr_safe_and_returns_isolated_lock_payload(
    tmp_path: Path,
) -> None:
    loaded = load_policy_bundle(_write_locked_policy(tmp_path))

    rendered = repr(loaded)
    assert rendered == "LoadedOraclePolicy()"
    assert all(
        hidden not in rendered
        for hidden in (
            str(tmp_path),
            loaded.semgrep_sha256,
            loaded.bandit_sha256,
            repr(_SEMGREP_BYTES),
            repr(_BANDIT_BYTES),
        )
    )
    with pytest.raises(ValidationError):
        loaded.semgrep_rules_bytes = b"changed"
    payload = loaded.lock_payload
    payload["semgrep_rules"] = "changed.yml"
    assert loaded.lock_payload["semgrep_rules"] == "semgrep.yml"


@pytest.mark.parametrize("forgery", ["bytes_copy", "construct", "extra"])
def test_loaded_policy_revalidation_rejects_model_copy_and_construct_forgery(
    tmp_path: Path,
    forgery: str,
) -> None:
    valid = load_policy_bundle(_write_locked_policy(tmp_path))
    if forgery == "bytes_copy":
        hidden = ("forged-policy-bytes",)
        forged: object = valid.model_copy(
            update={"semgrep_rules_bytes": hidden[0].encode("utf-8")}
        )
    elif forgery == "construct":
        hidden = (str(tmp_path), "semgrep.yml", "bandit.yml")
        payload = valid.model_dump(mode="python")
        payload.pop("combined_sha256")
        forged = LoadedOraclePolicy.model_construct(**payload)
    else:
        hidden = ("forged-extra-secret", "private_path")
        forged = valid.model_copy(update={"private_path": hidden[0]})

    with pytest.raises(ValidationError) as exc_info:
        LoadedOraclePolicy.model_validate(forged)

    _assert_safe_validation_error(exc_info.value, *hidden)


def test_lock_accepts_nested_relative_posix_policy_paths() -> None:
    lock = OraclePolicyLock.model_validate(
        _lock_payload(
            semgrep_rules="rules/python/semgrep.yml",
            bandit_config="config/bandit.yml",
        )
    )

    assert lock.semgrep_rules == "rules/python/semgrep.yml"
    assert lock.bandit_config == "config/bandit.yml"


@pytest.mark.parametrize(
    "invalid_path",
    [
        "",
        ".",
        "..",
        "./semgrep.yml",
        "rules/./semgrep.yml",
        "rules/../semgrep.yml",
        "../semgrep.yml",
        "/absolute/semgrep.yml",
        "//server/share/semgrep.yml",
        "\\\\server\\share\\semgrep.yml",
        "rules\\semgrep.yml",
        "C:/policies/semgrep.yml",
        "C:semgrep.yml",
        "policy.yml/",
        "policy.yml//nested",
        "policy.yml\x00suffix",
    ],
)
@pytest.mark.parametrize("field", ["semgrep_rules", "bandit_config"])
def test_lock_rejects_noncanonical_or_escaping_policy_paths(
    field: str,
    invalid_path: str,
) -> None:
    payload = _lock_payload()
    payload[field] = invalid_path

    with pytest.raises(ValidationError):
        OraclePolicyLock.model_validate(payload)


def test_loader_resolves_valid_nested_policy_paths(tmp_path: Path) -> None:
    semgrep_path = tmp_path / "rules" / "python" / "semgrep.yml"
    bandit_path = tmp_path / "config" / "bandit.yml"
    semgrep_path.parent.mkdir(parents=True)
    bandit_path.parent.mkdir(parents=True)
    semgrep_path.write_bytes(_SEMGREP_BYTES)
    bandit_path.write_bytes(_BANDIT_BYTES)
    lock_path = _write_lock_document(
        tmp_path,
        _lock_payload(
            semgrep_rules="rules/python/semgrep.yml",
            bandit_config="config/bandit.yml",
        ),
    )

    loaded = load_policy_bundle(lock_path)

    assert loaded.semgrep_rules_path == semgrep_path.resolve()
    assert loaded.bandit_config_path == bandit_path.resolve()


@pytest.mark.parametrize(
    "duplicate_path",
    ["semgrep.yml", "policy.lock.json"],
)
def test_loader_rejects_duplicate_or_lock_policy_file(
    tmp_path: Path,
    duplicate_path: str,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    payload = _lock_payload(bandit_config=duplicate_path)
    if duplicate_path == "semgrep.yml":
        payload["bandit_sha256"] = payload["semgrep_sha256"]
    else:
        payload["bandit_sha256"] = _sha256(lock_path.read_bytes())
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(lock_path), duplicate_path)


@pytest.mark.parametrize("policy_name", ["semgrep.yml", "bandit.yml"])
def test_loader_rejects_policy_directory(tmp_path: Path, policy_name: str) -> None:
    lock_path = _write_locked_policy(tmp_path)
    target = tmp_path / policy_name
    target.unlink()
    target.mkdir()

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(target))


@pytest.mark.parametrize("policy_name", ["semgrep.yml", "bandit.yml"])
def test_loader_rejects_policy_symlink(tmp_path: Path, policy_name: str) -> None:
    lock_path = _write_locked_policy(tmp_path)
    target = tmp_path / policy_name
    outside = tmp_path.parent / f"outside-{tmp_path.name}-{policy_name}"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    _symlink_or_skip(target, outside)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(target), str(outside))


def test_loader_rejects_symlinked_parent_even_when_target_stays_inside(
    tmp_path: Path,
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    semgrep_path = real_directory / "semgrep.yml"
    semgrep_path.write_bytes(_SEMGREP_BYTES)
    alias = tmp_path / "alias"
    _symlink_or_skip(alias, real_directory, target_is_directory=True)
    (tmp_path / "bandit.yml").write_bytes(_BANDIT_BYTES)
    lock_path = _write_lock_document(
        tmp_path,
        _lock_payload(semgrep_rules="alias/semgrep.yml"),
    )

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(alias), str(real_directory))


def test_loader_rejects_symlinked_lock(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_lock = _write_locked_policy(real_directory)
    lock_alias = tmp_path / "private-lock-alias.json"
    _symlink_or_skip(lock_alias, real_lock)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_alias)

    _assert_safe_policy_error(exc_info.value, str(lock_alias), str(real_lock))


def test_loader_rejects_nonregular_lock_path(tmp_path: Path) -> None:
    lock_directory = tmp_path / "private-lock-directory"
    lock_directory.mkdir()

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_directory)

    _assert_safe_policy_error(exc_info.value, str(lock_directory))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows device path regression")
def test_loader_rejects_windows_device_policy(tmp_path: Path) -> None:
    (tmp_path / "bandit.yml").write_bytes(_BANDIT_BYTES)
    lock_path = _write_lock_document(
        tmp_path,
        _lock_payload(semgrep_rules="NUL", semgrep_sha256=_sha256(b"")),
    )

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(lock_path), "NUL")


@pytest.mark.parametrize(
    ("policy_name", "replacement"),
    [
        ("semgrep.yml", b"private-tampered-semgrep-policy"),
        ("bandit.yml", b"private-tampered-bandit-policy"),
    ],
)
def test_loader_rejects_each_tampered_policy_without_leaking_bytes_or_hashes(
    tmp_path: Path,
    policy_name: str,
    replacement: bytes,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    expected_hash = _sha256(
        _SEMGREP_BYTES if policy_name == "semgrep.yml" else _BANDIT_BYTES
    )
    actual_hash = _sha256(replacement)
    target = tmp_path / policy_name
    target.write_bytes(replacement)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(
        exc_info.value,
        replacement.decode("utf-8"),
        expected_hash,
        actual_hash,
        str(target),
    )


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("schema_version", "9.9-private-version"),
        ("semgrep_version", "9.9-private-semgrep"),
        ("bandit_version", "9.9-private-bandit"),
        ("semgrep_sha256", "a" * 63 + "private"),
        ("bandit_sha256", "B" * 64),
    ],
)
def test_loader_rejects_tampered_lock_versions_and_hashes(
    tmp_path: Path,
    field: str,
    tampered: str,
) -> None:
    lock_path = _write_locked_policy(tmp_path, lock_overrides={field: tampered})

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, tampered, field, str(lock_path))


@pytest.mark.parametrize(
    "raw_lock",
    [
        b"",
        b"not-private-json",
        b"[]",
        b"null",
        b'{"private":"unterminated}',
        b'{"private":NaN}',
        b'{"private":Infinity}',
        b'{} private-trailing-json',
        b'{"private":"\xff"}',
        b"\xef\xbb\xbf{}",
    ],
)
def test_loader_rejects_empty_invalid_utf8_or_noncanonical_json(
    tmp_path: Path,
    raw_lock: bytes,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    lock_path.write_bytes(raw_lock)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(
        exc_info.value,
        raw_lock.decode("utf-8", errors="ignore"),
        str(lock_path),
    )


def test_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    payload = _lock_payload()
    serialized = json.dumps(payload)
    duplicate = (
        serialized[:-1]
        + ', "semgrep_rules": "semgrep.yml"}'
    )
    lock_path = _write_locked_policy(tmp_path)
    lock_path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(
        exc_info.value,
        str(lock_path),
    )


def test_loader_rejects_extra_lock_field(tmp_path: Path) -> None:
    sentinel = "private-extra-lock-field"
    lock_path = _write_locked_policy(
        tmp_path,
        lock_overrides={"private_credential": sentinel},
    )

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, sentinel, "private_credential", str(lock_path))


def test_lock_size_limit_accepts_boundary_and_rejects_one_more_byte(
    tmp_path: Path,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    raw = json.dumps(_lock_payload(), separators=(",", ":")).encode("utf-8")
    assert len(raw) < MAX_POLICY_LOCK_BYTES
    boundary = raw + b" " * (MAX_POLICY_LOCK_BYTES - len(raw))
    lock_path.write_bytes(boundary)

    loaded = load_policy_bundle(lock_path)

    assert loaded.policy_name == "secaware-python-v1"
    lock_path.write_bytes(boundary + b" ")
    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)
    _assert_safe_policy_error(exc_info.value, str(lock_path))


def test_policy_size_limit_accepts_boundary_and_rejects_one_more_byte(
    tmp_path: Path,
) -> None:
    boundary = b"x" * MAX_POLICY_FILE_BYTES
    lock_path = _write_locked_policy(
        tmp_path,
        lock_overrides={"semgrep_sha256": _sha256(boundary)},
    )
    semgrep_path = tmp_path / "semgrep.yml"
    semgrep_path.write_bytes(boundary)

    loaded = load_policy_bundle(lock_path)

    assert loaded.semgrep_rules_bytes is not boundary
    assert loaded.semgrep_rules_bytes == boundary
    oversized = boundary + b"x"
    semgrep_path.write_bytes(oversized)
    lock_path.write_text(
        json.dumps(_lock_payload(semgrep_sha256=_sha256(oversized))),
        encoding="utf-8",
    )
    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)
    _assert_safe_policy_error(exc_info.value, str(semgrep_path), _sha256(oversized))


def test_combined_digest_is_stable_across_json_key_order_and_formatting(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_lock = _write_locked_policy(first)
    second.mkdir()
    second.joinpath("semgrep.yml").write_bytes(_SEMGREP_BYTES)
    second.joinpath("bandit.yml").write_bytes(_BANDIT_BYTES)
    reverse_order = dict(reversed(tuple(_lock_payload().items())))
    second_lock = second / "policy.lock.json"
    second_lock.write_text(
        json.dumps(reverse_order, ensure_ascii=False, indent=4),
        encoding="utf-8",
    )

    first_loaded = load_policy_bundle(first_lock)
    second_loaded = load_policy_bundle(second_lock)

    assert first_loaded.combined_sha256 == second_loaded.combined_sha256
    assert first_loaded.combined_sha256 == canonical_sha256(
        OraclePolicyLock.model_validate(_lock_payload()).model_dump(mode="json")
    )


def test_source_mutation_after_load_does_not_change_authenticated_snapshots(
    tmp_path: Path,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    loaded = load_policy_bundle(lock_path)
    original = (
        loaded.semgrep_rules_bytes,
        loaded.bandit_config_bytes,
        loaded.semgrep_sha256,
        loaded.bandit_sha256,
        loaded.combined_sha256,
    )

    (tmp_path / "semgrep.yml").write_bytes(b"post-load-semgrep-mutation")
    (tmp_path / "bandit.yml").write_bytes(b"post-load-bandit-mutation")
    lock_path.write_text("post-load-lock-mutation", encoding="utf-8")

    assert (
        loaded.semgrep_rules_bytes,
        loaded.bandit_config_bytes,
        loaded.semgrep_sha256,
        loaded.bandit_sha256,
        loaded.combined_sha256,
    ) == original


def test_loader_wraps_raw_filesystem_exception_without_context_or_frame_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    sentinel = "private-hostile-filesystem-exception"

    def hostile_lstat(self: Path) -> os.stat_result:
        del self
        raise RuntimeError(sentinel)

    monkeypatch.setattr(Path, "lstat", hostile_lstat)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, sentinel, "RuntimeError", str(lock_path))


def test_loader_clears_hostile_path_object_from_error_frames() -> None:
    sentinel = "private-hostile-path-object"

    class HostilePath:
        def __fspath__(self) -> str:
            raise RuntimeError(sentinel)

        def __repr__(self) -> str:
            return sentinel

    candidate = HostilePath()
    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(candidate)  # type: ignore[arg-type]

    _assert_safe_policy_error(exc_info.value, sentinel, "RuntimeError", "HostilePath")
    for _, frame_locals in _secaware_traceback_frames(exc_info.value):
        assert all(id(value) != id(candidate) for value in frame_locals.values())


@pytest.mark.parametrize("policy_name", ["semgrep.yml", "bandit.yml"])
def test_loader_rejects_policy_hardlink_to_file_outside_bundle(
    tmp_path: Path,
    policy_name: str,
) -> None:
    bundle_directory = tmp_path / "bundle"
    lock_path = _write_locked_policy(bundle_directory)
    target = bundle_directory / policy_name
    outside = tmp_path / f"private-outside-{policy_name}"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    try:
        os.link(outside, target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hard links unavailable: {type(error).__name__}")

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(target), str(outside))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO regression")
def test_loader_rejects_posix_fifo_without_opening_it(tmp_path: Path) -> None:
    lock_path = _write_locked_policy(tmp_path)
    target = tmp_path / "semgrep.yml"
    target.unlink()
    os.mkfifo(target)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(exc_info.value, str(target))


def test_snapshot_open_uses_nonblocking_flag_when_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    synthetic_nonblocking = 1 << 29
    observed_flags: list[int] = []

    def recording_open(path: os.PathLike[str] | str, flags: int) -> int:
        observed_flags.append(flags)
        raise OSError("synthetic open stop")

    monkeypatch.setattr(policy_module.os, "O_NONBLOCK", synthetic_nonblocking, raising=False)
    monkeypatch.setattr(policy_module.os, "open", recording_open)

    with pytest.raises(SecAwareError):
        load_policy_bundle(lock_path)

    assert len(observed_flags) == 1
    assert observed_flags[0] & synthetic_nonblocking


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="POSIX regular-to-FIFO race regression",
)
def test_loader_rejects_regular_to_fifo_race_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    semgrep_path = (tmp_path / "semgrep.yml").resolve()
    original_open = policy_module.os.open
    observed_flags: list[int] = []
    swapped = False

    def fifo_swapping_open(path: os.PathLike[str] | str, flags: int) -> int:
        nonlocal swapped
        candidate = Path(path)
        if not swapped and candidate == semgrep_path:
            swapped = True
            candidate.unlink()
            os.mkfifo(candidate)
            observed_flags.append(flags)
            if not flags & os.O_NONBLOCK:
                raise RuntimeError("blocking FIFO open prevented by regression test")
        return original_open(path, flags)

    monkeypatch.setattr(policy_module.os, "open", fifo_swapping_open)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    assert swapped is True
    assert len(observed_flags) == 1
    assert observed_flags[0] & os.O_NONBLOCK
    _assert_safe_policy_error(exc_info.value, str(semgrep_path), "FIFO")


def test_loader_detects_inode_swap_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    semgrep_path = (tmp_path / "semgrep.yml").resolve()
    replacement_path = tmp_path / "private-swap-replacement.yml"
    replacement_path.write_bytes(_SEMGREP_BYTES)
    original_open = policy_module.os.open
    swapped = False

    def swapping_open(path: os.PathLike[str] | str, flags: int) -> int:
        nonlocal swapped
        candidate = Path(path)
        if not swapped and candidate == semgrep_path:
            swapped = True
            os.replace(replacement_path, semgrep_path)
        return original_open(path, flags)

    monkeypatch.setattr(policy_module.os, "open", swapping_open)

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    assert swapped is True
    _assert_safe_policy_error(
        exc_info.value,
        str(semgrep_path),
        str(replacement_path),
    )


def test_loader_rejects_parent_component_race_that_resolves_outside_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle_directory = tmp_path / "bundle"
    lock_path = _write_locked_policy(bundle_directory)
    outside_directory = tmp_path / "private-race-outside"
    outside_directory.mkdir()
    outside_policy = outside_directory / "semgrep.yml"
    outside_policy.write_bytes(_SEMGREP_BYTES)
    original_components = policy_module._require_plain_components

    def racing_components(root: Path, relative_path: str) -> Path:
        original_components(root, relative_path)
        if relative_path == "semgrep.yml":
            return outside_policy
        return root / relative_path

    monkeypatch.setattr(
        policy_module,
        "_require_plain_components",
        racing_components,
    )

    with pytest.raises(SecAwareError) as exc_info:
        load_policy_bundle(lock_path)

    _assert_safe_policy_error(
        exc_info.value,
        str(outside_directory),
        str(outside_policy),
    )


def test_loader_reads_policy_with_a_bounded_single_snapshot_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _write_locked_policy(tmp_path)
    original_fdopen = policy_module.os.fdopen
    read_sizes: list[int] = []

    class RecordingHandle:
        def __init__(self, handle: object) -> None:
            self._handle = handle

        def __enter__(self) -> "RecordingHandle":
            self._handle.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, *args: object) -> object:
            return self._handle.__exit__(*args)  # type: ignore[attr-defined]

        def fileno(self) -> int:
            return self._handle.fileno()  # type: ignore[attr-defined,no-any-return]

        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return self._handle.read(size)  # type: ignore[attr-defined,no-any-return]

    def recording_fdopen(*args: object, **kwargs: object) -> RecordingHandle:
        return RecordingHandle(original_fdopen(*args, **kwargs))

    monkeypatch.setattr(policy_module.os, "fdopen", recording_fdopen)

    load_policy_bundle(lock_path)

    assert read_sizes == [
        MAX_POLICY_LOCK_BYTES + 1,
        MAX_POLICY_FILE_BYTES + 1,
        MAX_POLICY_FILE_BYTES + 1,
    ]


def test_open_identity_tolerates_windows_creation_time_settling() -> None:
    values = {
        "st_dev": 11,
        "st_ino": 22,
        "st_mode": 0o100644,
        "st_nlink": 1,
        "st_size": 17,
        "st_mtime_ns": 33,
        "st_ctime_ns": 44,
    }
    before = SimpleNamespace(**values)
    opened = SimpleNamespace(**{**values, "st_ctime_ns": 45})

    assert policy_module._same_open_file_identity(before, opened)


def test_checked_in_policy_bundle_authenticates_exact_files_and_versions() -> None:
    lock_path = _CHECKED_IN_POLICY_DIRECTORY / "policy.lock.json"

    loaded = load_policy_bundle(lock_path)

    assert loaded.policy_name == "secaware-python-v1"
    assert loaded.language == "python"
    assert loaded.semgrep_version == SEMGREP_VERSION
    assert loaded.bandit_version == BANDIT_VERSION
    assert loaded.semgrep_rules_path == (
        _CHECKED_IN_POLICY_DIRECTORY / "semgrep.yml"
    ).resolve()
    assert loaded.bandit_config_path == (
        _CHECKED_IN_POLICY_DIRECTORY / "bandit.yml"
    ).resolve()
    assert loaded.semgrep_sha256 == _sha256(loaded.semgrep_rules_bytes)
    assert loaded.bandit_sha256 == _sha256(loaded.bandit_config_bytes)
    assert loaded.combined_sha256 == canonical_sha256(loaded.lock_payload)


def test_checked_in_semgrep_policy_is_finite_local_and_reviewed() -> None:
    policy_path = _CHECKED_IN_POLICY_DIRECTORY / "semgrep.yml"
    raw = policy_path.read_bytes()
    document = yaml.safe_load(raw)

    assert set(document) == {"rules"}
    rules = document["rules"]
    assert type(rules) is list
    assert len(rules) == 4
    expected = {
        "secaware.python.command-injection": ("CWE-78", "ERROR"),
        "secaware.python.sql-injection": ("CWE-89", "ERROR"),
        "secaware.python.unsafe-deserialization": ("CWE-502", "ERROR"),
        "secaware.python.path-traversal": ("CWE-22", "WARNING"),
    }
    assert {rule["id"] for rule in rules} == set(expected)
    for rule in rules:
        assert set(rule) == {
            "id",
            "message",
            "languages",
            "severity",
            "metadata",
            "mode",
            "pattern-sources",
            "pattern-sinks",
        }
        assert rule["languages"] == ["python"]
        assert rule["mode"] == "taint"
        assert rule["metadata"] == {"cwe": expected[rule["id"]][0]}
        assert rule["severity"] == expected[rule["id"]][1]
        assert type(rule["pattern-sources"]) is list
        assert rule["pattern-sources"]
        assert type(rule["pattern-sinks"]) is list
        assert rule["pattern-sinks"]
    lowered = raw.decode("utf-8").casefold()
    for forbidden in ("http://", "https://", "registry", "p/", "r/", "auto"):
        assert forbidden not in lowered


def test_checked_in_bandit_config_enables_bandit_native_tests_without_skips() -> None:
    config_path = _CHECKED_IN_POLICY_DIRECTORY / "bandit.yml"
    document = yaml.safe_load(config_path.read_bytes())

    assert document == {"exclude_dirs": []}
    assert "tests" not in document
    assert "skips" not in document


def test_exact_semgrep_policy_distinguishes_safe_and_unsafe_yaml_loaders(
    tmp_path: Path,
) -> None:
    configured_executable = os.environ.get("SECAWARE_TEST_SEMGREP")
    if configured_executable is None:
        pytest.skip("exact Semgrep policy integration is not enabled")
    executable = shutil.which(configured_executable)
    if executable is None:
        pytest.fail("configured Semgrep executable is unavailable")

    version = subprocess.run(
        [executable, "--version"],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert version.returncode == 0
    assert version.stdout.strip() == SEMGREP_VERSION

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    samples = {
        "safe_loader.py": "yaml.load(payload, Loader=yaml.SafeLoader)",
        "safe_c_loader.py": "yaml.load(payload, Loader=yaml.CSafeLoader)",
        "safe_base_loader.py": "yaml.load(payload, Loader=yaml.BaseLoader)",
        "safe_load.py": "yaml.safe_load(payload)",
        "unsafe_default.py": "yaml.load(payload)",
        "unsafe_loader.py": "yaml.load(payload, Loader=yaml.Loader)",
        "unsafe_c_loader.py": "yaml.load(payload, Loader=yaml.CLoader)",
        "unsafe_full_loader.py": "yaml.load(payload, Loader=yaml.FullLoader)",
        "unsafe_c_full_loader.py": "yaml.load(payload, Loader=yaml.CFullLoader)",
        "unsafe_unsafe_loader.py": "yaml.load(payload, Loader=yaml.UnsafeLoader)",
        "unsafe_c_unsafe_loader.py": "yaml.load(payload, Loader=yaml.CUnsafeLoader)",
    }
    for filename, sink in samples.items():
        corpus.joinpath(filename).write_text(
            "import yaml\n\n"
            "def parse_untrusted_yaml():\n"
            "    payload = input()\n"
            f"    return {sink}\n",
            encoding="utf-8",
            newline="\n",
        )

    completed = subprocess.run(
        [
            executable,
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--jobs=1",
            "--config",
            str(_CHECKED_IN_POLICY_DIRECTORY / "semgrep.yml"),
            str(corpus),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["errors"] == []
    unsafe_deserialization = {
        Path(result["path"]).name
        for result in report["results"]
        if result["check_id"].endswith("secaware.python.unsafe-deserialization")
    }
    assert unsafe_deserialization == {
        "unsafe_default.py",
        "unsafe_loader.py",
        "unsafe_c_loader.py",
        "unsafe_full_loader.py",
        "unsafe_c_full_loader.py",
        "unsafe_unsafe_loader.py",
        "unsafe_c_unsafe_loader.py",
    }
