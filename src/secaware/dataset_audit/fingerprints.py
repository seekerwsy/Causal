from __future__ import annotations

import hashlib
from pathlib import Path
import unicodedata


NORMALIZATION_VERSION = "prompt-normalization-v1"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8", errors="strict")).hexdigest()


def normalize_prompt(prompt: str) -> str:
    normalized = unicodedata.normalize("NFC", prompt).replace("\r\n", "\n").replace("\r", "\n")
    lines = (line.rstrip() for line in normalized.split("\n"))
    return " ".join(" ".join(lines).split())


def normalized_prompt_sha256(prompt: str) -> str:
    return exact_prompt_sha256(normalize_prompt(prompt))
