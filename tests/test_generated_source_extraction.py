from __future__ import annotations

import hashlib

import pytest

from secaware.generation.source_extraction import (
    SOURCE_EXTRACTION_POLICY_SHA256,
    extract_generated_source,
)


def test_plain_source_is_preserved_with_explicit_provenance() -> None:
    raw = "\npackage main\n\nfunc main() {}\n"

    result = extract_generated_source(raw)

    assert result.envelope == "plain_source"
    assert result.source == "package main\n\nfunc main() {}"
    assert result.files == ()
    assert result.policy_sha256 == SOURCE_EXTRACTION_POLICY_SHA256
    assert result.raw_response_sha256 == hashlib.sha256(raw.encode()).hexdigest()


def test_single_fenced_source_removes_only_the_outer_fence() -> None:
    result = extract_generated_source("```java\nclass Main {}\n```")

    assert result.envelope == "single_markdown_fence"
    assert result.fence_label == "java"
    assert result.source == "class Main {}"


@pytest.mark.parametrize("fenced", (False, True))
def test_result_xml_extracts_cdata_and_relative_path(fenced: bool) -> None:
    xml = (
        "<result><code><path>src/Main.java</path>"
        "<content><![CDATA[class Main {\n    static void run() {}\n}]]></content>"
        "</code></result>"
    )
    raw = f"```xml\n{xml}\n```" if fenced else xml

    result = extract_generated_source(raw)

    assert result.envelope == "result_code_xml"
    assert result.source == "class Main {\n    static void run() {}\n}"
    assert len(result.files) == 1
    assert result.files[0].path == "src/Main.java"
    assert result.files[0].content == result.source


def test_multiple_xml_files_have_a_frozen_flattening_order() -> None:
    raw = (
        "<result>"
        "<code><path>a.go</path><content><![CDATA[package main]]></content></code>"
        "<code><path>b.go</path><content><![CDATA[func run() {}]]></content></code>"
        "</result>"
    )

    result = extract_generated_source(raw)

    assert [item.path for item in result.files] == ["a.go", "b.go"]
    assert result.source == "package main\n\nfunc run() {}"


@pytest.mark.parametrize(
    "raw",
    (
        "",
        "prefix\n```python\nprint(1)\n```",
        "```python\nprint(1)\n```\n```python\nprint(2)\n```",
        "<result><code><path>../main.py</path><content>x</content></code></result>",
        "<result><code><path>main.py</path><content>x</content></code>trailing</result>",
        "<!DOCTYPE result><result><code><path>main.py</path><content>x</content></code></result>",
        "<result><code><content>x</content><path>main.py</path></code></result>",
    ),
)
def test_invalid_or_ambiguous_envelopes_fail_closed(raw: str) -> None:
    with pytest.raises(ValueError):
        extract_generated_source(raw)
