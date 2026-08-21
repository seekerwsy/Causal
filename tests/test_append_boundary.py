from __future__ import annotations

import ast

from secaware.intervention.append_boundary import (
    LEGACY_DIRECT_CONCAT_POLICY,
    PYTHON_COMMENT_BOUNDARY_POLICY,
    python_parse_preservation,
    render_append_boundary,
)


def test_python_comment_boundary_protects_eof_triple_quote() -> None:
    source = "def remove_user(username):\n    '''Remove the named user.'''"
    rendered = render_append_boundary(
        source,
        " Use parameterized queries for user-provided values.",
        policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )

    assert rendered.candidate_text == (
        source + "\n\n# Use parameterized queries for user-provided values."
    )
    assert rendered.candidate_text.startswith(source)
    ast.parse(rendered.candidate_text)


def test_python_comment_boundary_protects_ordinary_eof() -> None:
    source = "value = 1"
    rendered = render_append_boundary(
        source,
        " Keep the implementation concise.",
        policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )

    assert rendered.rendered_append == "\n\n# Keep the implementation concise."
    ast.parse(rendered.candidate_text)


def test_python_comment_boundary_reuses_existing_line_ending() -> None:
    source = "value = 1\n"
    rendered = render_append_boundary(
        source,
        " Keep the implementation concise.",
        policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )

    assert rendered.rendered_append == "\n# Keep the implementation concise."
    assert rendered.candidate_text == "value = 1\n\n# Keep the implementation concise."


def test_python_comment_boundary_comments_every_semantic_line() -> None:
    rendered = render_append_boundary(
        "value = 1",
        " First requirement.\nSecond requirement.\n\nFinal note. ",
        policy=PYTHON_COMMENT_BOUNDARY_POLICY,
    )

    assert rendered.rendered_append == (
        "\n\n# First requirement.\n# Second requirement.\n#\n# Final note."
    )
    assert rendered.metadata()["raw_semantic_suffix"] == (
        " First requirement.\nSecond requirement.\n\nFinal note. "
    )


def test_legacy_append_boundary_preserves_exact_direct_concatenation() -> None:
    source = "Write a query function."
    suffix = " Use parameterized queries."
    rendered = render_append_boundary(
        source,
        suffix,
        policy=LEGACY_DIRECT_CONCAT_POLICY,
    )

    assert rendered.rendered_append == suffix
    assert rendered.candidate_text == source + suffix


def test_python_parse_preservation_detects_a_regression() -> None:
    check = python_parse_preservation("value = 1", "value = 1\nnot Python prose")

    assert check.source_parse_ok is True
    assert check.candidate_parse_ok is False
    assert check.passed is False
