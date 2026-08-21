from __future__ import annotations

import pytest

from secaware.exploratory.discovery_mechanism_audit import _mechanism_state, _selected_tasks


@pytest.mark.parametrize(
    ("parse_ok", "facts", "expected"),
    (
        (False, [], "unavailable"),
        (True, [], "no_relevant_sink"),
        (True, [{"cwe": "CWE-78", "state": "safe"}], "proved_safe"),
        (True, [{"cwe": "CWE-78", "state": "unsafe"}], "proved_unsafe"),
        (True, [{"cwe": "CWE-78", "state": "unresolved"}], "unresolved"),
        (
            True,
            [
                {"cwe": "CWE-78", "state": "safe"},
                {"cwe": "CWE-78", "state": "unsafe"},
            ],
            "proved_unsafe",
        ),
        (
            True,
            [{"cwe": "CWE-89", "state": "unsafe"}],
            "no_relevant_sink",
        ),
    ),
)
def test_mechanism_state_projection(
    parse_ok: bool,
    facts: list[dict[str, object]],
    expected: str,
) -> None:
    assert _mechanism_state(cwe="CWE-78", parse_ok=parse_ok, sink_facts=facts) == expected


def test_parse_failure_cannot_carry_sink_facts() -> None:
    with pytest.raises(ValueError, match="parse failure"):
        _mechanism_state(
            cwe="CWE-78",
            parse_ok=False,
            sink_facts=[{"cwe": "CWE-78", "state": "unsafe"}],
        )


def test_pilot_selects_one_lexicographic_task_per_cwe() -> None:
    task_cwe = {
        "task-z": "CWE-78",
        "task-a": "CWE-78",
        "task-b": "CWE-89",
        "task-c": "CWE-502",
        "task-d": "CWE-328",
        "task-e": "CWE-338",
    }

    assert _selected_tasks(task_cwe, policy="one_lexicographic_task_per_cwe") == (
        "task-a",
        "task-b",
        "task-c",
        "task-d",
        "task-e",
    )
