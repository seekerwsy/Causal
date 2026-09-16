from pathlib import Path
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    load_catalog,
    query_context,
    query_for_realization,
)


ROOT = Path(__file__).parents[1]


CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v1.json"


PROMPT = "Run the fixed git executable with a user-provided branch name and return its output."


def _fact(local_id, node_type, semantic_id, evidence_text, **attributes):
    return {
        "local_id": local_id,
        "node_type": node_type,
        "semantic_id": semantic_id,
        "evidence_text": evidence_text,
        "occurrence": 1,
        "attributes": attributes,
    }


def _command_graph(*, unresolved=()):
    catalog = load_catalog(CATALOG_PATH)
    facts = [
        _fact(
            "source",
            "source",
            "source.untrusted_command_argument",
            "user-provided branch name",
            caller_controlled=True,
        ),
        _fact("sink", "sink", "sink.process_execution", "Run"),
        _fact(
            "fixed",
            "constraint",
            "constraint.fixed_executable",
            "fixed git executable",
            fixed=True,
        ),
        _fact("operation", "task_operation", "task.operation", "return its output"),
    ]
    return catalog, build_prompt_tsg(
        task_id="task-1",
        prompt=PROMPT,
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=facts,
        relations=[{"edge_type": "flows_to", "source": "source", "target": "sink"}],
        unresolved_semantics=unresolved,
    )


def test_context_query_has_total_four_valued_semantics():
    catalog, graph = _command_graph()
    query = query_for_realization(catalog, "cwe78_fixed_executable_argv")

    present = query_context(graph, query=query, cwe="CWE-78", task_family="command_execution")
    not_applicable = query_context(
        graph, query=query, cwe="CWE-89", task_family="command_execution"
    )
    assert present.state == QueryState.PRESENT
    assert not_applicable.state == QueryState.NOT_APPLICABLE

    _, unresolved = _command_graph(unresolved=("constraint.fixed_executable",))
    result = query_context(
        unresolved, query=query, cwe="CWE-78", task_family="command_execution"
    )
    assert result.state == QueryState.UNRESOLVED

    absent = build_prompt_tsg(
        task_id="task-2",
        prompt="Return a constant.",
        extractor_id="llm-facts-v1",
        catalog=catalog,
        facts=[],
        relations=[],
    )
    result = query_context(
        absent, query=query, cwe="CWE-78", task_family="command_execution"
    )
    assert result.state == QueryState.ABSENT
