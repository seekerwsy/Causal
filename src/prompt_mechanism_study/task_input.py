"""One baseline input for representation, intervention and code generation.

The evidence text is a readable view of the actual system message and user
request. Its headings are provenance delimiters, not extra generation instructions.
Raw source text is retained separately; no frozen source or graph is rewritten.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from prompt_mechanism_study.records import content_hash


DEFAULT_GENERATION_SYSTEM_PROMPT = (
    "Implement the supplied original task and its implementation notes. "
    "Preserve required interfaces and non-target behavior. "
    "Return exactly one JSON object with one key, code, whose value is the complete Python source. "
    "No Markdown fences or other keys."
)


def input_evidence_text(generation_input: Mapping[str, Any]) -> str:
    """Keep message roles and literal text available to the existing span compiler."""
    request = generation_input["request"]
    return ("System message:\n" + generation_input["system_prompt"]
            + "\n\nUser message:\nLanguage: " + request["language"]
            + "\n\nTask:\n" + request["task"])


def prepare_task_input(
    task: Mapping[str, Any], *, generation_system_prompt: str | None = None,
) -> dict[str, Any]:
    """Fill the declared language once, before annotation or arm construction.

    Revalidating a prepared record is idempotent. Its exact system message must
    agree with the generation plan; changes require a new graph and bindings.
    No outcome, routing label, arm, seed or provider setting enters this input.
    """
    language = task.get("language")
    if not isinstance(language, str) or not language or language != language.strip():
        raise ValueError("task input requires an explicit language")
    existing = task.get("generation_input")
    source = task.get("source_prompt") if existing is not None else task.get("prompt")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("task input requires the original source prompt")
    if existing is not None and not isinstance(existing, Mapping):
        raise ValueError("invalid prepared generation input")
    system = generation_system_prompt
    if system is None:
        system = (existing["system_prompt"] if existing is not None
                  else task.get("generation_system_prompt"))
    if system is None:
        if language != "python":
            raise ValueError("non-Python task input requires an explicit generation system prompt")
        system = DEFAULT_GENERATION_SYSTEM_PROMPT
    if not isinstance(system, str) or not system.strip():
        raise ValueError("task input requires the exact generation system prompt")
    if task.get("generation_system_prompt", system) != system:
        raise ValueError("declared generation system prompt differs from the prepared input")
    normalized = source.replace("<language>", language)
    generation_input = {"system_prompt": system,
                        "request": {"language": language, "task": normalized}}
    evidence = input_evidence_text(generation_input)
    expected = {"source_prompt": source, "source_prompt_sha256": content_hash(source),
                "generation_input": generation_input, "prompt": evidence,
                "prompt_sha256": content_hash(evidence)}
    if existing is not None:
        if any(task.get(key) != value for key, value in expected.items()):
            raise ValueError("prepared task input changed; re-extract the graph before generation")
    elif task.get("prompt_sha256", content_hash(source)) != content_hash(source):
        raise ValueError("original source prompt identity changed")
    return {**task, **expected}


def generation_template_facts(task: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Record the exact known generation template without reinterpreting task text.

    These facts describe code generation, not operations performed by the code.
    A custom system message remains a source-annotation problem, even when it
    resembles the default template. All quotations occur in the system message
    before any repeated wording in the user's task.
    """
    prepared = prepare_task_input(task)
    context = prepared["generation_input"]
    if (context["system_prompt"] != DEFAULT_GENERATION_SYSTEM_PROMPT
            or context["request"]["language"] != "python"):
        return {"concepts": [], "nodes": [], "edges": []}
    facts = (
        ("template.implementation", "code.implementation", "task_operation",
         "Implement the supplied task as source code.",
         "Implement the supplied original task and its implementation notes."),
        ("template.interface", "interface.preserve", "task_requirement",
         "Preserve the interfaces required by the source task.",
         "Preserve required interfaces and non-target behavior."),
        ("template.behavior", "behavior.preserve", "task_requirement",
         "Preserve the non-target behavior required by the source task.",
         "Preserve required interfaces and non-target behavior."),
        ("template.json", "output.json_code", "presentation_control",
         "Return one JSON object containing only the code key.",
         "Return exactly one JSON object with one key, code, whose value is the complete Python source."),
        ("template.python", "output.python", "constraint",
         "The requested source language is Python.", "complete Python source"),
    )
    return {
        "concepts": [{"concept_id": concept_id, "node_type": node_type,
                      "definition": definition}
                     for _, concept_id, node_type, definition, _ in facts],
        "nodes": [{"local_id": local_id, "concept_id": concept_id,
                   "evidence_text": evidence, "occurrence": 1}
                  for local_id, concept_id, _, _, evidence in facts],
        "edges": [{"source_node_local_id": local_id,
                   "target_node_local_id": "template.implementation",
                   "edge_type": "constrains", "evidence_text": evidence,
                   "occurrence": 1}
                  for local_id, _, _, _, evidence in facts[1:]],
    }


def generation_input_for_prompt(task: Mapping[str, Any], prompt: str) -> dict[str, Any]:
    """Recover the actual messages from an operation-bound arm's evidence text.

    The current ADD comparisons change only the task portion. Common system and
    language context must remain identical in all five arms.
    """
    if "generation_input" not in task:
        raise ValueError("prepare task input before TSG extraction and generation")
    prepared = prepare_task_input(task)
    baseline = prepared["generation_input"]
    request = baseline["request"]
    prefix = input_evidence_text({"system_prompt": baseline["system_prompt"],
                                  "request": {"language": request["language"], "task": ""}})
    if not isinstance(prompt, str) or not prompt.startswith(prefix):
        raise ValueError("intervention changed the common system or language context")
    body = prompt[len(prefix):]
    if "<language>" in body:
        raise ValueError("unfilled language placeholder in generation input")
    return {"system_prompt": baseline["system_prompt"],
            "request": {"language": request["language"], "task": body}}
