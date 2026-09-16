"""Compile one retained automatic proposal under either frozen projection version.

Run with PYTHONPATH selecting the archived baseline or current source. Per-factor
checks localize batch rejection; they never replace its result or constitute acceptance.
"""
from pathlib import Path
import sys

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.candidate_construction import candidate_request, compile_candidate_proposal
from prompt_mechanism_study.prompt_contract import task_context_contract_from_record


def run(base, output):
    saved = base / "proposal-request"
    request = candidate_request(read_json(saved / "tasks.json"),
        [task_context_contract_from_record(c) for c in read_json(saved / "contracts.json")],
        input_catalog=read_json(saved / "input-catalog.json"))
    original = read_json(saved / "request.json")
    assert request["sources"] == original["sources"], "comparison must use identical graphs"
    import json
    call = read_json(base / "proposal-result/call/call.json")
    response = json.loads(call["response_text"]) if call["response_text"] is not None else None
    if response is None:
        # The completed leading array can locate defects, but never repairs or
        # accepts the truncated top-level response or its missing dispositions.
        partial = json.loads(call["trace"]["response"])["choices"][0]["message"]["content"]
        start = partial.index("[", partial.index('"factors"'))
        factors, _ = json.JSONDecoder().raw_decode(partial, start)
    else:
        factors = response["factors"]
    design = read_json(base / "proposal-config-canonical/design.json")

    def attempt(value):
        try:
            proposal = compile_candidate_proposal(request, value, design)
            return dict(status="STRUCTURALLY_COMPILED_PENDING_REVIEW", proposal=proposal)
        except Exception as error:
            return dict(status="FAILED", error_type=type(error).__name__, error_message=str(error))

    full = (attempt(response) if response is not None else dict(
        status="NOT_EVALUABLE_INVALID_PROVIDER_RESPONSE", error=call["error"],
        accepted_factors=0, actual_edits=0))
    local = []
    for index, factor in enumerate(factors):
        selected = {(o["task_id"], node) for o in factor["occurrences"] for node in o["requirement_node_ids"]}
        dispositions = [dict(task_id=s["task_id"], requirement_node_id=n["node_id"],
            status="included" if (s["task_id"], n["node_id"]) in selected else "not_actionable",
            rationale="Mechanical per-factor diagnostic only; not a model disposition or acceptance.")
            for s in request["sources"] for n in s["nodes"] if n["node_type"] in
            {"task_requirement", "safety_requirement", "constraint", "presentation_control"}]
        local.append(dict(index=index, label=factor["label"], diagnostic_only=True,
            result=attempt(dict(factors=[factor], dispositions=dispositions))))
    write_bundle(output, {"request.json": request, "full.json": full, "per-factor-diagnostics.json": local,
        "leading-factors-diagnostic-only.json": factors})
    print(full["status"], len(factors), [r["result"]["status"] for r in local])


if __name__ == "__main__":
    run(Path(sys.argv[1]), Path(sys.argv[2]))
