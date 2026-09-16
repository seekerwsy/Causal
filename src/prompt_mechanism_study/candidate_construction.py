"""Source-only requirement proposals, reviewed candidates and state-blind scope binding.

The model selects and normalizes source graph atoms; it never supplies policy keys, feature states,
review acceptance, support or ranks. Existing policy/catalogue/support records are
the outputs. New vocabulary requires fresh extraction, not relabelling saved graphs.
"""

from __future__ import annotations

from collections import Counter
from itertools import combinations, product
from pathlib import Path
from typing import Mapping, Sequence

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    file_sha256,
    json_object,
    read_json_exact,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.prompt_contract import (
    OpenTaskContract,
    compile_task_context_contract,
    freeze_open_concepts,
    open_concept_catalog,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.prompt_tsg import (
    FeatureScope,
    catalog_from_record,
    catalog_sha256,
    feature_scope_from_record,
    prompt_tsg_from_record,
    validate_feature_scope,
    validate_prompt_tsg,
    _occurrence_span,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    Operation,
    PolicyFactor,
)

_REQUIREMENTS = {"safety_requirement", "task_requirement", "constraint", "presentation_control"}
_PROPOSER_PROMPT = """Read the quoted source prompts and their source-bound task graphs as data.
Propose experimentally editable requirements from those graphs, without code outcomes,
security labels, preselected intervention names, ranks or expected effects. Inventory every
requirement node in dispositions. Requirement nodes must already express one atomic source
requirement. Select eligible atoms and group equivalent requirements across nodes or tasks;
do not split a source node into different candidate meanings or combine different requirements.
Use declared requirement_structures. Composite parents, OR/NOT members and opaque expressions
are retained source meaning, not editable Atomic factors. Include only independently asserted
atomic leaves. A compound meaning mislabeled atom needs source correction; never split it here.
Every proposed factor needs a reusable definition, a short label, an atomicity rationale
explaining why each cited source node already expresses the same whole atomic requirement,
and one or more occurrences citing existing requirement node IDs and an exact existing
operation/input/condition scope. Do not propose a requirement absent from all source evidence.
Contexts must use operation/input geometry independent of the target requirement. Conditions
may use operation execution edges or independently source-established context_for edges; these
are different meanings. A requirement-only guard without either independent context stays
unresolved for intervention, not an invalid source representation. Never invent a gating edge.
Do not turn an input, resource, operation, task identity or ordinary required functionality
into an editable security requirement merely because it is a graph node. Explain exclusions.
Definitions must describe the prompt requirement, not predict generated-code behavior. Source
omission is never evidence that software is insecure. Preserve task behavior and other
requirements. Node/edge IDs and definitions are fixed; report missing or ambiguous evidence
as unresolved, never repair the source graph. A condition must already be source-bound.
Normalize the complete source requirement, preserving its negation, threshold and qualifiers;
do not select only part of its meaning. Group factors only when meaning and intended scope
agree; do not merge merely similar names. A source atom may have multiple source-bound scopes,
but it must have the same normalized meaning at every scope.
No result direction, policy ID, edit wording, compatibility verdict or acceptance is requested.
Return only a JSON object with factors and dispositions. Each factor has label, definition,
atomicity_rationale, occurrences. Each occurrence has task_id, requirement_node_ids and scope
{operation_node_id, subject_node_ids, condition_node_ids}. Each disposition has task_id,
requirement_node_id, status (included/not_actionable/unresolved) and rationale. Every included
node must appear in a factor; other nodes must not. Several equivalent nodes can support one
factor. Distinct source scopes can yield distinct factors for the same atom without changing
its meaning. Empty factors is a valid result, never fill a quota.
"""


def candidate_request(tasks: Sequence[dict], contracts: Sequence[OpenTaskContract], *, input_catalog: dict | None = None) -> dict:
    """Expose source graphs only; require recorded development exposure before reading them."""
    by_task = {row["task_id"]: row for row in tasks}
    if len(by_task) != len(tasks) or not tasks:
        raise ValueError("candidate sources must be nonempty unique tasks")
    for contract in contracts:
        if not isinstance(contract, OpenTaskContract) or contract.review_status != "development_exposed" or contract.arms_or_outcomes_used:
            raise ValueError("candidate concepts require source-only exposed development contracts")
    catalog = _source_input_catalog(contracts, input_catalog)
    seen, sources = set(), []
    for contract in sorted(contracts, key=lambda row: row.task_id):
        if (not isinstance(contract, OpenTaskContract) or contract.review_status != "development_exposed"
                or contract.arms_or_outcomes_used or contract.task_id not in by_task or contract.task_id in seen):
            raise ValueError("candidate concepts require source-only exposed development contracts")
        seen.add(contract.task_id)
        prompt = by_task[contract.task_id]["prompt"]
        graph = compile_task_context_contract(contract, prompt=prompt, catalog=catalog)
        nodes = [dict(node_id=node.node_id, node_type=node.node_type, concept_id=node.semantic_id,
                      definition=contract.catalog["semantic_guidance"].get(node.semantic_id, ""),
                      evidence=prompt[node.evidence_start:node.evidence_end])
                 for node in sorted(graph.nodes, key=lambda n: n.node_id)]
        modalities = (contract.source_inventory or {}).get("statement_kinds", {})
        for fact in contract.facts:
            if fact["local_id"] not in modalities:
                continue
            left, right = _occurrence_span(prompt, fact["evidence_text"], fact["occurrence"])
            match = next(n for n in graph.nodes if n.semantic_id == fact["semantic_id"]
                         and (n.evidence_start, n.evidence_end) == (left, right))
            next(n for n in nodes if n["node_id"] == match.node_id)["statement_kind"] = modalities[fact["local_id"]]
        # Outcomes, predicted feature states, task labels and unrelated metadata are not copied.
        sources.append(dict(task_id=graph.task_id, source_prompt=prompt,
                            prompt_sha256=graph.prompt_sha256, prompt_tsg_id=graph.tsg_id,
                            nodes=nodes, edges=canonical_value(sorted(graph.edges, key=lambda e: e.edge_id)),
                            requirement_structures=canonical_value(graph.requirement_structures)))
    return dict(request_kind="source_graph_requirement_candidates", sources=sources,
                missing_graph_task_ids=sorted(set(by_task) - seen), arms_or_outcomes_used=False,
                requirement_granularity="atomic_source_requirement")


def _source_input_catalog(contracts, supplied=None):
    candidates = [supplied] if supplied is not None else [open_concept_catalog(), *[c.catalog for c in contracts]]
    for catalog in candidates:
        if all(c.input_catalog_sha256 == catalog_sha256(catalog) for c in contracts):
            return catalog_from_record(catalog)
    raise ValueError("provide the exact original input catalogue; a derived vocabulary cannot replace it")


def candidate_response_format() -> dict:
    text = {"type": "string"}
    def obj(properties):
        return dict(type="object", properties=properties, required=list(properties), additionalProperties=False)
    def array(items):
        return dict(type="array", items=items)
    scope = obj(dict(operation_node_id=text, subject_node_ids=array(text), condition_node_ids=array(text)))
    occurrence = obj(dict(task_id=text, requirement_node_ids=array(text), scope=scope))
    factor = obj(dict(label=text, definition=text, atomicity_rationale=text, occurrences=array(occurrence)))
    disposition = obj(dict(task_id=text, requirement_node_id=text,
        status=dict(type="string", enum=["included", "not_actionable", "unresolved"]), rationale=text))
    return dict(type="json_schema", json_schema=dict(name="source_requirement_candidates", strict=True,
        schema=obj(dict(factors=array(factor), dispositions=array(disposition)))))


def _fields(row: Mapping, expected: set[str], name: str) -> None:
    if not isinstance(row, dict) or set(row) != expected:
        raise ValueError(f"{name} fields are invalid")


def _canonical_concepts(request: dict) -> tuple[dict, dict, dict]:
    """Merge only identical type/definition pairs, never infer semantic equivalence."""
    aliases, definitions, types = {}, {}, {}
    fixed = _fixed_template_concepts()
    reserved = {(row["node_type"], row["definition"]): key for key, row in fixed.items()}
    for source in request["sources"]:
        for node in source["nodes"]:
            original = node["concept_id"]
            if original == "task.root":
                continue
            definition = node["definition"]
            require_text(definition, "source concept definition")
            key = reserved.get((node["node_type"], definition), content_id("concept_", (node["node_type"], definition)))
            alias = node["node_type"] + "::" + original
            if alias in aliases and aliases[alias] != key:
                raise ValueError("conflicting source concept definitions need semantic repair before candidate construction")
            aliases[alias] = key
            definitions[key], types[key] = definition, node["node_type"]
    return aliases, definitions, types


def _fixed_template_concepts():
    from prompt_mechanism_study.task_input import generation_template_facts
    # These are the program's existing baseline-message definitions, never
    # candidate requirements or newly acquired source tasks.
    return {row["concept_id"]: row for row in generation_template_facts(
        dict(task_id="template-definition", prompt="Template definitions only.", language="python"))["concepts"]}


def _occurrence(source: dict, occurrence: dict, aliases: dict) -> tuple[dict, dict]:
    _fields(occurrence, {"task_id", "requirement_node_ids", "scope"}, "factor occurrence")
    nodes = {node["node_id"]: node for node in source["nodes"]}
    links = {(e["source_id"], e["edge_type"], e["target_id"]) for e in source["edges"]}
    requirements = occurrence["requirement_node_ids"]
    from .prompt_tsg import requirement_membership
    _, atoms = requirement_membership(source.get('requirement_structures', []),
        {key for key,node in nodes.items() if node['node_type'] in _REQUIREMENTS})
    if (not isinstance(requirements, list) or not requirements or len(set(requirements)) != len(requirements)
            or any(key not in nodes or nodes[key]["node_type"] not in _REQUIREMENTS
                   or nodes[key].get("statement_kind", "obligation") != "obligation" or key not in atoms for key in requirements)):
        raise ValueError("factor needs existing source requirement evidence")
    scope = feature_scope_from_record(occurrence["scope"])
    op, subjects, conditions = scope.operation_node_id, scope.subject_node_ids, scope.condition_node_ids
    if (op not in nodes or nodes[op]["node_type"] != "task_operation"
            or len(set(subjects)) != len(subjects) or len(set(conditions)) != len(conditions)
            or any(key not in nodes or nodes[key]["node_type"] != "data_object"
                   or (key, "used_by", op) not in links for key in subjects)
            or any(key not in nodes or nodes[key]["node_type"] != "condition" for key in conditions)):
        raise ValueError("factor scope must use source-bound operations, inputs and conditions")
    for requirement in requirements:
        if ((requirement, "constrains", op) not in links
                or any((requirement, "constrains", key) not in links for key in subjects)):
            raise ValueError("requirement evidence does not bind the complete proposed scope")
        actual_conditions = {a for a, relation, b in links if relation == "conditions" and b in {op, requirement}}
        if set(conditions) != actual_conditions:
            raise ValueError("candidate scope cannot discard or invent source conditions")
    if any((condition, "conditions", op) not in links and (condition, 'context_for', op) not in links for condition in conditions):
        raise ValueError("candidate context needs source-established operation conditions independent of the target")
    requirement_types = {nodes[key]["node_type"] for key in requirements}
    if len(requirement_types) != 1:
        raise ValueError("semantic normalization cannot merge different requirement roles")
    # A positive binding may not be narrowed or broadened silently. Repeated occurrences
    # preserve the whole source atom and its operation/subject envelope.
    all_subjects = {b for a, relation, b in links if a in requirements and relation == "constrains"
                    and nodes[b]["node_type"] == "data_object"}
    if all_subjects != set(subjects):
        raise ValueError("candidate scope differs from the source requirement subject set")
    def semantic(key):
        node = nodes[key]
        return aliases[node["node_type"] + "::" + node["concept_id"]]
    selector = dict(operation_semantic_id=semantic(op),
                    subject_semantic_ids=sorted(semantic(key) for key in subjects),
                    condition_semantic_ids=sorted(semantic(key) for key in conditions),
                    match_rule="unique_source_geometry_match")
    selector['execution_condition_semantic_ids'] = sorted(semantic(c) for c in conditions if (c,'conditions',op) in links)
    evidence = dict(task_id=source["task_id"], prompt_tsg_id=source["prompt_tsg_id"],
                    requirement_node_ids=sorted(requirements), requirement_type=next(iter(requirement_types)),
                    scope=canonical_value(scope))
    return selector, evidence


def _query(selector: dict, feature_id: str) -> dict:
    op = selector["operation_semantic_id"]
    subjects, conditions = selector["subject_semantic_ids"], selector["condition_semantic_ids"]
    semantics = sorted({op, *subjects, *conditions})
    # A condition bound only through the editable requirement cannot define a
    # feature-independent context. Such tasks remain unbound downstream.
    execution = set(selector.get('execution_condition_semantic_ids', conditions))
    relations = sorted({(s, "used_by", op) for s in subjects}
                       | {(c, "conditions" if c in execution else "context_for", op) for c in conditions})
    identity = content_hash(dict(required_semantics=semantics, required_relations=relations))
    return dict(query_id="context_" + identity, realization_id=content_id("candidate_query_", (identity, feature_id)),
                cwe_id="source_semantics", task_family="source_semantics", required_semantics=semantics,
                forbidden_semantics=[], required_relations=[list(r) for r in relations], actionable_feature_id=feature_id)


def compile_candidate_proposal(
    request: dict, response: dict, design: dict, review: dict | None = None
) -> dict:
    """Normalize source atoms into scoped factors; missing review stays pending."""
    _fields(response, {"factors", "dispositions"}, "candidate response")
    if not isinstance(response["factors"], list) or not isinstance(response["dispositions"], list):
        raise ValueError("candidate response needs arrays")
    if request.get("arms_or_outcomes_used") is not False:
        raise ValueError("candidate request must be source-only")
    if request.get("requirement_granularity") != "atomic_source_requirement":
        raise ValueError(
            "candidate request must require atomic source requirements; prepare a new request from the source TSG"
        )
    _validate_design(design)
    aliases, definitions, types = _canonical_concepts(request)
    sources = {source["task_id"]: source for source in request["sources"]}
    expected = {
        (source["task_id"], n["node_id"])
        for source in sources.values()
        for n in source["nodes"]
        if n["node_type"] in _REQUIREMENTS
    }
    dispositions = {}
    for row in response["dispositions"]:
        _fields(
            row,
            {"task_id", "requirement_node_id", "status", "rationale"},
            "requirement disposition",
        )
        key = row["task_id"], row["requirement_node_id"]
        if (
            key not in expected
            or key in dispositions
            or row["status"] not in {"included", "not_actionable", "unresolved"}
        ):
            raise ValueError("every requirement needs exactly one explicit disposition")
        require_text(row["rationale"], "requirement disposition rationale")
        dispositions[key] = row
    if set(dispositions) != expected:
        raise ValueError("requirement dispositions do not cover every source requirement")
    proposals, covered, source_meanings = {}, set(), {}
    for row in response["factors"]:
        _fields(
            row, {"label", "definition", "atomicity_rationale", "occurrences"}, "proposed factor"
        )
        for key in ("label", "definition", "atomicity_rationale"):
            require_text(row[key], key)
        if not isinstance(row["occurrences"], list) or not row["occurrences"]:
            raise ValueError("every factor must have source occurrences")
        for occurrence in row["occurrences"]:
            if occurrence.get("task_id") not in sources:
                raise ValueError("factor occurrence references an unknown source task")
            selector, evidence = _occurrence(sources[occurrence["task_id"]], occurrence, aliases)
            meaning = (row["definition"], evidence["requirement_type"])
            for node_id in evidence["requirement_node_ids"]:
                source_key = (evidence["task_id"], node_id)
                if source_key in source_meanings and source_meanings[source_key] != meaning:
                    raise ValueError(
                        "source requirement node cannot be split into different candidate meanings; correct the source TSG first"
                    )
                source_meanings[source_key] = meaning
            feature = content_id(
                "feature_",
                dict(
                    definition=row["definition"],
                    scope_selector=selector,
                    node_type=evidence["requirement_type"],
                ),
            )
            proposal = proposals.setdefault(
                feature,
                dict(
                    feature_id=feature,
                    label=row["label"],
                    definition=row["definition"],
                    node_type=evidence["requirement_type"],
                    scope_selector=selector,
                    atomicity_rationales=[],
                    source_occurrences=[],
                ),
            )
            proposal["label"] = min(proposal["label"], row["label"])
            proposal["atomicity_rationales"].append(row["atomicity_rationale"])
            proposal["source_occurrences"].append(evidence)
            covered.update((evidence["task_id"], key) for key in evidence["requirement_node_ids"])
    if covered != {key for key, row in dispositions.items() if row["status"] == "included"}:
        raise ValueError("included requirements and factor evidence disagree")
    for proposal in proposals.values():
        proposal["atomicity_rationales"] = sorted(set(proposal["atomicity_rationales"]))
        proposal["source_occurrences"] = list(
            {content_hash(e): e for e in proposal["source_occurrences"]}.values()
        )
        proposal["source_occurrences"].sort(key=content_hash)
    decisions = _review_decisions(request, response, proposals, review)
    accepted = [value for key, value in sorted(proposals.items()) if decisions.get(key) == "accept"]
    # Queries for different features may share geometry, but each must schedule its
    # own fixed-scope assessment. Identity is feature-specific; geometry is unchanged.
    queries = []
    for factor in accepted:
        query = _query(factor["scope_selector"], factor["feature_id"])
        query["query_id"] = content_id("context_", (query["query_id"], factor["feature_id"]))
        factor["query"] = query
        queries.append(query)
    policies = _policies(accepted, design)
    return dict(
        request_sha256=content_hash(request),
        response_sha256=content_hash(response),
        design=canonical_value(design),
        review=review,
        status="REVIEWED" if review is not None else "PENDING_SEMANTIC_REVIEW",
        factors=[
            dict(value, review_decision=decisions.get(key, "pending"))
            for key, value in sorted(proposals.items())
        ],
        normalization_map=aliases,
        source_definitions=definitions,
        source_types=types,
        queries=queries,
        policies=canonical_value(policies),
        dispositions=sorted(
            dispositions.values(), key=lambda r: (r["task_id"], r["requirement_node_id"])
        ),
        missing_graph_task_ids=request["missing_graph_task_ids"],
        scientific_claim_allowed=False,
        formal_execution_authorized=False,
    )


def _validate_design(design: dict) -> None:
    _fields(
        design,
        {
            "outcome_id",
            "language_scope",
            "api_scope",
            "task_archetype_scope",
            "operations",
            "model_id",
            "support_rule",
            "covariate_names",
        },
        "candidate design",
    )
    for key in ("outcome_id", "model_id"):
        require_text(design[key], key)
    for key in ("language_scope", "api_scope", "task_archetype_scope", "covariate_names"):
        values = design[key]
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or (key != "covariate_names" and not values)
        ):
            raise ValueError("design scopes must be canonical finite sets")
        for value in values:
            require_text(value, key)
    if design["operations"] != ["add", "remove"]:
        raise ValueError("source-derived candidates preserve both ADD and REMOVE")
    rule = design["support_rule"]
    _fields(
        rule,
        {
            "minimum_state_task_units",
            "minimum_shared_lineages",
            "maximum_unresolved_fraction",
            "minimum_feature_reliability",
        },
        "support rule",
    )
    for key in ("minimum_state_task_units", "minimum_shared_lineages"):
        if type(rule[key]) is not int or rule[key] < 1:
            raise ValueError("support counts must be positive integers")
    for key in ("maximum_unresolved_fraction", "minimum_feature_reliability"):
        if type(rule[key]) not in (int, float) or not 0 <= rule[key] <= 1:
            raise ValueError("support fractions must be within zero and one")


def _review_decisions(request, response, proposals, review):
    if review is None:
        return {}
    _fields(review, {"request_sha256", "response_sha256", "reviewer_id", "arms_or_outcomes_used", "decisions"}, "semantic review")
    if (review["request_sha256"] != content_hash(request) or review["response_sha256"] != content_hash(response)
            or review["arms_or_outcomes_used"] is not False):
        raise ValueError("semantic review must bind the exact source-only proposal")
    require_text(review["reviewer_id"], "semantic reviewer")
    decisions = {}
    for row in review["decisions"]:
        _fields(row, {"feature_id", "decision", "rationale", "source_supported", "single_requirement",
                      "normalization_valid", "context_independent", "scope_preserves_task"}, "semantic review decision")
        feature = row["feature_id"]
        if feature not in proposals or feature in decisions or row["decision"] not in {"accept", "reject", "unresolved"}:
            raise ValueError("semantic review must cover each generated factor once")
        require_text(row["rationale"], "semantic review rationale")
        assertions = ("source_supported", "single_requirement", "normalization_valid", "context_independent", "scope_preserves_task")
        if any(type(row[key]) is not bool for key in assertions):
            raise ValueError("semantic review assertions must be explicit booleans")
        if row["decision"] == "accept" and not all(row[key] for key in assertions):
            raise ValueError("accepted factor lacks a source/atomicity/scope review")
        decisions[feature] = row["decision"]
    if set(decisions) != set(proposals):
        raise ValueError("semantic review does not cover all proposed factors")
    return decisions


def _policies(factors, design):
    policies = []

    def scope(query_id, identity):
        return AnalysisScope(
            identity,
            query_id,
            tuple(design["language_scope"]),
            tuple(design["api_scope"]),
            tuple(design["task_archetype_scope"]),
        )

    for factor in factors:
        analysis_scope = scope(
            factor["query"]["query_id"], content_id("pattern_", factor["scope_selector"])
        )
        for operation in design["operations"]:
            policies.append(
                AtomicPolicyKey(
                    analysis_scope,
                    PolicyFactor(factor["feature_id"], Operation(operation)),
                    design["outcome_id"],
                )
            )
    return sorted(policies, key=lambda p: p.policy_key)


def prepare_candidate_request(tasks_path: Path, extraction_bundle: Path, output: Path, *, input_catalog_path: Path | None = None) -> dict:
    """Prepare one inspectable graph-first request from an already exposed extraction."""
    verify_bundle(extraction_bundle)
    extraction = read_json_exact(extraction_bundle / "report.json")
    if extraction.get("review_status") != "development_exposed" or extraction.get("arms_or_outcomes_used") is not False:
        raise ValueError("candidate proposal cannot expose protected or outcome-informed extraction")
    tasks = read_json_exact(tasks_path)
    contracts = [task_context_contract_from_record(row) for row in read_json_exact(extraction_bundle / "contracts.json")]
    exported_tasks = read_json_exact(extraction_bundle / "tasks.json")
    if {t["task_id"]: t["prompt"] for t in tasks} != {t["task_id"]: t["prompt"] for t in exported_tasks}:
        raise ValueError("candidate request must bind the complete prepared extraction task set")
    input_catalog = _source_input_catalog(contracts, read_json_exact(input_catalog_path) if input_catalog_path else None)
    request = candidate_request(tasks, contracts, input_catalog=input_catalog)
    extracted_graphs = {g["task_id"]: prompt_tsg_from_record(g).tsg_id for g in read_json_exact(extraction_bundle / "graphs.json")}
    if extracted_graphs != {source["task_id"]: source["prompt_tsg_id"] for source in request["sources"]}:
        raise ValueError("candidate source graphs do not replay their contracts")
    report = dict(status="CANDIDATE_REQUEST_READY", source_tasks_sha256=file_sha256(tasks_path),
        extraction_bundle_sha256=bundle_digest(extraction_bundle), request_sha256=content_hash(request),
        source_tasks=len(tasks), source_graphs=len(contracts), provider_calls=0,
        missing_graph_task_ids=request["missing_graph_task_ids"], arms_or_outcomes_used=False,
        scientific_claim_allowed=False, formal_execution_authorized=False)
    # Store the same source-only projection used by the request. No outcome-bearing
    # task metadata is transported to the proposal or its reproducibility package.
    source_tasks = [dict(task_id=row["task_id"], prompt=row["prompt"]) for row in sorted(tasks, key=lambda t: t["task_id"])]
    write_bundle(output, {"report.json": report, "request.json": request, "tasks.json": source_tasks,
        "contracts.json": [task_context_contract_record(c) for c in contracts],
        "prompt.json": _PROPOSER_PROMPT, "response-format.json": candidate_response_format(), "input-catalog.json": input_catalog})
    return report


def build_candidate_catalog(
    request_bundle: Path,
    design_path: Path,
    output: Path,
    *,
    response_path: Path | None = None,
    evaluator_path: Path | None = None,
    review_path: Path | None = None,
) -> dict:
    """Compile a retained response or make one explicit development proposal call.

    Omission of an evaluator means zero calls. Review replays the retained response;
    acceptance never supplies new factors, changes graph evidence, or runs Discovery.
    """
    if output.exists():
        raise FileExistsError(output)
    verify_bundle(request_bundle)
    if (response_path is None) == (evaluator_path is None):
        raise ValueError("provide a retained response or one explicit development evaluator")
    request = read_json_exact(request_bundle / "request.json")
    tasks = read_json_exact(request_bundle / "tasks.json")
    contracts = [
        task_context_contract_from_record(row)
        for row in read_json_exact(request_bundle / "contracts.json")
    ]
    if request != candidate_request(
        tasks, contracts, input_catalog=read_json_exact(request_bundle / "input-catalog.json")
    ):
        raise ValueError("candidate request cannot be replayed from its source contracts")
    design = read_json_exact(design_path)
    _validate_design(design)
    raw, evaluator, calls = None, None, 0
    try:
        if response_path is not None:
            raw = response_path.read_bytes()
        else:
            from prompt_mechanism_study.functional_judge import bailian_complete

            evaluator = _proposal_evaluator(evaluator_path)
            calls = 1
            raw = bailian_complete(
                request,
                {**evaluator, "response_format": candidate_response_format()},
                read_json_exact(request_bundle / "prompt.json"),
            )
        response = json_object(raw)
        review = read_json_exact(review_path) if review_path is not None else None
        proposal = compile_candidate_proposal(request, response, design, review)
        catalog = _candidate_catalog(contracts, proposal, design, review)
    except Exception as error:
        # A rejected provider response remains an inspectable failure, not an empty
        # candidate universe or a prompt-repair/retry opportunity.
        rejected = getattr(error, "provider_response", None)
        report = dict(
            status="CANDIDATE_PROPOSAL_FAILED",
            provider_calls=calls,
            error_type=type(error).__name__,
            error_message=str(error),
            request_bundle_sha256=bundle_digest(request_bundle),
            scientific_claim_allowed=False,
            formal_execution_authorized=False,
        )
        write_bundle(
            output,
            {
                "report.json": report,
                "request.json": request,
                "design.json": design,
                "response-text.json": (
                    raw.decode("utf-8", errors="replace") if raw is not None else None
                ),
                "rejected-response.json": (
                    rejected.decode("utf-8", errors="replace")
                    if isinstance(rejected, bytes)
                    else None
                ),
            },
        )
        return report
    accepted = [f for f in proposal["factors"] if f["review_decision"] == "accept"]
    report = dict(
        status=proposal["status"],
        source_requirement_nodes=len(proposal["dispositions"]),
        proposed_factors=len(proposal["factors"]),
        accepted_factors=len(accepted),
        atomic_policies=sum("factor" in row for row in proposal["policies"]),
        provider_calls=calls,
        request_bundle_sha256=bundle_digest(request_bundle),
        request_sha256=proposal["request_sha256"],
        response_sha256=proposal["response_sha256"],
        design_sha256=file_sha256(design_path),
        catalog_sha256=catalog_sha256(catalog) if catalog else None,
        implementation_sha256=file_sha256(Path(__file__)),
        arms_or_outcomes_used=False,
        requires_fresh_extraction=True,
        scientific_claim_allowed=False,
        formal_execution_authorized=False,
    )
    review_template = dict(
        request_sha256=proposal["request_sha256"],
        response_sha256=proposal["response_sha256"],
        reviewer_id="",
        arms_or_outcomes_used=False,
        decisions=[
            dict(
                feature_id=f["feature_id"],
                decision="unresolved",
                rationale="",
                source_supported=False,
                single_requirement=False,
                normalization_valid=False,
                context_independent=False,
                scope_preserves_task=False,
            )
            for f in proposal["factors"]
        ],
    )
    artifacts = {
        "report.json": report,
        "proposal.json": proposal,
        "request.json": request,
        "response.json": response,
        "response-text.json": raw.decode("utf-8"),
        "design.json": design,
        "prompt.json": read_json_exact(request_bundle / "prompt.json"),
        "response-format.json": candidate_response_format(),
        "review-template.json": review_template,
        "evaluator.json": evaluator,
        "policies.json": proposal["policies"],
    }
    if catalog is not None:
        artifacts["catalog.json"] = catalog
    write_bundle(output, artifacts)
    return report


def _candidate_catalog(contracts, proposal, design, review):
    if review is None:
        return None
    accepted = [f for f in proposal["factors"] if f["review_decision"] == "accept"]
    fixed = _fixed_template_concepts() if "python" in design["language_scope"] else {}
    definitions = {**proposal["source_definitions"], **{k: v["definition"] for k, v in fixed.items()},
                   **{f["feature_id"]: f["definition"] for f in accepted}}
    # Derived factors are source-grounded decompositions, not additional facts
    # retroactively asserted in input graphs. New scopes need fresh extraction.
    return freeze_open_concepts(tuple(contracts), normalization_map=proposal["normalization_map"],
        definitions=definitions, queries=proposal["queries"],
        seed_semantics={**{k: v["node_type"] for k, v in fixed.items()}, **{f["feature_id"]: f["node_type"] for f in accepted}})


def _proposal_evaluator(path):
    from prompt_mechanism_study.prompt_contract_extract import _evaluator
    evaluator = _evaluator(read_json_exact(path), path)
    if (evaluator["provider"] != "ali_bailian_pay_as_you_go"
            or evaluator["model_id"] != "qwen3.7-flash-2026-07-15"
            or evaluator["base_url"] != "https://dashscope.aliyuncs.com/compatible-mode/v1"
            or evaluator["enable_thinking"] is not False):
        raise ValueError("candidate proposal must use the current fixed development model and region")
    if any(type(evaluator.get(key)) is not int or evaluator[key] <= 0
           for key in ("maximum_input_bytes", "maximum_output_tokens", "max_response_bytes")):
        raise ValueError("candidate proposal requires explicit finite input and output ceilings")
    if type(evaluator["timeout_seconds"]) not in (int, float) or not 0 < evaluator["timeout_seconds"] <= 3600:
        raise ValueError("candidate proposal requires a finite timeout")
    return evaluator


def choose_candidate_scope(graph, selector: dict) -> FeatureScope | None:
    """Select a sole exact structural match, never inspecting requirements or states.

    Ambiguity is not resolved by picking a PRESENT/ABSENT scope. It remains null.
    Conditions use execution guards or non-gating source contexts, never target state.
    """
    nodes = {n.node_id: n for n in graph.nodes}
    links = {(e.source_id, e.edge_type, e.target_id) for e in graph.edges}
    matches = []
    for op in sorted(graph.nodes, key=lambda n: n.node_id):
        if op.node_type != "task_operation" or op.semantic_id != selector["operation_semantic_id"]:
            continue
        inputs = sorted(a for a, rel, b in links if rel == "used_by" and b == op.node_id
                        and nodes[a].node_type == "data_object")
        conditions = sorted(a for a, rel, b in links if rel == "conditions" and b == op.node_id
                            and nodes[a].node_type == "condition")
        # Exact condition set preserves conditional versus unconditional scopes.
        execution = selector.get('execution_condition_semantic_ids', selector['condition_semantic_ids'])
        if sorted(nodes[key].semantic_id for key in conditions) != execution:
            continue
        context_counts = Counter(selector['condition_semantic_ids']) - Counter(execution)
        available_contexts = {a for a,rel,b in links if rel=='context_for' and b==op.node_id}
        context_choices = [list(combinations(sorted(key for key in available_contexts
            if nodes[key].semantic_id==semantic), count)) for semantic,count in sorted(context_counts.items())]
        counts = Counter(selector["subject_semantic_ids"])
        selections = []
        for semantic, count in sorted(counts.items()):
            choices = [key for key in inputs if nodes[key].semantic_id == semantic]
            selections.append(list(combinations(choices, count)))
        for groups in product(*selections):
            subjects = tuple(sorted(key for group in groups for key in group))
            for context_groups in product(*context_choices):
                scoped_conditions = tuple(sorted(set(conditions) | {c for group in context_groups for c in group}))
                matches.append(FeatureScope(op.node_id, subjects, scoped_conditions))
                if len(matches) > 1:
                    return None
    return matches[0] if len(matches) == 1 else None


def bind_candidate_scopes(
    candidate_bundle: Path,
    tasks_path: Path,
    graph_bundles: Sequence[Path],
    output: Path,
    *,
    qualification_bundle: Path | None = None,
) -> dict:
    """Generate the existing positivity configuration from a reviewed candidate bundle."""
    verify_bundle(candidate_bundle)
    report = read_json_exact(candidate_bundle / "report.json")
    if report.get("status") != "REVIEWED" or report.get("arms_or_outcomes_used") is not False:
        raise ValueError("candidate scope binding requires source-reviewed generated factors")
    proposal = read_json_exact(candidate_bundle / "proposal.json")
    request = read_json_exact(candidate_bundle / "request.json")
    response = read_json_exact(candidate_bundle / "response.json")
    if proposal != compile_candidate_proposal(
        request, response, proposal["design"], proposal["review"]
    ):
        raise ValueError("candidate bundle does not replay its source-derived proposal")
    catalog = catalog_from_record(read_json_exact(candidate_bundle / "catalog.json"))
    if catalog_sha256(catalog) != report["catalog_sha256"]:
        raise ValueError("candidate catalogue differs from its review")
    tasks = read_json_exact(tasks_path)
    task_ids = {t["task_id"] for t in tasks}
    if len(task_ids) != len(tasks) or not tasks:
        raise ValueError("candidate scope binding requires unique tasks")
    graphs, digests = {}, []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        digests.append(bundle_digest(bundle))
        for row in read_json_exact(bundle / "graphs.json"):
            graph = prompt_tsg_from_record(row)
            if (
                graph.task_id in graphs
                or graph.task_id not in task_ids
                or graph.catalog_sha256 != catalog_sha256(catalog)
            ):
                raise ValueError(
                    "fresh source graphs must bind the exact candidate catalogue and task set"
                )
            graphs[graph.task_id] = graph
    factors = [f for f in proposal["factors"] if f["review_decision"] == "accept"]
    bindings, unbound = [], []
    for task in sorted(tasks, key=lambda t: t["task_id"]):
        graph = graphs.get(task["task_id"])
        if graph is not None:
            validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        scopes = {}
        for factor in factors:
            scope = (
                choose_candidate_scope(graph, factor["scope_selector"])
                if graph is not None
                else None
            )
            if scope is not None:
                validate_feature_scope(graph, scope)
            scopes[factor["feature_id"]] = canonical_value(scope)
            if scope is None:
                unbound.append(
                    dict(
                        task_id=task["task_id"],
                        feature_id=factor["feature_id"],
                        reason=(
                            "source_graph_missing"
                            if graph is None
                            else "no_unique_source_geometry_match"
                        ),
                    )
                )
        bindings.append(
            dict(
                task_id=task["task_id"],
                prompt_tsg_id=graph.tsg_id if graph else None,
                factor_scopes=scopes,
            )
        )
    definitions = {
        f["feature_id"]: dict(
            definition=f["definition"],
            scope_rule="Unique exact operation/input/condition geometry; no requirement or feature-state reads.",
            scope_selector=f["scope_selector"],
            atomicity_review="SOURCE_REVIEWED_SINGLE_REQUIREMENT",
            candidate_bundle_sha256=bundle_digest(candidate_bundle),
        )
        for f in factors
    }
    design = proposal["design"]
    config = dict(
        source_tasks_sha256=file_sha256(tasks_path),
        catalog_sha256=catalog_sha256(catalog),
        graph_bundle_sha256=sorted(digests),
        model_id=design["model_id"],
        covariate_names=design["covariate_names"],
        policies=proposal["policies"],
        factor_definitions=definitions,
        task_bindings=bindings,
        support_rule=design["support_rule"],
        arms_or_outcomes_used=False,
        scope_choice_used_feature_states=False,
        candidate_construction=dict(
            bundle=str(candidate_bundle.resolve()), bundle_sha256=bundle_digest(candidate_bundle)
        ),
    )
    if qualification_bundle is not None:
        # Absolute local reference survives moving only the generated scope config.
        # Qualification is rechecked by the existing producer, never trusted here.
        config["representation_qualification"] = dict(
            bundle=str(qualification_bundle.resolve()),
            bundle_sha256=bundle_digest(qualification_bundle),
        )
    result = dict(
        status="CANDIDATE_SCOPES_BOUND",
        task_units=len(tasks),
        factors=len(factors),
        policies=len(proposal["policies"]),
        unresolved_scope_bindings=len(unbound),
        candidate_bundle_sha256=bundle_digest(candidate_bundle),
        arms_or_outcomes_used=False,
        scope_choice_used_feature_states=False,
        provider_calls=0,
        scientific_claim_allowed=False,
        formal_execution_authorized=False,
    )
    write_bundle(
        output, {"report.json": result, "scopes.json": config, "unbound-scopes.json": unbound}
    )
    return result


def validate_generated_scope_config(config, tasks, graphs, catalog, *, relative_to: Path):
    """Keep generated factors/scopes attached to their reviewed source proposal."""
    reference = config["candidate_construction"]
    root = relative_to / reference["bundle"]
    if bundle_digest(root) != reference["bundle_sha256"]:
        raise ValueError("candidate construction bundle changed")
    proposal = read_json_exact(root / "proposal.json")
    request, response = read_json_exact(root / "request.json"), read_json_exact(root / "response.json")
    if (proposal["status"] != "REVIEWED" or proposal != compile_candidate_proposal(request, response, proposal["design"], proposal["review"])
            or read_json_exact(root / "catalog.json") != catalog
            or config["policies"] != proposal["policies"]):
        raise ValueError("generated candidate policies do not replay their reviewed source proposal")
    factors = {f["feature_id"]: f for f in proposal["factors"] if f["review_decision"] == "accept"}
    if set(config["factor_definitions"]) != set(factors):
        raise ValueError("generated candidate factor set changed")
    for key, factor in factors.items():
        supplied = config["factor_definitions"][key]
        if supplied["definition"] != factor["definition"] or supplied.get("scope_selector") != factor["scope_selector"]:
            raise ValueError("generated candidate meaning or scope rule changed")
    by_task = {t["task_id"]: t for t in config["task_bindings"]}
    for task in tasks:
        graph = graphs.get(task["task_id"])
        expected = {key: canonical_value(choose_candidate_scope(graph, factor["scope_selector"])) if graph else None
                    for key, factor in factors.items()}
        if by_task[task["task_id"]]["factor_scopes"] != expected:
            raise ValueError("generated scope binding differs from state-blind source geometry")
