"""Source-backed requirements and bounded knowledge-supported ADD proposals.

The model selects and normalizes complete source requirements; it never supplies policy keys, feature states,
review acceptance, support or ranks. Existing policy/catalogue/support records are
the outputs. New vocabulary requires fresh extraction, not relabelling saved graphs.
The opt-in development ADD path records external policy provenance separately;
it never invents a source requirement or activates the formal protocol.
"""

from __future__ import annotations

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
from prompt_mechanism_study.tsg.prompt_contract import (
    OpenTaskContract,
    compile_task_context_contract,
    freeze_open_concepts,
    open_concept_catalog,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    catalog_from_record,
    catalog_sha256,
    feature_scope_from_record,
    prompt_tsg_from_record,
    requirement_binding,
    select_feature_scope as choose_candidate_scope,
    validate_feature_scope,
    validate_prompt_tsg,
    _occurrence_span,
    source_nodes,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text
from prompt_mechanism_study.tsg.source_records import (
    candidate_record_dependencies,
    source_evidence_diagnostics,
    validate_development_records,
)
from prompt_mechanism_study.tsg.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    Operation,
    PolicyFactor,
)

_REQUIREMENTS = {"safety_requirement", "task_requirement", "constraint", "presentation_control"}


def render_add_policy(binding, view, source_prompt):
    """Render the one binding verbatim; no independent model-written edit."""
    parts = ['Additional requirement: ' + binding['requirement']]
    for field, title in (('targets', 'Directly constrained objects'), ('operations', 'Directly constrained operations')):
        if binding[field]:
            targets = []
            for key in binding[field]:
                fact = view['records'][key]['fact']
                definition, quote = fact['concept']['definition'], fact['evidence_text']
                targets.append(f'{definition} (source: {quote})'
                               if quote != definition and quote in source_prompt else definition)
            parts.append(title + ': ' + '; '.join(targets))
    parts.extend(['Conditions: ' + ('; '.join(binding['conditions']) if binding['conditions'] else 'No additional condition.'),
                  'Scope: ' + binding['scope'], 'Required time: ' + binding['time']])
    return '\n'.join(parts)


def knowledge_add_candidate(*, source_prompt, source_records, knowledge, binding, assessment):
    """Build one bounded development ADD proposal without modifying source facts.

    Source compatibility and coverage are explicit upstream semantic judgments,
    not inferred from a CWE tag, a node type, or missing graph nodes. This path
    does not activate a formal protocol or certify an automatic proposal.
    """
    view = validate_development_records(source_records, source_prompt)
    return _knowledge_add_candidate(source_prompt, view, knowledge, binding, assessment)


def _knowledge_add_candidate(source_prompt, view, knowledge, binding, assessment):
    """Compile one proposal using the source view already checked for this call."""
    if not isinstance(binding, dict) or not isinstance(assessment, dict):
        raise ValueError('binding and assessment must be objects')
    for key in ('id', 'url', 'principle', 'version'):
        require_text(knowledge.get(key), f'knowledge {key}')
    if not knowledge['url'].startswith('https://'):
        raise ValueError('knowledge needs a public source URL')
    for key in ('author', 'source_state', 'compatibility', 'relevance', 'rationale'):
        require_text(assessment.get(key), f'assessment {key}')
    if assessment['source_state'] not in {'UNEXPRESSED', 'EXPRESSED', 'UNRESOLVED'}:
        raise ValueError('an explicit full-source expression judgment is required')
    if assessment['compatibility'] not in {'compatible', 'conflict', 'unresolved'}:
        raise ValueError('invalid compatibility judgment')
    if assessment['relevance'] not in {'supported', 'unsupported', 'unresolved'}:
        raise ValueError('invalid security relevance judgment')
    evidence_diagnostics = view['evidence_diagnostics'] + source_evidence_diagnostics(assessment, source_prompt)
    base = dict(source_sha256=content_hash(source_prompt),
                source_records_sha256=view['source_records_sha256'],
                policy_origin='knowledge_supported_development_add',
                knowledge=dict(knowledge), assessment=dict(assessment),
                effect_status='UNTESTED', formal_eligible=False,
                source_graph_mutated=False, automatic_semantic_certification=False,
                evidence_diagnostics=evidence_diagnostics, structural_diagnostics=view['structural_diagnostics'])
    if assessment['compatibility'] == 'conflict':
        return dict(base, decision='reject', policy=None)
    if (assessment['source_state'] != 'UNEXPRESSED'
            or assessment['compatibility'] != 'compatible'
            or assessment['relevance'] != 'supported'
            or assessment.get('complete_binding') is not True):
        return dict(base, decision='abstain', policy=None)
    if not assessment.get('evidence'):
        raise ValueError('an accepted ADD needs source evidence, not knowledge alone')
    targets, operations = binding.get('targets'), binding.get('operations')
    for key, refs, group in (('targets', targets, 'objects'), ('operations', operations, 'operations')):
        if (not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs)
                or len(refs) != len(set(refs)) or not set(refs) <= set(view['groups'][group])):
            raise ValueError(f'ADD {key} must be existing, unique source {group}')
    if not targets and not operations:
        raise ValueError('ADD needs at least one directly constrained object or operation')
    for key in ('requirement', 'time', 'scope', 'endpoint'):
        require_text(binding.get(key), f'binding {key}')
    if (not isinstance(binding.get('conditions'), list)
            or any(not isinstance(c, str) or not c.strip() for c in binding['conditions'])):
        raise ValueError('explicit policy conditions are required')
    support = binding.get('support_records', [])
    if not isinstance(support, list) or any(not isinstance(r, str) for r in support):
        raise ValueError('support_records must be source IDs')
    dependencies = candidate_record_dependencies(view, binding)
    dispositions = assessment.get('structural_dispositions', {})
    if not isinstance(dispositions, dict):
        raise ValueError('structural_dispositions must be a record-keyed object')
    blocked = []
    for issue in view['structural_diagnostics']:
        key = issue['record_id']
        judgment = dispositions.get(key, {})
        if (key in dependencies or not isinstance(judgment, dict)
                or judgment.get('relevance') != 'unrelated'
                or not isinstance(judgment.get('rationale'), str) or not judgment['rationale'].strip()):
            blocked.append(issue)
    if blocked:
        return dict(base, decision='abstain', policy=None, blocking_records=blocked)
    invariants = assessment.get('non_target_invariants')
    if (not isinstance(invariants, list) or not invariants
            or any(not isinstance(text, str) or not text.strip() for text in invariants)):
        raise ValueError('ADD needs explicit non-target invariants')
    policy = canonical_value({key: binding[key] for key in ('requirement', 'targets', 'operations', 'conditions', 'scope', 'time', 'endpoint')})
    policy.update(operation='ADD', support_records=list(support))
    policy['edit_text'] = render_add_policy(policy, view, source_prompt)
    policy['policy_id'] = 'policy.' + content_hash({
        'knowledge': knowledge, 'binding': policy, 'source': base['source_sha256']})
    # There is deliberately no invented requirement_node_id: no such source
    # requirement need exist. REMOVE remains on the original source-backed path.
    return dict(base, decision='include', policy=policy)


def knowledge_add_model_request(source_prompt, source_records, knowledge):
    """Request source-only judgments and proposals; no outcome-based ranking."""
    view = validate_development_records(source_records, source_prompt)
    return dict(request_kind='bounded_development_knowledge_add', source_prompt=source_prompt,
        source_records=source_records, knowledge=knowledge,
        evidence_diagnostics=view['evidence_diagnostics'], structural_diagnostics=view['structural_diagnostics'], instructions=(
        'Read the entire source and its records. For EVERY supplied principle, return '
        'one assessment, including irrelevant principles. applicability is applicable, '
        'not_applicable or unresolved. source_state describes whether the complete '
        'principle is explicitly expressed in the FULL source: UNEXPRESSED, EXPRESSED '
        'or UNRESOLVED; never infer it from missing nodes. Cite literal source quotations. '
        'evidence_diagnostics flags unlocated quotations, not proven semantic errors. '
        'Check their claims against the complete source; exact quote matching alone '
        'also does not prove a binding. Do not approve unsupported claims, silently '
        'repair records, or infer absence from a quotation mismatch. If necessary '
        'binding meaning cannot be established, keep the relevant judgment unresolved. '
        'Expected input domains are assumptions, not automatically validation obligations. '
        'A required operation does not prescribe a particular optional implementation. '
        'An import alone does not prescribe using that API. Original examples, return '
        'contracts, branch conditions and any intended raw markup/code behavior must '
        'be preserved. Select at most TWO distinct single-requirement ADD proposals '
        'in source-supported priority order, independent of expected effect. Each '
        'proposal must be relevant, compatible, UNEXPRESSED and completely bound. '
        'targets and operations name direct recipients of the ENTIRE requirement, '
        'not merely participants. Either list may be empty, but not both. A parser '
        'restriction may constrain a parsing operation without a fabricated parser '
        'object; its input file need not be a direct target. Necessary input/output '
        'identities must still be supported in the source records. '
        'One policy may quantify multiple targets; do not combine independent safety '
        'requirements. Write ONE binding only; the program renders it directly as '
        'the appended note. Do not supply a separate edit_text. requirement states '
        'the property, targets/operations identify its direct recipients, and conditions '
        'contains complete condition texts (empty means no additional condition, NEVER '
        'unknown). scope/time retain quantification and when it must hold without '
        'contradicting the targets. support_records names other necessary source records. '
        'For each structural diagnostic, judge its relevance to this EXACT proposal '
        'in assessment.structural_dispositions. Only a source-supported unrelated '
        'judgment with rationale permits ignoring a nondependent defect; missing or '
        'uncertain relevance remains unresolved. Global constraints remain relevant. '
        'Each proposal supplies its own full-source expression and compatibility '
        'assessment of the COMPLETE binding, not just the broad knowledge principle. '
        'The note may not change the source '
        'interface, required content or legitimate input domain. Do not add unrelated '
        'allowlists, privacy assumptions or rejection rules. You cannot repair the '
        'source records downstream: missing necessary objects, bindings or guards '
        'mean unresolved. Already expressed, conflicting and unresolved policies '
        'must not be proposed. Unsupported measurement ideas may be described in '
        'the rationale, not silently mapped to another principle. Program validation '
        'does not certify your judgments. No prose outside the JSON object.'),
        output_format=dict(
          assessments={'EACH_PRINCIPLE_ID': dict(applicability='applicable|not_applicable|unresolved',
              source_state='UNEXPRESSED|EXPRESSED|UNRESOLVED', evidence=['literal source quote'], rationale='source reasoning')},
          proposals=[dict(knowledge_id='one supplied principle ID', binding=dict(
              targets=['existing object IDs'], operations=['existing operation IDs'], conditions=[], support_records=[],
              time='when the policy must hold', scope='complete target set, guards and scope',
              requirement='one complete requirement'),
              assessment=dict(source_state='UNEXPRESSED|EXPRESSED|UNRESOLVED', compatibility='compatible|conflict|unresolved',
                  relevance='supported|unsupported|unresolved', complete_binding=True,
                  evidence=['source quote'], non_target_invariants=['preserved source meaning'], rationale='exact binding reasoning',
                  structural_dispositions={'DEFECTIVE_RECORD_ID':dict(relevance='unrelated|relevant|unresolved',rationale='why in the full source')}))]))


def compile_knowledge_add_response(*, source_prompt, source_records, knowledge, response, author):
    """Preserve each principle judgment and each of the two ordered proposal slots.

    Missing/malformed neighboring answers do not erase valid cells. Extra slots
    are recorded, never used as replacements or to enlarge the frozen budget.
    Measurement compatibility is deliberately decided by the caller afterwards.
    """
    if not isinstance(response, dict):
        raise ValueError('proposal response must be an object')
    view = validate_development_records(source_records, source_prompt)
    cards = {card['id']: card for card in knowledge}
    assessments, errors, diagnostics = {}, {}, []
    raw_assessments = response.get('assessments')
    if not isinstance(raw_assessments, dict):
        raw_assessments = {}
    for key in cards:
        assessments[key] = None
        try:
            a = raw_assessments[key]
            if not isinstance(a, dict):
                raise ValueError('assessment must be an object')
            if a.get('applicability') not in {'applicable', 'not_applicable', 'unresolved'}:
                raise ValueError('invalid applicability')
            if a.get('source_state') not in {'EXPRESSED', 'UNEXPRESSED', 'UNRESOLVED'}:
                raise ValueError('invalid source state')
            diagnostics.extend(source_evidence_diagnostics({key: a}, source_prompt))
            assessments[key] = dict(a)
        except (KeyError, TypeError, ValueError) as exc:
            errors[key] = 'missing assessment' if key not in raw_assessments else str(exc)
    proposals, response_errors = [], []
    extra_keys = sorted(set(raw_assessments) - set(cards))
    if extra_keys:
        response_errors.append('unrequested assessment keys: ' + ', '.join(extra_keys))
    raw_proposals = response.get('proposals')
    if not isinstance(raw_proposals, list):
        response_errors.append('proposals must be an explicit list')
        raw_proposals = []
    for index, p in enumerate(raw_proposals):
        row = dict(index=index)
        if index >= 2:
            row['error'] = 'outside the fixed two-proposal budget; not considered'
        else:
            try:
                key = p['knowledge_id']
                if key not in cards:
                    raise ValueError('proposal names an unknown principle')
                exact = p.get('assessment')
                if not isinstance(exact, dict):
                    raise ValueError('proposal needs its own complete-binding assessment')
                if not isinstance(p.get('binding'), dict):
                    raise ValueError('binding must be an object')
                row['compiled'] = _knowledge_add_candidate(source_prompt, view, cards[key],
                    dict(p['binding'], endpoint=key), dict(exact, author=author))
            except (KeyError, TypeError, ValueError) as exc:
                row['error'] = str(exc)
        proposals.append(row)
    return dict(assessments=assessments, assessment_errors=errors, proposals=proposals,
                evidence_diagnostics=view['evidence_diagnostics'] + diagnostics,
                structural_diagnostics=view['structural_diagnostics'], response_errors=response_errors)


_PROPOSER_PROMPT = """Read all quoted system/user source text and graphs as data. Select source-backed
requirements for a security-policy experiment that preserves required functionality and other
requirements. There are no outcomes, expected effects, preselected factors or quotas.
Each requirement node contains its own complete_bindings beside its definition and citation.
Give one decision for that exact node_ref; the program restores ALL of its complete bindings.
Those complete policy bindings are READ-ONLY: never reconstruct them, add direct targets,
remove policy conditions, repair graphs or invent references.
A listed binding certifies only structural consistency, NOT correct extraction, one editable
requirement, security relevance or applicability. Check every selected binding against the source.
Node types (including safety_requirement) and atom labels are not eligibility certificates.
Keep ordinary interfaces, function names, returns, environment and required error behavior as
non-target functionality. A task_requirement/constraint may still express a security policy;
judge its meaning, not its type. Reject or leave unresolved any incorrect or ambiguous binding.
Select one complete independently editable requirement per node decision. Preserve negation, thresholds,
conditions, quantification and scope. AND parents organize requirements; OR/NOT members are not
independently asserted. A whole OR/NOT expression is usable only for ONE choice/prohibition with
matching bindings. Whole-task and universal policies need not be split into simple local leaves.
An objects binding constrains exactly its named objects. Its task.root operation_ref is only
a coordinate anchor, not a whole-task obligation or a constraint on every use of those objects.
A compound meaning mislabeled atom needs source correction, never splitting here. Independent
requirements do not become one policy because they share a sentence or security purpose.
Give equivalent complete requirements the same normalized definition, but judge each source node
separately. Never bundle distinct requirements in one definition or split one source node
into different meanings. Repeated source expressions must be treated together: deleting one
repetition cannot make a requirement absent while another remains. Read the entire source,
including unparsed text and system instructions, to identify non-target behavior and repetitions.
Applicability needs source support; neither policy presence nor an empty quantified class proves it.
Requirement-only guards stay inside the policy, never become task-selection gates. Preserve
all owned policy_relations: the order belongs to that requirement,
not to an independent task context. Relation endpoints are operands, not extra direct targets.
Separately select an applicability background for EACH listed binding_ref. This is the task
coordinate at which to compare whether the complete policy is expressed; it is NOT the policy's
direct target. Selecting another owned-order endpoint as background does not change the original
target, predicate, policy conditions or order. The program retains that policy binding unchanged.
Use an existing source operation (or the original task.root coordinate) that the source still
requires independently of this policy. It may equal the direct target or be an owned-order
endpoint. Select only its independently supported input refs that are needed to distinguish this
comparison, and ALL its independent execution-condition refs. Do not copy every input automatically:
a policy-produced result can be an input to an otherwise independent operation. Do not clear all
subjects merely to avoid that dependency. Policy-only guards stay inside the unchanged policy.
A valid endpoint or declaration alone does not prove
an independently required action. Cite the exact source text that supports the selected background
without relying on the target policy, and explain why that text requires this actual coordinate.
Check the chosen operation_ref itself: a rationale naming a different operation cannot justify it.
Omitting an input does not narrow the operation's definition. If that definition itself contains a
disputed participant, guard or order, leave the affected requirement unresolved for development
source repair; this candidate response cannot rewrite it or reinterpret a frozen concept.
Account for the operation, EVERY source used_by input to it and EVERY source execution condition in
component_decisions. For task.root, account for the original binding's subject refs instead of
inventing root inputs. Each component has its own source quotation and rationale; a source sentence
may be reused. Retain exactly the operation, selected subjects and all execution conditions.
An omitted input must be omit_policy_dependent, or omit_not_needed with an explanation of why the
retained tuple still distinguishes the intended comparison. An unrelated input need not have its
entire semantics resolved before omission. Independently supported does not mean every input is
necessary. Never omit a source execution guard; if a necessary component's independence or the
retained tuple's sufficiency is unresolved, mark the requirement unresolved. Omissions do not delete
graph facts or alter the complete policy. The whole retained tuple, not just the operation, must
remain supported without the policy. Quotations locate evidence, not certify this semantic judgment.
Do not infer an implementation or missing software protection. If any necessary background is
unresolved, mark this requirement unresolved; do not silently reuse the policy-only action.
Describe requirements without predicting code security. Missing prompt text is not missing software protection.
Return only {decisions: {node_ref: {status, label, definition, rationale, applicability_bindings}, ...}}. The schema names
every required decision key. Use exactly those keys, once each, including non-actionable units.
status is include, not_actionable or unresolved. For include, label and definition normalize only
THIS node's complete meaning; rationale explains its one editable predicate and preserved behavior.
applicability_bindings maps each listed binding_ref to {operation_ref, subject_refs,
execution_condition_refs, independent_source_evidence: [{evidence_text, occurrence}], rationale,
component_decisions: [{node_ref, decision: retain|omit_policy_dependent|omit_not_needed,
source_evidence: [{evidence_text, occurrence}], rationale}]}.
Every included binding needs a non-null selection and nonempty supporting citations, including
when background and direct target coincide. occurrence is the one-based source occurrence.
For other statuses, label and definition must be empty strings and rationale explains the decision.
Their applicability_bindings still lists every binding_ref, each with a null value.
A node with no complete_bindings cannot be included. Do not return a separate exclusions list,
occurrence list, revised policy scope fields or baskets of nodes. The same node_ref identifies
the source and its decision; binding_ref only identifies the unchanged binding's background choice.
The compiler groups individually selected
units only by normalized complete meaning and exact scope. Selecting none is valid. Inclusion
remains subject to separate explicit semantic review; matching structure alone does not prove meaning.
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
        modalities = (contract.source_inventory or {}).get("statement_kinds", {})
        kinds = {node.node_id: modalities[key] for key,node in source_nodes(contract.facts, prompt=prompt).items()
                 if key in modalities}
        nodes = [dict(node_id=node.node_id, node_type=node.node_type, concept_id=node.semantic_id,
                      definition=contract.catalog["semantic_guidance"].get(node.semantic_id, ""),
                      evidence=prompt[node.evidence_start:node.evidence_end],
                      **({'statement_kind': kinds[node.node_id]} if node.node_id in kinds else {}))
                 for node in graph.nodes]
        # Outcomes, predicted feature states, task labels and unrelated metadata are not copied.
        sources.append(dict(task_id=graph.task_id, source_prompt=prompt,
                            prompt_sha256=graph.prompt_sha256, prompt_tsg_id=graph.tsg_id,
                            nodes=nodes, edges=canonical_value(sorted(graph.edges, key=lambda e: e.edge_id)),
                            requirement_structures=canonical_value(graph.requirement_structures),
                            retained_requirement_scopes=canonical_value(graph.requirement_scopes),
                            **({"requirement_relations": canonical_value(graph.requirement_relations)}
                               if graph.requirement_relations else {})))
    return dict(request_kind="source_graph_requirement_candidates", sources=sources,
                missing_graph_task_ids=sorted(set(by_task) - seen), arms_or_outcomes_used=False,
                requirement_granularity="complete_single_requirement")


def _source_input_catalog(contracts, supplied=None):
    candidates = [supplied] if supplied is not None else [open_concept_catalog(), *[c.catalog for c in contracts]]
    for catalog in candidates:
        if all(c.input_catalog_sha256 == catalog_sha256(catalog) for c in contracts):
            return catalog_from_record(catalog)
    raise ValueError("provide the exact original input catalogue; a derived vocabulary cannot replace it")


def _candidate_units(request):
    """Enumerate existing complete bindings; make no semantic eligibility judgment."""
    from prompt_mechanism_study.tsg.prompt_tsg import requirement_membership
    aliases, _, _ = _canonical_concepts(request)
    requirements, bindings, sources = {}, {}, []
    for index, source in enumerate(request["sources"], 1):
        task_ref = f"T{index}"
        nodes = {node["node_id"]: node for node in source["nodes"]}
        refs = {key: f"{task_ref}.N{i}" for i, key in enumerate(sorted(nodes), 1)}
        types = {key: node["node_type"] for key, node in nodes.items()}
        links = {(e["source_id"], e["edge_type"], e["target_id"]) for e in source["edges"]}
        ids = {key for key, kind in types.items() if kind in _REQUIREMENTS}
        asserted, _ = requirement_membership(source.get("requirement_structures", []), ids)
        short_bindings = {refs[key]: [] for key in ids}
        for key in sorted(ids):
            requirements[refs[key]] = (source["task_id"], key)
            bindings[refs[key]] = []
            if key not in asserted or nodes[key].get("statement_kind", "obligation") != "obligation":
                continue
            envelope = requirement_binding(key, links=links, node_types=types,
                structures=source.get("requirement_structures", []),
                retained_scopes=source.get("retained_requirement_scopes", []),
                owned_relations=source.get("requirement_relations", []))
            if envelope is None:
                continue
            object_bound = envelope["kind"] == "targets" and not envelope["operations"] and bool(envelope["subjects"])
            operations = ({key for key, node in nodes.items() if node["concept_id"] == "task.root"}
                          if object_bound else envelope["operations"])
            for operation in sorted(operations):
                execution = {a for a, relation, b in links if relation == "conditions" and b == operation}
                scope = dict(operation_node_id=operation, subject_node_ids=sorted(envelope["subjects"]),
                             condition_node_ids=sorted(envelope["conditions"] | execution))
                occurrence = dict(task_id=source["task_id"], requirement_node_ids=[key], scope=scope)
                try:
                    _occurrence(source, occurrence, aliases)
                except ValueError:
                    # The full graph remains visible; unsupported geometry is never guessed.
                    continue
                bindings[refs[key]].append(occurrence)
                short_bindings[refs[key]].append(dict(
                    binding_ref=f"{refs[key]}.B{len(bindings[refs[key]])}",
                    operation_ref=refs[operation], subject_refs=[refs[n] for n in scope["subject_node_ids"]],
                    execution_condition_refs=[refs[n] for n in sorted(execution)],
                    policy_condition_refs=[refs[n] for n in sorted(envelope["conditions"] - execution)],
                    scope_kind="objects" if object_bound else envelope["kind"], target_class=envelope["target_class"],
                    **({"policy_relations": [[refs[a], rel, refs[b]] for a, rel, b in sorted(envelope["relations"])]}
                       if envelope["relations"] else {})))
        sources.append(dict(source_ref=task_ref, source_prompt=source["source_prompt"],
            nodes=[dict(node_ref=refs[key], **{k: v for k, v in node.items() if k not in {"node_id", "concept_id"}},
                        **({"complete_bindings": short_bindings[refs[key]]} if key in ids else {}))
                   for key, node in sorted(nodes.items())],
            edges=[dict(source_ref=refs[edge["source_id"]], target_ref=refs[edge["target_id"]],
                        **{k: v for k, v in edge.items() if k not in {"edge_id", "source_id", "target_id"}})
                   for edge in source["edges"]],
            requirement_structures=[[refs[key], kind, [refs[n] for n in members]]
                                    for key, kind, members in source.get("requirement_structures", [])],
            retained_requirement_scopes=[[refs[key], kind, [refs[n] for n in boundaries], target_class]
                                        for key, kind, boundaries, target_class in source.get("retained_requirement_scopes", [])],
            **({"requirement_relations": [[refs[owner], refs[a], rel, refs[b]]
                for owner, a, rel, b in source["requirement_relations"]]}
               if source.get("requirement_relations") else {})))
    return requirements, bindings, sources


def candidate_model_request(request: dict) -> dict:
    """Compact transport only: preserve all source meaning and exact stored request identity."""
    _, _, sources = _candidate_units(request)
    return dict(request_kind="decide_complete_source_requirements", source_request_sha256=content_hash(request),
                instructions=_PROPOSER_PROMPT, sources=sources, arms_or_outcomes_used=False)


def _expand_unit_decisions(request, response):
    """Restore policy bindings; resolve separately submitted source-backed backgrounds."""
    _fields(response, {"decisions"}, "requirement decision response")
    requirements, bindings, short_sources = _candidate_units(request)
    _fields(response["decisions"], set(requirements), "complete requirement decisions")
    source_nodes = {}
    for source, short in zip(request["sources"], short_sources, strict=True):
        source_nodes[source["task_id"]] = {item["node_ref"]: node["node_id"]
            for node, item in zip(sorted(source["nodes"], key=lambda n: n["node_id"]), short["nodes"], strict=True)}
    # Four-field decisions are retained only to replay frozen pre-background responses.
    # The active request/schema always requires an explicit choice for every binding.
    active = any(isinstance(row, dict) and "applicability_bindings" in row for row in response["decisions"].values())
    factors, dispositions = [], []
    for ref, row in response["decisions"].items():
        _fields(row, {"status", "label", "definition", "rationale"}
                | ({"applicability_bindings"} if active else set()), "requirement decision")
        if row["status"] not in {"include", "not_actionable", "unresolved"}:
            raise ValueError("requirement decision status is invalid")
        require_text(row["rationale"], "requirement decision rationale")
        occurrences = bindings[ref]
        if active:
            expected = {f"{ref}.B{i}": occurrence for i, occurrence in enumerate(occurrences, 1)}
            _fields(row["applicability_bindings"], set(expected), "applicability binding decisions")
            occurrences = []
            for binding_ref, occurrence in expected.items():
                choice = row["applicability_bindings"][binding_ref]
                if row["status"] != "include":
                    if choice is not None:
                        raise ValueError("excluded requirement cannot select an applicability binding")
                    continue
                _fields(choice, {"operation_ref", "subject_refs", "execution_condition_refs",
                                 "independent_source_evidence", "rationale", "component_decisions"},
                        "included applicability binding")
                refs = source_nodes[occurrence["task_id"]]
                def resolve(value):
                    if not isinstance(value, str) or value not in refs:
                        raise ValueError("applicability binding references an unknown source node")
                    return refs[value]
                for name in ("subject_refs", "execution_condition_refs"):
                    if (not isinstance(choice[name], list) or any(not isinstance(value, str) for value in choice[name])
                            or len(set(choice[name])) != len(choice[name])):
                        raise ValueError("applicability binding refs must be unique source-node lists")
                if not isinstance(choice["component_decisions"], list):
                    raise ValueError("applicability component decisions must be an array")
                components = []
                for item in choice["component_decisions"]:
                    _fields(item, {"node_ref", "decision", "source_evidence", "rationale"},
                            "applicability component decision")
                    components.append(dict(node_id=resolve(item["node_ref"]),
                        **{key: item[key] for key in ("decision", "source_evidence", "rationale")}))
                occurrences.append(dict(occurrence,
                    applicability_scope=dict(operation_node_id=resolve(choice["operation_ref"]),
                        subject_node_ids=sorted(resolve(value) for value in choice["subject_refs"]),
                        condition_node_ids=sorted(resolve(value) for value in choice["execution_condition_refs"])),
                    applicability_support=dict(source_evidence=choice["independent_source_evidence"],
                        rationale=choice["rationale"], component_decisions=components)))
        if row["status"] == "include":
            if not bindings[ref]:
                raise ValueError("included requirement has no complete source binding")
            for key in ("label", "definition"):
                require_text(row[key], key)
            factors.append(dict(label=row["label"], definition=row["definition"],
                                atomicity_rationale=row["rationale"], occurrences=occurrences))
        elif row["label"] != "" or row["definition"] != "":
            raise ValueError("excluded requirement must not supply a candidate label or definition")
        task, node = requirements[ref]
        dispositions.append(dict(task_id=task, requirement_node_id=node,
            status="included" if row["status"] == "include" else row["status"], rationale=row["rationale"]))
    return dict(factors=factors, dispositions=dispositions)


def candidate_response_format(request: dict) -> dict:
    text = {"type": "string"}
    def obj(properties):
        return dict(type="object", properties=properties, required=list(properties), additionalProperties=False)
    requirements, bindings, _ = _candidate_units(request)
    citation = obj(dict(evidence_text=text, occurrence=dict(type="integer", minimum=1)))
    component = obj(dict(node_ref=text,
        decision=dict(type="string", enum=["retain", "omit_policy_dependent", "omit_not_needed"]),
        source_evidence=dict(type="array", items=citation, minItems=1), rationale=text))
    choice = obj(dict(operation_ref=text, subject_refs=dict(type="array", items=text),
        execution_condition_refs=dict(type="array", items=text),
        independent_source_evidence=dict(type="array", items=citation, minItems=1), rationale=text,
        component_decisions=dict(type="array", items=component, minItems=1)))
    decisions = {ref: obj(dict(status=dict(type="string", enum=["include", "not_actionable", "unresolved"]),
        label=text, definition=text, rationale=text,
        applicability_bindings=obj({f"{ref}.B{i}": dict(anyOf=[choice, dict(type="null")])
                                    for i in range(1, len(bindings[ref]) + 1)}))) for ref in requirements}
    return dict(type="json_schema", json_schema=dict(name="source_requirement_candidates", strict=True,
        schema=obj(dict(decisions=obj(decisions)))))


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
    from prompt_mechanism_study.tsg.task_input import generation_template_facts
    # These are the program's existing baseline-message definitions, never
    # candidate requirements or newly acquired source tasks.
    return {row["concept_id"]: row for row in generation_template_facts(
        dict(task_id="template-definition", prompt="Template definitions only.", language="python"))["concepts"]}


def _occurrence(source: dict, occurrence: dict, aliases: dict) -> tuple[dict, dict]:
    _fields(occurrence, {"task_id", "requirement_node_ids", "scope"}
            | ({"applicability_scope"} if "applicability_scope" in occurrence else set())
            | ({"applicability_support"} if "applicability_support" in occurrence else set()), "factor occurrence")
    nodes = {node["node_id"]: node for node in source["nodes"]}
    links = {(e["source_id"], e["edge_type"], e["target_id"]) for e in source["edges"]}
    requirements = occurrence["requirement_node_ids"]
    from prompt_mechanism_study.tsg.prompt_tsg import requirement_membership
    asserted, _ = requirement_membership(source.get('requirement_structures', []),
        {key for key,node in nodes.items() if node['node_type'] in _REQUIREMENTS})
    if (not isinstance(requirements, list) or not requirements or len(set(requirements)) != len(requirements)
            or any(key not in nodes or nodes[key]["node_type"] not in _REQUIREMENTS
                   or nodes[key].get("statement_kind", "obligation") != "obligation" or key not in asserted for key in requirements)):
        raise ValueError("factor needs existing source requirement evidence")
    scope = feature_scope_from_record(occurrence["scope"])
    op, subjects, conditions = scope.operation_node_id, scope.subject_node_ids, scope.condition_node_ids
    object_coordinate = op in nodes and nodes[op]["concept_id"] == "task.root" and bool(subjects)
    if (op not in nodes or nodes[op]["node_type"] not in {"task_operation", "task"}
            or len(set(subjects)) != len(subjects) or len(set(conditions)) != len(conditions)
            or any(key not in nodes or nodes[key]["node_type"] != "data_object"
                   or not object_coordinate and (key, "used_by", op) not in links for key in subjects)
            or any(key not in nodes or nodes[key]["node_type"] != "condition" for key in conditions)):
        raise ValueError("factor scope must use source-bound operations, inputs and conditions")
    forms = {key: kind for key, kind, _ in source.get("requirement_structures", [])}
    envelopes = []
    execution = {a for a, relation, b in links if relation == "conditions" and b == op}
    for requirement in requirements:
        envelope = requirement_binding(requirement, links=links,
            node_types={key: node["node_type"] for key, node in nodes.items()},
            structures=source.get("requirement_structures", []),
            retained_scopes=source.get("retained_requirement_scopes", []),
            owned_relations=source.get("requirement_relations", []))
        object_bound = (envelope is not None and envelope["kind"] == "targets"
                        and not envelope["operations"] and bool(envelope["subjects"]))
        if (envelope is None or (not object_bound and op not in envelope["operations"])
                or object_bound != object_coordinate):
            raise ValueError("requirement evidence does not bind the complete proposed scope")
        if envelope["subjects"] != set(subjects):
            raise ValueError("candidate scope differs from the source requirement subject set")
        actual_conditions = execution | envelope["conditions"]
        if set(conditions) != actual_conditions:
            raise ValueError("candidate scope cannot discard or invent source conditions")
        envelopes.append(("objects" if object_bound else envelope["kind"],
                          envelope["target_class"], forms.get(requirement, "atom"),
                          tuple(sorted(envelope["relations"]))))
    if len(set(envelopes)) != 1:
        raise ValueError("normalization must preserve the whole scope and composition")
    requirement_types = {nodes[key]["node_type"] for key in requirements}
    if len(requirement_types) != 1:
        raise ValueError("semantic normalization cannot merge different requirement roles")
    # A positive binding may not be narrowed or broadened silently. Repeated occurrences
    # preserve the whole source atom and its operation/subject envelope.
    def semantic(key):
        node = nodes[key]
        if node["concept_id"] == "task.root":
            return "task.root"
        return aliases[node["node_type"] + "::" + node["concept_id"]]
    kind, target_class, requirement_kind, policy_relations = envelopes[0]
    selector = dict(operation_semantic_id=semantic(op),
                    subject_semantic_ids=sorted(semantic(key) for key in subjects),
                    condition_semantic_ids=sorted(semantic(key) for key in execution),
                    execution_condition_semantic_ids=sorted(semantic(key) for key in execution),
                    policy_condition_semantic_ids=sorted(semantic(key) for key in set(conditions) - execution),
                    scope_kind=kind, target_class=target_class, requirement_kind=requirement_kind,
                    match_rule="unique_source_geometry_match")
    if policy_relations:
        selector["policy_relations"] = sorted([semantic(a), rel, semantic(b)] for a, rel, b in policy_relations)
    evidence = dict(task_id=source["task_id"], prompt_tsg_id=source["prompt_tsg_id"],
                    requirement_node_ids=sorted(requirements), requirement_type=next(iter(requirement_types)),
                    scope=canonical_value(scope))
    if "applicability_scope" in occurrence:
        # This is an explicitly proposed, separately reviewed comparison coordinate;
        # it does not replace the source requirement's complete binding above.
        background = feature_scope_from_record(occurrence["applicability_scope"])
        anchor = background.operation_node_id
        connected = {op, *(key for a, _, b in policy_relations for key in (a, b))}
        guards = {a for a, rel, b in links if rel == "conditions" and b == anchor}
        root_anchor = anchor == op and nodes.get(anchor, {}).get("concept_id") == "task.root"
        if (anchor not in connected or anchor not in nodes
                or not root_anchor and nodes[anchor]["node_type"] != "task_operation"
                or background.subject_node_ids != tuple(sorted(set(background.subject_node_ids)))
                or background.condition_node_ids != tuple(sorted(guards))
                or root_anchor and (guards or set(background.subject_node_ids) != set(subjects))
                or any(key not in nodes or nodes[key]["node_type"] != "data_object"
                       or not root_anchor and (key, "used_by", anchor) not in links for key in background.subject_node_ids)):
            raise ValueError("applicability scope needs an exact source operation/input/execution binding connected to the policy")
        selector["applicability_scope"] = dict(operation_semantic_id=semantic(anchor),
            subject_semantic_ids=sorted(semantic(key) for key in background.subject_node_ids),
            execution_condition_semantic_ids=sorted(semantic(key) for key in guards))
        evidence["applicability_scope"] = canonical_value(background)
    if "applicability_support" in occurrence:
        if "applicability_scope" not in occurrence:
            raise ValueError("applicability support requires an explicit background coordinate")
        support = occurrence["applicability_support"]
        _fields(support, {"source_evidence", "rationale"}
                | ({"component_decisions"} if "component_decisions" in support else set()), "applicability support")
        require_text(support["rationale"], "independent applicability rationale")
        evidence_rows = [support]
        if "component_decisions" in support:
            components = support["component_decisions"]
            if not isinstance(components, list):
                raise ValueError("applicability component decisions must be an array")
            inputs = (set(subjects) if root_anchor else
                      {a for a, rel, b in links if rel == "used_by" and b == anchor})
            required = {anchor, *inputs, *guards}
            retained = {anchor, *background.subject_node_ids, *guards}
            seen = set()
            for item in components:
                _fields(item, {"node_id", "decision", "source_evidence", "rationale"},
                        "applicability component decision")
                key, decision = item["node_id"], item["decision"]
                if (not isinstance(key, str) or key not in required or key in seen
                        or decision not in {"retain", "omit_policy_dependent", "omit_not_needed"}
                        or (decision == "retain") != (key in retained)):
                    raise ValueError("applicability component decisions must account for the exact retained and omitted inputs")
                seen.add(key)
                require_text(item["rationale"], "applicability component rationale")
            if seen != required:
                raise ValueError("applicability component decisions must cover the operation, every input and execution guard")
            evidence_rows.extend(components)
        for row in evidence_rows:
            if not isinstance(row["source_evidence"], list) or not row["source_evidence"]:
                raise ValueError("independent applicability requires source evidence")
            for citation in row["source_evidence"]:
                _fields(citation, {"evidence_text", "occurrence"}, "independent applicability citation")
                require_text(citation["evidence_text"], "independent applicability quotation")
                if type(citation["occurrence"]) is not int or citation["occurrence"] < 1:
                    raise ValueError("independent applicability occurrence must be a positive integer")
                _occurrence_span(source["source_prompt"], citation["evidence_text"], citation["occurrence"])
        # Exact quotation proves source location only; the existing semantic reviewer
        # still decides whether it supports this actual background without the policy.
        evidence["applicability_support"] = canonical_value(support)
    return selector, evidence


def _query(selector: dict, feature_id: str) -> dict:
    background = selector.get("applicability_scope")
    coordinate = background or selector
    op = coordinate["operation_semantic_id"]
    subjects = coordinate["subject_semantic_ids"]
    conditions = (coordinate["execution_condition_semantic_ids"] if background
                  else coordinate["condition_semantic_ids"])
    endpoints = (set() if background else
                 {key for a, _, b in selector.get("policy_relations", []) for key in (a, b)})
    semantics = sorted({op, *subjects, *conditions, *endpoints})
    # An explicit background excludes policy operands from task selection. Without
    # one, preserve the original source geometry rather than inventing an anchor.
    execution = set(coordinate.get('execution_condition_semantic_ids', conditions))
    relations = sorted({(s, "used_by", op) for s in subjects if op != "task.root" and (background or selector["scope_kind"] != "objects")}
                       | {(c, "conditions" if c in execution else "context_for", op) for c in conditions})
    identity = content_hash(dict(required_semantics=semantics, required_relations=relations))
    return dict(query_id="context_" + identity, realization_id=content_id("candidate_query_", (identity, feature_id)),
                cwe_id="source_semantics", task_family="source_semantics", required_semantics=semantics,
                forbidden_semantics=[], required_relations=[list(r) for r in relations], actionable_feature_id=feature_id)


def compile_candidate_proposal(
    request: dict, response: dict, design: dict, review: dict | None = None
) -> dict:
    """Normalize complete requirements into scoped factors; missing review stays pending."""
    retained_response = response
    if isinstance(response, dict) and "decisions" in response:
        response = _expand_unit_decisions(request, response)
    _fields(response, {"factors", "dispositions"}, "candidate response")
    if not isinstance(response["factors"], list) or not isinstance(response["dispositions"], list):
        raise ValueError("candidate response needs arrays")
    if request.get("arms_or_outcomes_used") is not False:
        raise ValueError("candidate request must be source-only")
    if request.get("requirement_granularity") != "complete_single_requirement":
        raise ValueError(
            "candidate request must require complete single requirements; prepare a new request from the source TSG"
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
    decisions = _review_decisions(request, retained_response, proposals, review)
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
        response_sha256=content_hash(retained_response),
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
        "model-request.json": candidate_model_request(request),
        "prompt.json": _PROPOSER_PROMPT, "response-format.json": candidate_response_format(request), "input-catalog.json": input_catalog})
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
    model_request = candidate_model_request(request)
    model_request_path = request_bundle / "model-request.json"
    if model_request_path.exists() and read_json_exact(model_request_path) != model_request:
        raise ValueError("candidate model request does not preserve the source bindings")
    design = read_json_exact(design_path)
    _validate_design(design)
    raw, evaluator, calls = None, None, 0
    try:
        if response_path is not None:
            raw = response_path.read_bytes()
        else:
            from prompt_mechanism_study.llm import complete_chat

            if read_json_exact(request_bundle / "prompt.json") != _PROPOSER_PROMPT:
                raise ValueError("prepare a current binding-selection request before a new provider call")
            evaluator = _proposal_evaluator(evaluator_path)
            calls = 1
            raw = complete_chat(
                model_request,
                {**evaluator, "response_format": candidate_response_format(request)},
                read_json_exact(request_bundle / "prompt.json"),
            )
        response = json_object(raw)
        if evaluator_path is not None:
            # New model calls must use the current interface. Legacy four-field
            # parsing is available only when replaying a retained response.
            _fields(response, {"decisions"}, "requirement decision response")
            if not isinstance(response["decisions"], dict):
                raise ValueError("complete requirement decisions must be an object")
            for row in response["decisions"].values():
                _fields(row, {"status", "label", "definition", "rationale", "applicability_bindings"},
                        "current requirement decision")
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
                "model-request.json": model_request,
                "design.json": design,
                "evaluator.json": evaluator,
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
        "model-request.json": model_request,
        "response.json": response,
        "response-text.json": raw.decode("utf-8"),
        "design.json": design,
        "prompt.json": read_json_exact(request_bundle / "prompt.json"),
        "response-format.json": (candidate_response_format(request) if evaluator is not None
                                 else read_json_exact(request_bundle / "response-format.json")),
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
    # Action predicates and ground bindings must already be separated in the
    # development source records. Freezing must not silently rewrite their meaning.
    # Derived factors are source-grounded decompositions, not additional facts
    # retroactively asserted in input graphs. New scopes need fresh extraction.
    catalog = freeze_open_concepts(tuple(contracts), normalization_map=proposal["normalization_map"],
        definitions=definitions, queries=proposal["queries"],
        seed_semantics={**{k: v["node_type"] for k, v in fixed.items()}, **{f["feature_id"]: f["node_type"] for f in accepted}})
    catalog["feature_scope_selectors"] = {f["feature_id"]: f["scope_selector"] for f in accepted}
    return catalog_from_record(catalog)


def _proposal_evaluator(path):
    from prompt_mechanism_study.tsg.prompt_contract_extract import _evaluator
    evaluator = _evaluator(read_json_exact(path), path)
    if any(type(evaluator.get(key)) is not int or evaluator[key] <= 0
           for key in ("maximum_input_bytes", "max_response_bytes")) or not any(
               evaluator.get(key) for key in ("maximum_output_tokens", "maximum_completion_tokens")):
        raise ValueError("candidate proposal requires explicit finite input and output ceilings")
    return evaluator


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
