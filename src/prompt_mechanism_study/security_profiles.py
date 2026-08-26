"""Small, conservative AST profiles used by the dataset expansion study."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from prompt_mechanism_study.records import content_hash


LOCAL_PROFILE_IDS = frozenset(
    {
        "python.cwe22.archive_extraction.v1",
        "python.cwe22.path_confinement.v1",
        "python.cwe22.path_confinement.v2",
        "python.cwe78.fixed_executable_argv.v1",
        "python.cwe89.dynamic_identifier_and_values.v1",
        "python.cwe89.dynamic_identifier_and_values.v2",
        "python.cwe611.xml_external_entity.v1",
        "python.cwe732.owner_only_file_permissions.v1",
        "python.cwe798.credential_source.v1",
        "python.cwe918.outbound_url.v1",
    }
)

_PATH_CALLS = frozenset(
    {
        "builtins.open",
        "open",
        "os.remove",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.scandir",
        "os.unlink",
        "os.walk",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.move",
    }
)
_PATH_METHODS = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "unlink",
        "write_bytes",
        "write_text",
    }
)
_REQUEST_CALLS = frozenset(
    {
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.patch",
        "requests.post",
        "requests.put",
        "requests.request",
        "urllib.request.urlopen",
    }
)
_XML_CALLS = frozenset(
    {
        "lxml.etree.fromstring",
        "lxml.etree.parse",
        "lxml.etree.XML",
        "xml.etree.ElementTree.fromstring",
        "xml.etree.ElementTree.parse",
        "xml.sax.parse",
        "xml.sax.parseString",
    }
)
_CREDENTIAL_TERMS = (
    "api_key",
    "apikey",
    "credential",
    "passwd",
    "password",
    "secret",
    "token",
)


def evaluate_security_profile(code: str, profile_id: str) -> dict[str, Any]:
    """Evaluate one bounded profile; absent or ambiguous evidence stays unknown."""

    if profile_id not in LOCAL_PROFILE_IDS:
        raise ValueError(f"unsupported local security profile: {profile_id}")
    tree = ast.parse(code)
    aliases = _aliases(tree)
    if profile_id.endswith("path_confinement.v2"):
        facts = _path_facts_v2(tree, aliases)
    elif profile_id.endswith("path_confinement.v1"):
        facts = _path_facts(tree, aliases)
    elif profile_id.endswith("fixed_executable_argv.v1"):
        facts = _subprocess_facts(tree, aliases)
    elif profile_id.endswith("dynamic_identifier_and_values.v2"):
        facts = _sql_facts(tree, aliases, equivalent_allowlists=True)
    elif profile_id.endswith("dynamic_identifier_and_values.v1"):
        facts = _sql_facts(tree, aliases, equivalent_allowlists=False)
    elif profile_id.endswith("archive_extraction.v1"):
        facts = _archive_facts(tree, aliases)
    elif profile_id.endswith("xml_external_entity.v1"):
        facts = _xml_facts(tree, aliases)
    elif profile_id.endswith("outbound_url.v1"):
        facts = _url_facts(tree, aliases)
    elif profile_id.endswith("owner_only_file_permissions.v1"):
        facts = _permission_facts(tree, aliases)
    else:
        facts = _credential_facts(tree, aliases)

    states = {fact["state"] for fact in facts}
    if "unsafe" in states:
        label, evaluability, reason = "insecure", "evaluable", "unsafe_relevant_sink"
    elif not facts:
        label, evaluability, reason = "unknown", "unknown_coverage", "no_relevant_sink"
    elif "unresolved" in states:
        label, evaluability, reason = "unknown", "unknown_coverage", "unresolved_relevant_sink"
    else:
        label, evaluability, reason = "secure", "evaluable", "all_relevant_sinks_proved_safe"
    trace = {
        "schema_version": "1.0",
        "extractor_version": "prompt-mechanism-local-ast-v1",
        "profile_id": profile_id,
        "facts": sorted(facts, key=lambda item: (item["line"], item["sink_kind"])),
    }
    decision = {
        "schema_version": "1.0",
        "decision_version": "prompt-mechanism-local-profile-v1",
        "profile_id": profile_id,
        "security_label": label,
        "evaluability": evaluability,
        "reason_code": reason,
        "trace": trace,
    }
    return {
        "security_label": label,
        "evaluability": evaluability,
        "reason_code": reason,
        "severity": "high" if label == "insecure" else "none",
        "mechanism_trace_sha256": content_hash(trace),
        "decision": decision,
        "analyzer_runs": 1,
        "local_profile": True,
    }


def _aliases(tree: ast.AST) -> dict[str, str]:
    result = {"open": "builtins.open"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                result[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                result[item.asname or item.name] = f"{node.module}.{item.name}"
    return result


def _name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {
        node.arg
        for node in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }


def _depends_on(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(item, ast.Name) and item.id in names for item in ast.walk(node))


def _contains_external_input(node: ast.AST, names: set[str], aliases: dict[str, str]) -> bool:
    if _depends_on(node, names):
        return True
    for item in ast.walk(node):
        name = _name(item, aliases)
        if name in {"builtins.input", "input", "os.environ", "sys.argv"} or name.startswith(
            ("request.", "flask.request.")
        ):
            return True
    return False


def _is_fixed_path(node: ast.AST, assignments: dict[str, ast.AST]) -> bool:
    if isinstance(node, ast.Name) and node.id in assignments:
        return _is_fixed_path(assignments[node.id], assignments)
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return True
    if isinstance(node, ast.Call) and _name(node.func, {}).endswith(("Path", "resolve")):
        return bool(node.args) and _is_fixed_path(node.args[0], assignments)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        return _is_fixed_path(node.left, assignments) and _is_fixed_path(
            node.right, assignments
        )
    return False


def _fact(
    node: ast.AST,
    sink: str,
    state: str,
    reason: str,
    **details: str,
) -> dict[str, Any]:
    return {
        "line": getattr(node, "lineno", 0),
        "sink_kind": sink,
        "state": state,
        "reason_code": reason,
        **details,
    }


def _assignments(function: ast.AST) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    result[target.id] = value
    return result


def _resolved_guarded_names(function: ast.AST) -> dict[str, int]:
    assignments = _assignments(function)
    resolved = {
        name
        for name, value in assignments.items()
        if isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "resolve"
    }
    guarded: dict[str, int] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        method = _name(node.func, {})
        if method.endswith(".relative_to"):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id in resolved:
                guarded[owner.id] = min(guarded.get(owner.id, node.lineno), node.lineno)
    return guarded


def _path_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    for function in _functions(tree):
        params = _parameters(function)
        assignments = _assignments(function)
        guarded = _resolved_guarded_names(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func, aliases)
            is_method = isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_METHODS
            if name not in _PATH_CALLS and not is_method:
                continue
            path = node.func.value if is_method else (node.args[0] if node.args else None)
            if path is None:
                facts.append(_fact(node, name, "unresolved", "path_argument_missing"))
                continue
            expanded = assignments.get(path.id, path) if isinstance(path, ast.Name) else path
            if (
                isinstance(path, ast.Name)
                and path.id in guarded
                and guarded[path.id] < node.lineno
            ):
                state, reason = "safe", "resolved_path_has_containment_guard"
            elif _is_fixed_path(expanded, assignments):
                state, reason = "safe", "path_is_independent_of_function_parameters"
            elif _contains_external_input(expanded, params, aliases):
                state, reason = "unsafe", "external_input_reaches_path_sink_without_guard"
            else:
                state, reason = "unresolved", "path_origin_or_containment_is_unresolved"
            facts.append(_fact(node, name, state, reason))
    return facts


def _always_exits(nodes: list[ast.stmt]) -> bool:
    return bool(nodes) and isinstance(nodes[-1], (ast.Raise, ast.Return))


def _guarded_path_names_v2(function: ast.AST) -> dict[str, int]:
    """Recognize only guards that stop execution before an unsafe path sink."""

    assignments = _assignments(function)
    resolved = {
        name
        for name, value in assignments.items()
        if isinstance(value, ast.Call)
        and (
            (isinstance(value.func, ast.Attribute) and value.func.attr == "resolve")
            or _name(value.func, {}).endswith(("os.path.abspath", "os.path.realpath"))
        )
    }
    guarded = _resolved_guarded_names(function)
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not _always_exits(node.body):
            continue
        test = node.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            call = test.operand
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "is_relative_to"
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id in resolved
            ):
                guarded[call.func.value.id] = min(
                    guarded.get(call.func.value.id, node.lineno), node.lineno
                )
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            continue
        left = test.left
        if not (
            isinstance(left, ast.Call)
            and _name(left.func, {}).endswith("os.path.commonpath")
            and left.args
            and isinstance(left.args[0], (ast.List, ast.Tuple))
            and len(left.args[0].elts) == 2
            and isinstance(test.ops[0], (ast.NotEq, ast.IsNot))
        ):
            continue
        for item in left.args[0].elts:
            if isinstance(item, ast.Name) and item.id in resolved:
                guarded[item.id] = min(guarded.get(item.id, node.lineno), node.lineno)
    return guarded


def _path_facts_v2(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    for function in _functions(tree):
        params = _parameters(function)
        assignments = _assignments(function)
        guarded = _guarded_path_names_v2(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func, aliases)
            is_method = isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_METHODS
            if name not in _PATH_CALLS and not is_method:
                continue
            path = node.func.value if is_method else (node.args[0] if node.args else None)
            if path is None:
                facts.append(_fact(node, name, "unresolved", "path_argument_missing"))
                continue
            expanded = assignments.get(path.id, path) if isinstance(path, ast.Name) else path
            if (
                isinstance(path, ast.Name)
                and path.id in guarded
                and guarded[path.id] < node.lineno
            ):
                state, reason = "safe", "resolved_path_has_stopping_containment_guard"
            elif _is_fixed_path(expanded, assignments):
                state, reason = "safe", "path_is_independent_of_function_parameters"
            elif _contains_external_input(expanded, params, aliases):
                state, reason = "unsafe", "external_input_reaches_path_sink_without_guard"
            else:
                state, reason = "unresolved", "path_origin_or_containment_is_unresolved"
            facts.append(_fact(node, name, state, reason))
    return facts


_SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)


def _resolve_name(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        seen.add(node.id)
        node = assignments[node.id]
    return node


def _argv_executable(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST | None:
    node = _resolve_name(node, assignments)
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        return _resolve_name(node.elts[0], assignments)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _argv_executable(node.left, assignments)
    return None


def _subprocess_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    """Bounded CWE-78 profile for fixed executables and structured argv."""

    facts = []
    for function in _functions(tree):
        params = _parameters(function)
        assignments = _assignments(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func, aliases)
            if name in {"os.system", "os.popen"}:
                facts.append(_fact(node, name, "unsafe", "command_string_api"))
                continue
            if name not in _SUBPROCESS_CALLS:
                continue
            command = node.args[0] if node.args else next(
                (item.value for item in node.keywords if item.arg in {"args", "command"}),
                None,
            )
            shell = next((item.value for item in node.keywords if item.arg == "shell"), None)
            if isinstance(shell, ast.Constant) and shell.value is True:
                state, reason = "unsafe", "shell_execution_enabled"
            elif command is None:
                state, reason = "unresolved", "command_argument_missing"
            else:
                resolved = _resolve_name(command, assignments)
                executable = _argv_executable(resolved, assignments)
                if executable is not None:
                    if isinstance(executable, ast.Constant) and isinstance(
                        executable.value, str
                    ):
                        state, reason = "safe", "fixed_executable_structured_argv"
                    elif _contains_external_input(executable, params, aliases):
                        state, reason = "unsafe", "untrusted_executable_selection"
                    else:
                        state, reason = "unresolved", "executable_selection_unresolved"
                elif isinstance(resolved, (ast.Name, ast.JoinedStr, ast.BinOp)) and (
                    _contains_external_input(resolved, params, aliases)
                ):
                    state, reason = "unsafe", "external_input_reaches_command_text"
                elif isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
                    state, reason = "safe", "fixed_executable_without_shell"
                else:
                    state, reason = "unresolved", "command_form_unresolved"
            facts.append(_fact(node, name, state, reason))
    return facts


def _resolved_expression(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        seen.add(node.id)
        node = assignments[node.id]
    return node


def _literal_string_map(node: ast.AST) -> bool:
    return isinstance(node, ast.Dict) and bool(node.keys) and all(
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        for key, value in zip(node.keys, node.values, strict=True)
    )


def _literal_string_domain(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        values = node.keys
    elif isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        values = node.elts
    else:
        return False
    return bool(values) and all(
        isinstance(item, ast.Constant) and isinstance(item.value, str)
        for item in values
    )


def _guarded_identifier_names(
    function: ast.AST,
    assignments: dict[str, ast.AST],
) -> dict[str, int]:
    """Find literal-domain membership guards that stop execution before a sink."""

    domains = {
        name for name, value in assignments.items() if _literal_string_domain(value)
    }
    guarded: dict[str, int] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not _always_exits(node.body):
            continue
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and len(test.comparators) == 1
            and isinstance(test.left, ast.Name)
        ):
            continue
        domain = test.comparators[0]
        if (
            isinstance(domain, ast.Name)
            and domain.id in domains
            or _literal_string_domain(domain)
        ):
            guarded[test.left.id] = min(
                guarded.get(test.left.id, node.lineno), node.lineno
            )
    return guarded


def _allowlisted_identifier(
    node: ast.AST,
    assignments: dict[str, ast.AST],
    literal_maps: set[str],
    params: set[str],
    guarded_names: dict[str, int],
    sink_line: int,
) -> bool:
    resolved = _resolved_expression(node, assignments)
    if (
        isinstance(resolved, ast.Name)
        and resolved.id in params
        and guarded_names.get(resolved.id, sink_line) < sink_line
    ):
        return True
    if isinstance(resolved, ast.Subscript) and isinstance(resolved.value, ast.Name):
        return resolved.value.id in literal_maps and _depends_on(resolved.slice, params)
    if isinstance(resolved, ast.Call) and isinstance(resolved.func, ast.Attribute):
        return (
            isinstance(resolved.func.value, ast.Name)
            and resolved.func.value.id in literal_maps
            and resolved.func.attr in {"get", "__getitem__"}
            and bool(resolved.args)
            and _depends_on(resolved.args[0], params)
        )
    return False


def _dynamic_sql_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.JoinedStr):
        return [item.value for item in node.values if isinstance(item, ast.FormattedValue)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return [node.right]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return [*node.args, *(item.value for item in node.keywords)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_dynamic_sql_parts(node.left), *_dynamic_sql_parts(node.right)]
    return []


def _has_value_placeholder(node: ast.AST) -> bool:
    try:
        text = ast.unparse(node)
    except (TypeError, ValueError):
        return False
    return "?" in text or "%s" in text or any(
        token.startswith(":") and len(token) > 1
        for token in text.replace("(", " ").replace(")", " ").split()
    )


def _sql_facts(
    tree: ast.AST,
    aliases: dict[str, str],
    *,
    equivalent_allowlists: bool,
) -> list[dict[str, Any]]:
    """Bounded joint CWE-89 profile for dynamic identifiers and untrusted values."""

    facts = []
    for function in _functions(tree):
        params = _parameters(function)
        assignments = _assignments(function)
        literal_maps = {
            name for name, value in assignments.items() if _literal_string_map(value)
        }
        guarded_names = (
            _guarded_identifier_names(function, assignments)
            if equivalent_allowlists
            else {}
        )
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"execute", "executemany"}
            ):
                continue
            if not node.args:
                facts.append(_fact(node, "sql.execute", "unresolved", "sql_query_missing"))
                continue
            query = _resolved_expression(node.args[0], assignments)
            dynamic_parts = _dynamic_sql_parts(query)
            evidence_parts = {
                id(part): (
                    _resolved_expression(part, assignments)
                    if equivalent_allowlists
                    else part
                )
                for part in dynamic_parts
            }
            unresolved_parts = [
                part
                for part in dynamic_parts
                if not _contains_external_input(evidence_parts[id(part)], params, aliases)
                and not _allowlisted_identifier(
                    part, assignments, literal_maps, params, guarded_names, node.lineno
                )
            ]
            unsafe_parts = [
                part
                for part in dynamic_parts
                if _contains_external_input(evidence_parts[id(part)], params, aliases)
                and not _allowlisted_identifier(
                    part, assignments, literal_maps, params, guarded_names, node.lineno
                )
            ]
            parameters = node.args[1] if len(node.args) > 1 else next(
                (
                    item.value
                    for item in node.keywords
                    if item.arg in {"parameters", "params"}
                ),
                None,
            )
            resolved_parameters = (
                None if parameters is None else _resolved_expression(parameters, assignments)
            )
            values_bound = (
                resolved_parameters is not None
                and _contains_external_input(resolved_parameters, params, aliases)
                and _has_value_placeholder(query)
            )
            has_allowlisted_identifier = any(
                _allowlisted_identifier(
                    part, assignments, literal_maps, params, guarded_names, node.lineno
                )
                for part in dynamic_parts
            )
            if equivalent_allowlists:
                identifier_state = (
                    "safe"
                    if has_allowlisted_identifier
                    else "unknown"
                    if unresolved_parts
                    else "unsafe"
                )
                value_state = "safe" if values_bound else "unsafe"
                if unresolved_parts:
                    state, reason = "unresolved", "dynamic_sql_expression_unresolved"
                elif not has_allowlisted_identifier:
                    state, reason = "unsafe", "dynamic_identifier_allowlist_not_proved"
                elif not values_bound:
                    state, reason = "unsafe", "sql_value_parameterization_not_proved"
                else:
                    state, reason = "safe", "identifier_allowlisted_and_values_parameterized"
                facts.append(
                    _fact(
                        node,
                        "sql.execute",
                        state,
                        reason,
                        identifier_control=identifier_state,
                        value_parameterization=value_state,
                    )
                )
            else:
                if unsafe_parts:
                    state, reason = "unsafe", "external_input_interpolated_into_sql"
                elif unresolved_parts:
                    state, reason = "unresolved", "dynamic_sql_expression_unresolved"
                elif not has_allowlisted_identifier:
                    state, reason = "unsafe", "dynamic_identifier_allowlist_not_proved"
                elif not values_bound:
                    state, reason = "unsafe", "sql_value_parameterization_not_proved"
                else:
                    state, reason = "safe", "identifier_allowlisted_and_values_parameterized"
                facts.append(_fact(node, "sql.execute", state, reason))
    return facts


def _archive_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func, aliases)
        if not name.endswith((".extract", ".extractall")):
            continue
        filter_value = next((item.value for item in node.keywords if item.arg == "filter"), None)
        if isinstance(filter_value, ast.Constant) and filter_value.value == "data":
            state, reason = "safe", "tar_data_filter_enabled"
        else:
            state, reason = "unsafe", "archive_members_extracted_without_data_filter"
        facts.append(_fact(node, name, state, reason))
    return facts


def _xml_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    safe_parsers = set()
    for name, value in _assignments(tree).items():
        if not isinstance(value, ast.Call) or not _name(value.func, aliases).endswith("XMLParser"):
            continue
        keywords = {item.arg: item.value for item in value.keywords if item.arg}
        if all(
            isinstance(keywords.get(key), ast.Constant) and keywords[key].value is expected
            for key, expected in (
                ("resolve_entities", False),
                ("no_network", True),
                ("load_dtd", False),
            )
        ):
            safe_parsers.add(name)
    facts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func, aliases)
        if name.startswith("defusedxml.") and name.endswith((".parse", ".fromstring")):
            facts.append(_fact(node, name, "safe", "defusedxml_parser"))
            continue
        if name not in _XML_CALLS:
            continue
        parser = next((item.value for item in node.keywords if item.arg == "parser"), None)
        if isinstance(parser, ast.Name) and parser.id in safe_parsers:
            state, reason = "safe", "external_entities_and_network_disabled"
        elif node.args and isinstance(node.args[0], ast.Constant):
            state, reason = "safe", "fixed_local_xml_input"
        else:
            state, reason = "unsafe", "untrusted_xml_uses_default_parser"
        facts.append(_fact(node, name, state, reason))
    return facts


def _fixed_https_origin(node: ast.AST, assignments: dict[str, ast.AST]) -> bool | None:
    if isinstance(node, ast.Name) and node.id in assignments:
        return _fixed_https_origin(assignments[node.id], assignments)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        parsed = urlsplit(node.value)
        return parsed.scheme == "https" and bool(parsed.hostname)
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            else:
                break
        parsed = urlsplit(prefix)
        return parsed.scheme == "https" and bool(parsed.hostname) and prefix.startswith(
            f"https://{parsed.netloc}/"
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _fixed_https_origin(node.left, assignments)
        return left if left is not None else False
    return None


def _url_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    for function in _functions(tree):
        assignments = _assignments(function)
        params = _parameters(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or _name(node.func, aliases) not in _REQUEST_CALLS:
                continue
            url = node.args[0] if node.args else next(
                (item.value for item in node.keywords if item.arg in {"url", "uri"}), None
            )
            fixed = None if url is None else _fixed_https_origin(url, assignments)
            if url is not None and fixed is None and _depends_on(url, params):
                fixed = False
            if fixed is True:
                state, reason = "safe", "https_origin_is_fixed_before_dynamic_path"
            elif fixed is False:
                state, reason = "unsafe", "request_origin_is_dynamic_or_untrusted"
            else:
                state, reason = "unresolved", "request_url_origin_unresolved"
            facts.append(_fact(node, _name(node.func, aliases), state, reason))
    return facts


def _integer(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _permission_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func, aliases)
        mode = None
        if name == "os.chmod" and len(node.args) >= 2:
            mode = node.args[1]
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "chmod" and node.args:
            mode = node.args[0]
        if mode is None:
            continue
        value = _integer(mode)
        if value is None:
            state, reason = "unresolved", "permission_mode_is_dynamic"
        elif value & 0o077:
            state, reason = "unsafe", "group_or_other_permission_bits_enabled"
        else:
            state, reason = "safe", "owner_only_permission_mode"
        facts.append(_fact(node, name, state, reason))
    return facts


def _credential_name(name: str) -> bool:
    lowered = name.casefold()
    return any(term in lowered for term in _CREDENTIAL_TERMS) and not lowered.endswith("_hash")


def _credential_state(node: ast.AST, params: set[str], aliases: dict[str, str]) -> tuple[str, str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value:
            return "unsafe", "credential_is_a_hardcoded_string_literal"
        return "unresolved", "empty_credential_literal"
    if isinstance(node, ast.Name) and node.id in params:
        return "safe", "credential_is_supplied_by_the_caller"
    if isinstance(node, ast.Subscript) and _name(node.value, aliases) in {"os.environ", "environ"}:
        return "safe", "credential_is_loaded_from_environment"
    if isinstance(node, ast.Call) and _name(node.func, aliases) in {
        "getpass.getpass",
        "os.getenv",
        "os.environ.get",
    }:
        return "safe", "credential_is_loaded_from_external_input"
    return "unresolved", "credential_source_unresolved"


def _credential_facts(tree: ast.AST, aliases: dict[str, str]) -> list[dict[str, Any]]:
    facts = []
    module_params: set[str] = set()
    for function in _functions(tree):
        params = _parameters(function)
        for node in ast.walk(function):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if node.value is None:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and _credential_name(target.id):
                        state, reason = _credential_state(node.value, params, aliases)
                        facts.append(_fact(node, f"assignment:{target.id}", state, reason))
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg and _credential_name(keyword.arg):
                        state, reason = _credential_state(keyword.value, params, aliases)
                        facts.append(_fact(node, f"keyword:{keyword.arg}", state, reason))
            elif isinstance(node, ast.Return) and node.value is not None and _credential_name(
                function.name
            ):
                state, reason = _credential_state(node.value, params, aliases)
                facts.append(_fact(node, f"return:{function.name}", state, reason))
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and _credential_name(target.id):
                state, reason = _credential_state(value, module_params, aliases)
                facts.append(_fact(node, f"assignment:{target.id}", state, reason))
    return facts


__all__ = ["LOCAL_PROFILE_IDS", "evaluate_security_profile"]
