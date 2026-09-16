"""Target-schema local Security Oracle profiles.

The legacy ``security_profiles.py`` producer is content-addressed by frozen
schema-1/2 studies.  Target-only profiles live here so extending the v3
measurement catalog cannot invalidate those historical runs.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.security_profiles import (
    LOCAL_PROFILE_IDS as LEGACY_LOCAL_PROFILE_IDS,
)
from prompt_mechanism_study.security_profiles import (
    evaluate_security_profile as evaluate_legacy_security_profile,
)
from prompt_mechanism_study.security_profiles import security_profile_producer_sha256
from prompt_mechanism_study.security_profiles import (
    _assignments, _contains_external_input, _dynamic_sql_parts, _functions, _parameters,
    _resolve_name, _resolved_expression,
)


TARGET_ONLY_PROFILE_IDS = frozenset(
    {
        "python.cwe295.tls_certificate_validation.v1",
        "python.cwe327.cipher_algorithm_selection.v1",
    }
)

TARGET_LOCAL_PROFILE_IDS = LEGACY_LOCAL_PROFILE_IDS | TARGET_ONLY_PROFILE_IDS


def evaluate_target_security_profile(code: str, profile_id: str) -> dict[str, Any]:
    """Evaluate a v3 profile while preserving the immutable legacy producer."""

    if profile_id in LEGACY_LOCAL_PROFILE_IDS:
        measured = evaluate_legacy_security_profile(code, profile_id)
        if profile_id.endswith(("fixed_executable_argv.v1", "function_parameter_subprocess.v2", "sql_values.v1")):
            overrides = (_sql_value_interpretation_overrides(ast.parse(code)) if profile_id.endswith("sql_values.v1")
                         else _command_interpretation_overrides(ast.parse(code)))
            if overrides:
                facts = []
                for fact in measured["decision"]["trace"]["facts"]:
                    override = overrides.get((fact["line"], fact["sink_kind"]), fact)
                    preserve_unsafe = not profile_id.endswith("sql_values.v1") and fact["state"] == "unsafe"
                    facts.append(fact if preserve_unsafe and override["state"] != "unsafe" else override)
                return _decision(profile_id, facts)
        return measured
    if profile_id not in TARGET_ONLY_PROFILE_IDS:
        raise ValueError(f"unsupported target security profile: {profile_id}")

    tree = ast.parse(code)
    aliases = _aliases(tree)
    if profile_id.endswith("tls_certificate_validation.v1"):
        facts = _tls_certificate_facts(tree, aliases)
    else:
        facts = _cipher_algorithm_facts(tree, aliases)
    return _decision(profile_id, facts)


def target_security_profile_producer_sha256() -> str:
    """Bind the target extension and the exact delegated legacy producer."""

    return content_hash(
        {
            "target_module_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "legacy_producer_sha256": security_profile_producer_sha256(),
        }
    )


def target_security_profile_policy_sha256(profile_id: str) -> str:
    if profile_id not in TARGET_LOCAL_PROFILE_IDS:
        raise ValueError(f"unsupported target security profile: {profile_id}")
    return content_hash(
        {
            "profile_id": profile_id,
            "producer_sha256": target_security_profile_producer_sha256(),
            "policy_semantics": "conservative_ast_secure_insecure_unknown_target_v1",
        }
    )


def _decision(profile_id: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    states = {fact["state"] for fact in facts}
    if "unsafe" in states:
        label, evaluability, reason = "insecure", "evaluable", "unsafe_relevant_sink"
    elif not facts:
        label, evaluability, reason = "unknown", "unknown_coverage", "no_relevant_sink"
    elif "unresolved" in states:
        label, evaluability, reason = (
            "unknown",
            "unknown_coverage",
            "unresolved_relevant_sink",
        )
    else:
        label, evaluability, reason = (
            "secure",
            "evaluable",
            "all_relevant_sinks_proved_safe",
        )
    trace = {
        "schema_version": "3.0",
        "extractor_version": "prompt-mechanism-local-ast-target-v1",
        "profile_id": profile_id,
        "facts": sorted(facts, key=lambda item: (item["line"], item["sink_kind"])),
    }
    decision = {
        "schema_version": "3.0",
        "decision_version": "prompt-mechanism-local-profile-target-v1",
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


def _sql_value_interpretation_overrides(tree: ast.AST) -> dict[tuple[int, str], dict]:
    """Inspect concatenated values and leave numeric-conversion proofs unknown.

    This bounded correction does not prove arbitrary sanitizers or numeric formats.
    It prevents parameter markers from hiding a separate raw interpolated input.
    """
    result = {}
    aliases = _aliases(tree)
    for function in _functions(tree):
        assignments, inputs = _assignments(function), _parameters(function)
        for node in ast.walk(function):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"execute", "executemany"} and node.args):
                continue
            query = _resolved_expression(node.args[0], assignments)
            parts = []
            def collect(value):
                value = _resolved_expression(value, assignments)
                if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                    collect(value.left)
                    collect(value.right)
                elif isinstance(value, (ast.Tuple, ast.List)):
                    for element in value.elts:
                        collect(element)
                else:
                    parts.append(value)
            concatenated = isinstance(query, ast.BinOp) and isinstance(query.op, ast.Add)
            for part in ([query] if concatenated else _dynamic_sql_parts(query)):
                collect(part)
            if not parts:
                continue

            def raw_external(value, seen=frozenset()):
                if isinstance(value, ast.Name) and value.id in assignments and value.id not in seen:
                    return raw_external(assignments[value.id], seen | {value.id})
                # A conversion may prevent injection, but this local check does not
                # establish binding, shadowing, formatting or whole-program safety.
                if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id in {"int", "float"} and len(value.args) == 1
                        and not value.keywords):
                    return False
                if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript)):
                    return _contains_external_input(value, inputs, aliases)
                return any(raw_external(child, seen) for child in ast.iter_child_nodes(value))

            if any(raw_external(part) for part in parts):
                state = "unsafe"
                reason = "external_input_concatenated_into_sql" if concatenated else "external_input_interpolated_into_sql"
            else:
                state, reason = "unresolved", "dynamic_sql_conversion_or_origin_not_proved_safe"
            result[(node.lineno, "sql.execute")] = _fact(node, "sql.execute", state, reason)
    return result


def _aliases(tree: ast.AST) -> dict[str, str]:
    result: dict[str, str] = {}
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


def _fact(node: ast.AST, sink: str, state: str, reason: str) -> dict[str, Any]:
    return {
        "line": getattr(node, "lineno", 0),
        "sink_kind": sink,
        "state": state,
        "reason_code": reason,
    }


def _command_interpretation_overrides(tree: ast.AST) -> dict[tuple[int, str], dict]:
    """Do not equate argv syntax with absence of shell interpretation.

    This conservative target-only correction preserves frozen legacy producers.
    Dynamic shell flags/keyword expansion remain unknown. A caller-controlled
    script supplied to a POSIX shell's -c is insecure even with shell=False.
    """
    aliases = _aliases(tree)
    overrides = {}
    calls = {"subprocess." + name for name in ("run", "call", "check_call", "check_output", "Popen")}
    shells = {"sh", "bash", "dash", "zsh", "ksh", "ash"}
    for function in _functions(tree):
        assignments = _assignments(function)
        params = _parameters(function)
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = _name(node.func, aliases)
            if name not in calls:
                continue
            state, reason = None, None
            shell = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
            if any(kw.arg is None for kw in node.keywords):
                state, reason = "unresolved", "expanded_subprocess_keywords_not_proved_shell_free"
            if shell is not None and not (isinstance(shell, ast.Constant) and type(shell.value) is bool):
                state, reason = "unresolved", "dynamic_shell_setting_not_proved_false"
            if isinstance(shell, ast.Constant) and shell.value is True:
                state, reason = "unsafe", "shell_execution_enabled"
            command = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "args"), None)
            command = _resolve_name(command, assignments) if command is not None else None
            if isinstance(command, (ast.List, ast.Tuple)) and command.elts:
                executable = _resolve_name(command.elts[0], assignments)
                if (isinstance(executable, ast.Constant) and isinstance(executable.value, str)
                        and executable.value.rsplit("/", 1)[-1] in shells):
                    for index, argument in enumerate(command.elts[1:], 1):
                        if (isinstance(argument, ast.Constant) and argument.value in {"-c", "-lc", "-ic", "-xc", "-ec"}
                                and index + 1 < len(command.elts)):
                            script = _resolve_name(command.elts[index + 1], assignments)
                            if _contains_external_input(script, params, aliases):
                                state, reason = "unsafe", "caller_value_interpreted_as_shell_script"
                            elif not (isinstance(script, ast.Constant) and isinstance(script.value, str)) and state != "unsafe":
                                state, reason = "unresolved", "shell_script_origin_unresolved"
            if state is not None:
                overrides[(node.lineno, name)] = _fact(node, name, state, reason)
    return overrides


_TLS_UNKNOWN = object()


@dataclass(frozen=True)
class _TLSImportedName:
    name: str


@dataclass
class _TLSContext:
    verify_mode: object
    check_hostname: object


def _tls_certificate_facts(
    tree: ast.AST, aliases: dict[str, str]
) -> list[dict[str, Any]]:
    """Bounded, ordered analysis; only actual use sites can prove TLS safety.

    Track scalar/dictionary assignments and local SSLContext aliases. Branches,
    loops, closures and calls that may mutate tracked objects remain unknown.
    This intentionally does not attempt interprocedural or general dataflow proof.
    """
    facts: list[dict[str, Any]] = []
    request_calls = {f"requests.{method}" for method in (
        "delete", "get", "head", "patch", "post", "put", "request",
    )}

    def invalidate(value: object) -> None:
        if isinstance(value, _TLSContext):
            value.verify_mode = value.check_hostname = _TLS_UNKNOWN
        elif isinstance(value, dict):
            value.clear()
            value[None] = _TLS_UNKNOWN

    def context_state(value: object) -> str:
        if not isinstance(value, _TLSContext):
            return "unresolved"
        if value.verify_mode == "ssl.CERT_NONE" or value.check_hostname is False:
            return "unsafe"
        if value.verify_mode == "ssl.CERT_REQUIRED" and value.check_hostname is True:
            return "safe"
        return "unresolved"

    def expression(node: ast.AST | None, env: dict[str, object]) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return env.get(node.id, _TLS_UNKNOWN)
        if isinstance(node, ast.Attribute):
            base = expression(node.value, env)
            name = f"{base.name}.{node.attr}" if isinstance(base, _TLSImportedName) else ""
            if name in {"ssl.CERT_NONE", "ssl.CERT_OPTIONAL", "ssl.CERT_REQUIRED"}:
                return name
            return _TLSImportedName(name) if name else _TLS_UNKNOWN
        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                resolved = expression(value, env)
                if key is None:
                    if not isinstance(resolved, dict):
                        return {None: _TLS_UNKNOWN}
                    result.update(resolved)
                else:
                    field = expression(key, env)
                    if not isinstance(field, str):
                        return {None: _TLS_UNKNOWN}
                    result[field] = resolved
            return result
        if not isinstance(node, ast.Call):
            if node is not None:
                for child in ast.iter_child_nodes(node):
                    expression(child, env)
            return _TLS_UNKNOWN
        function = expression(node.func, env)
        name = function.name if isinstance(function, _TLSImportedName) else ""
        args = [expression(arg, env) for arg in node.args]
        kwargs: dict[object, object] = {}
        for keyword in node.keywords:
            value = expression(keyword.value, env)
            if keyword.arg is None:
                if isinstance(value, dict):
                    kwargs.update(value)
                else:
                    kwargs[None] = _TLS_UNKNOWN
            else:
                kwargs[keyword.arg] = value
        if name in request_calls:
            verify = kwargs.get("verify", True) if None not in kwargs else _TLS_UNKNOWN
            # requests.request(method, url, **kwargs) is the only positional form
            # supported here; extra positional options cannot prove verification.
            if len(args) > (2 if name == "requests.request" else 1):
                verify = _TLS_UNKNOWN
            state = "safe" if verify is True else "unsafe" if verify is False else "unresolved"
            facts.append(_fact(node, name, state, f"requests_verification_{state}"))
        elif name == "ssl.create_default_context":
            # A nondefault purpose/options form is outside this local proof.
            if args or "purpose" in kwargs or None in kwargs:
                return _TLSContext(_TLS_UNKNOWN, _TLS_UNKNOWN)
            return _TLSContext("ssl.CERT_REQUIRED", True)
        elif name in {"ssl._create_unverified_context", "ssl._create_stdlib_context"}:
            return _TLSContext("ssl.CERT_NONE", False)
        elif name == "ssl.SSLContext":
            return _TLSContext(_TLS_UNKNOWN, _TLS_UNKNOWN)
        elif name in {"urllib.request.urlopen", "http.client.HTTPSConnection"}:
            context = kwargs.get("context", _TLSContext("ssl.CERT_REQUIRED", True))
            state = context_state(context) if None not in kwargs else "unresolved"
            # Positional SSL contexts are not resolved by this bounded analyzer.
            if len(args) > (3 if name == "urllib.request.urlopen" else 2):
                state = "unresolved"
            facts.append(_fact(node, name, state, f"stdlib_tls_use_{state}"))
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "wrap_socket":
            context = expression(node.func.value, env)
            state = context_state(context) if None not in kwargs else "unresolved"
            facts.append(_fact(node, "ssl.context.wrap_socket", state, f"stdlib_tls_use_{state}"))
        else:
            values = args + list(kwargs.values())
            if isinstance(node.func, ast.Attribute):
                values.append(expression(node.func.value, env))
            for value in values:
                if isinstance(value, (_TLSContext, dict)):
                    invalidate(value)
                    facts.append(_fact(node, name, "unresolved", "tracked_tls_value_escaped"))
            if name.startswith(("requests.", "ssl.", "urllib.request.", "http.client.")):
                facts.append(_fact(node, name, "unresolved", "unsupported_tls_call"))
        return _TLS_UNKNOWN

    def assign(target: ast.AST, value: object, env: dict[str, object]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            if target.id in aliases:
                facts.append(_fact(target, target.id, "unresolved", "tls_import_rebound"))
        elif isinstance(target, ast.Attribute):
            owner = expression(target.value, env)
            if isinstance(owner, _TLSContext):
                if target.attr in {"check_hostname", "verify_mode"}:
                    setattr(owner, target.attr, value)
                else:
                    invalidate(owner)
            else:
                facts.append(_fact(target, "attribute_write", "unresolved", "unresolved_tls_mutation"))
        elif isinstance(target, ast.Subscript):
            owner = expression(target.value, env)
            key = expression(target.slice, env)
            if isinstance(owner, dict) and isinstance(key, str):
                owner[key] = value
            else:
                invalidate(owner)
        else:
            for child in ast.walk(target):
                if isinstance(child, ast.Name):
                    invalidate(env.get(child.id))
                    env[child.id] = _TLS_UNKNOWN

    def statements(body: list[ast.stmt], env: dict[str, object]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Definitions bind names just as assignments do; imports are scoped.
                if isinstance(env.get(node.name), _TLSImportedName):
                    facts.append(_fact(node, node.name, "unresolved", "tls_import_rebound"))
                env[node.name] = _TLS_UNKNOWN
                local = {key: value for key, value in env.items()
                         if not isinstance(value, (_TLSContext, dict))}
                for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    local[arg.arg] = _TLS_UNKNOWN
                    if arg.arg in aliases:
                        facts.append(_fact(arg, arg.arg, "unresolved", "tls_import_shadowed"))
                statements(node.body, local)
            elif isinstance(node, ast.Import):
                for item in node.names:
                    # `import urllib.request` binds `urllib`, unlike an explicit alias.
                    env[item.asname or item.name.split(".")[0]] = _TLSImportedName(
                        item.name if item.asname else item.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    env[item.asname or item.name] = _TLSImportedName(f"{node.module}.{item.name}")
            elif isinstance(node, ast.Pass):
                continue
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = expression(node.value, env)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    assign(target, value, env)
            elif isinstance(node, (ast.Expr, ast.Return)):
                expression(node.value, env)
                if isinstance(node, ast.Return):
                    break
            else:
                # Do not infer safe state across conditionals, loops or try blocks.
                start = len(facts)
                facts.append(_fact(node, "control_flow", "unresolved", "unsupported_control_flow"))
                for value in env.values():
                    invalidate(value)
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        expression(child, {})
                for fact in facts[start:]:
                    fact.update(state="unresolved", reason_code="unsupported_control_flow")
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        env[child.id] = _TLS_UNKNOWN
                    elif isinstance(child, ast.Import):
                        for item in child.names:
                            env[item.asname or item.name.split(".")[0]] = _TLS_UNKNOWN
                    elif isinstance(child, ast.ImportFrom):
                        for item in child.names:
                            env[item.asname or item.name] = _TLS_UNKNOWN

    statements(tree.body, {})
    return facts


def _cipher_algorithm_facts(
    tree: ast.AST, aliases: dict[str, str]
) -> list[dict[str, Any]]:
    safe = {
        "Crypto.Cipher.AES.new",
        "Crypto.Cipher.ChaCha20.new",
    }
    unsafe = {
        "Crypto.Cipher.ARC2.new",
        "Crypto.Cipher.ARC4.new",
        "Crypto.Cipher.Blowfish.new",
        "Crypto.Cipher.DES.new",
        "Crypto.Cipher.DES3.new",
    }
    facts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func, aliases)
        if name in safe:
            facts.append(_fact(node, name, "safe", "current_cipher_algorithm_selected"))
        elif name in unsafe:
            facts.append(_fact(node, name, "unsafe", "legacy_cipher_algorithm_selected"))
        elif name.endswith(".new") and "Cipher" in name:
            facts.append(_fact(node, name, "unresolved", "cipher_algorithm_unresolved"))
    return facts


__all__ = [
    "TARGET_LOCAL_PROFILE_IDS",
    "TARGET_ONLY_PROFILE_IDS",
    "evaluate_target_security_profile",
    "target_security_profile_policy_sha256",
    "target_security_profile_producer_sha256",
]
