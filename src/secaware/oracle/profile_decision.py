"""Bounded, profile-scoped Oracle decisions over a finite Python mechanism trace."""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import hashlib
from typing import Literal, Protocol, Sequence

from secaware.schema.oracle import (
    AnalyzerFindingRecord,
    OracleEvaluability,
    SecurityLabel,
)


MECHANISM_EXTRACTOR_VERSION = "python-function-local-mechanism-v1"
PROFILE_DECISION_VERSION = "profile-scoped-oracle-decision-v1"

_COMMAND_SINKS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)
_SUBPROCESS_SINKS = frozenset(item for item in _COMMAND_SINKS if item.startswith("subprocess."))
_SQL_METHODS = frozenset({"execute", "executemany", "executescript"})
_TERMINAL_STATEMENTS = (ast.Raise, ast.Return)

SinkState = Literal["safe", "unsafe", "unresolved"]


@dataclass(frozen=True, slots=True)
class OracleMechanismSinkFact:
    cwe: Literal["CWE-78", "CWE-89"]
    function_name: str
    line: int
    sink_kind: str
    state: SinkState
    source_names: tuple[str, ...]
    properties: tuple[str, ...]
    reason_code: str


@dataclass(frozen=True, slots=True)
class OracleMechanismTrace:
    schema_version: Literal["1.0"]
    extractor_version: Literal["python-function-local-mechanism-v1"]
    language: Literal["python"]
    analysis_scope: Literal["single_file_function_local"]
    code_sha256: str
    parse_ok: bool
    sink_facts: tuple[OracleMechanismSinkFact, ...]


@dataclass(frozen=True, slots=True)
class OracleProfileDecision:
    schema_version: Literal["1.0"]
    decision_version: Literal["profile-scoped-oracle-decision-v1"]
    profile_id: str
    cwe: str
    security_label: SecurityLabel
    evaluability: OracleEvaluability
    severity: Literal["none", "low", "medium", "high"]
    findings: tuple[AnalyzerFindingRecord, ...]
    raw_findings: tuple[AnalyzerFindingRecord, ...]
    mechanism_trace: OracleMechanismTrace
    reason_code: str


class _Profile(Protocol):
    profile_id: str
    cwe: str
    zero_finding_supported: bool
    analyzer_rule_ids: tuple[str, ...]
    decision_backend: str


@dataclass(frozen=True, slots=True)
class _ExprState:
    sources: frozenset[str] = frozenset()
    allowlisted_sources: frozenset[str] = frozenset()
    constant: bool = False
    finite_mapping: bool = False
    finite_collection: bool = False
    form: str = "unknown"
    elements: tuple["_ExprState", ...] = ()
    unknown: bool = False


def _merge_states(*states: _ExprState, form: str, unknown: bool = False) -> _ExprState:
    return _ExprState(
        sources=frozenset().union(*(item.sources for item in states)),
        allowlisted_sources=frozenset().union(*(item.allowlisted_sources for item in states)),
        constant=bool(states) and all(item.constant for item in states),
        form=form,
        unknown=unknown or any(item.unknown for item in states),
    )


def _qualified_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _all_sources_allowlisted(state: _ExprState) -> bool:
    return bool(state.sources) and state.sources <= state.allowlisted_sources


class _FunctionAnalyzer:
    def __init__(self, aliases: dict[str, str], function_name: str) -> None:
        self.aliases = aliases
        self.function_name = function_name
        self.env: dict[str, _ExprState] = {}
        self.facts: list[OracleMechanismSinkFact] = []

    def seed_parameters(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        arguments = (
            tuple(node.args.posonlyargs) + tuple(node.args.args) + tuple(node.args.kwonlyargs)
        )
        for argument in arguments:
            self.env[argument.arg] = _ExprState(
                sources=frozenset({f"parameter:{argument.arg}"}),
                form="source",
            )
        if node.args.vararg is not None:
            name = node.args.vararg.arg
            self.env[name] = _ExprState(sources=frozenset({f"parameter:{name}"}), form="source")
        if node.args.kwarg is not None:
            name = node.args.kwarg.arg
            self.env[name] = _ExprState(sources=frozenset({f"parameter:{name}"}), form="source")

    def analyze(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            self._statement(statement)

    def _statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(statement, ast.Assign):
            state = self._expr(statement.value)
            for target in statement.targets:
                self._assign(target, state)
            return
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._assign(statement.target, self._expr(statement.value))
            return
        if isinstance(statement, ast.AugAssign):
            current = self._expr(statement.target)
            value = self._expr(statement.value)
            self._assign(statement.target, _merge_states(current, value, form="formatted"))
            return
        if isinstance(statement, ast.Expr):
            self._expr(statement.value)
            return
        if isinstance(statement, (ast.Return, ast.Raise)):
            value = getattr(statement, "value", None) or getattr(statement, "exc", None)
            if value is not None:
                self._expr(value)
            return
        if isinstance(statement, ast.If):
            self._expr(statement.test)
            guarded = self._fail_closed_allowlist(statement)
            body_analyzer = self._fork()
            body_analyzer.analyze(statement.body)
            self.facts.extend(body_analyzer.facts)
            else_analyzer = self._fork()
            else_analyzer.analyze(statement.orelse)
            self.facts.extend(else_analyzer.facts)
            if guarded is not None:
                current = self.env.get(guarded, _ExprState(unknown=True))
                self.env[guarded] = replace(
                    current,
                    allowlisted_sources=current.allowlisted_sources | current.sources,
                    form="allowlisted",
                )
            else:
                self._merge_branch_environments(body_analyzer.env, else_analyzer.env)
            return
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            iterable = self._expr(statement.iter)
            loop_analyzer = self._fork()
            loop_analyzer._assign(statement.target, replace(iterable, unknown=True))
            loop_analyzer.analyze(statement.body)
            loop_analyzer.analyze(statement.orelse)
            self.facts.extend(loop_analyzer.facts)
            self._merge_branch_environments(self.env, loop_analyzer.env)
            return
        if isinstance(statement, ast.While):
            self._expr(statement.test)
            loop_analyzer = self._fork()
            loop_analyzer.analyze(statement.body)
            loop_analyzer.analyze(statement.orelse)
            self.facts.extend(loop_analyzer.facts)
            self._merge_branch_environments(self.env, loop_analyzer.env)
            return
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                state = self._expr(item.context_expr)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, state)
            self.analyze(statement.body)
            return
        if isinstance(statement, ast.Try):
            branches = [statement.body, *(handler.body for handler in statement.handlers)]
            analyzers = []
            for branch in branches:
                branch_analyzer = self._fork()
                branch_analyzer.analyze(branch)
                self.facts.extend(branch_analyzer.facts)
                analyzers.append(branch_analyzer)
            if analyzers:
                merged = analyzers[0].env
                for analyzer in analyzers[1:]:
                    self._merge_branch_environments(merged, analyzer.env)
                self._merge_branch_environments(self.env, merged)
            self.analyze(statement.orelse)
            self.analyze(statement.finalbody)
            return
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._expr(child)

    def _fork(self) -> "_FunctionAnalyzer":
        result = _FunctionAnalyzer(self.aliases, self.function_name)
        result.env = dict(self.env)
        return result

    def _merge_branch_environments(
        self, first: dict[str, _ExprState], second: dict[str, _ExprState]
    ) -> None:
        for name in set(first) | set(second):
            left = first.get(name, _ExprState(unknown=True))
            right = second.get(name, _ExprState(unknown=True))
            self.env[name] = _merge_states(left, right, form="branch", unknown=True)

    def _assign(self, target: ast.AST, state: _ExprState) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = state
        elif isinstance(target, (ast.Tuple, ast.List)):
            for index, element in enumerate(target.elts):
                item = (
                    state.elements[index]
                    if index < len(state.elements)
                    else replace(state, unknown=True)
                )
                self._assign(element, item)

    def _fail_closed_allowlist(self, statement: ast.If) -> str | None:
        test = statement.test
        if (
            statement.orelse
            or not statement.body
            or not isinstance(statement.body[-1], _TERMINAL_STATEMENTS)
        ):
            return None
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
            return None
        if not isinstance(test.ops[0], ast.NotIn) or not isinstance(test.left, ast.Name):
            return None
        collection = self._expr(test.comparators[0])
        return test.left.id if collection.finite_collection or collection.finite_mapping else None

    def _expr(self, node: ast.AST) -> _ExprState:
        if isinstance(node, ast.Constant):
            return _ExprState(constant=True, form="constant")
        if isinstance(node, ast.Name):
            return self.env.get(node.id, _ExprState(form="name", unknown=True))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elements = tuple(self._expr(item) for item in node.elts)
            merged = (
                _merge_states(*elements, form="sequence")
                if elements
                else _ExprState(constant=True, form="sequence")
            )
            return replace(
                merged,
                finite_collection=all(item.constant for item in elements),
                elements=elements,
            )
        if isinstance(node, ast.Dict):
            keys = tuple(self._expr(item) for item in node.keys if item is not None)
            values = tuple(self._expr(item) for item in node.values)
            states = keys + values
            merged = (
                _merge_states(*states, form="mapping")
                if states
                else _ExprState(constant=True, form="mapping")
            )
            finite = all(item.constant for item in states)
            return replace(merged, finite_mapping=finite, finite_collection=finite)
        if isinstance(node, ast.Subscript):
            qualified = _qualified_name(node.value, self.aliases)
            if qualified in {"sys.argv", "os.environ"}:
                return _ExprState(sources=frozenset({qualified}), form="source")
            container = self._expr(node.value)
            key = self._expr(node.slice)
            if container.finite_mapping:
                return _ExprState(
                    sources=key.sources,
                    allowlisted_sources=key.sources | key.allowlisted_sources,
                    constant=True,
                    form="finite_mapping_lookup",
                )
            return _merge_states(container, key, form="subscript", unknown=True)
        if isinstance(node, ast.JoinedStr):
            values = tuple(
                self._expr(item.value) if isinstance(item, ast.FormattedValue) else self._expr(item)
                for item in node.values
            )
            return _merge_states(*values, form="formatted")
        if isinstance(node, ast.BinOp):
            return _merge_states(self._expr(node.left), self._expr(node.right), form="formatted")
        if isinstance(node, ast.UnaryOp):
            return self._expr(node.operand)
        if isinstance(node, ast.BoolOp):
            return _merge_states(*(self._expr(item) for item in node.values), form="boolean")
        if isinstance(node, ast.Compare):
            return _merge_states(
                self._expr(node.left),
                *(self._expr(item) for item in node.comparators),
                form="boolean",
            )
        if isinstance(node, ast.IfExp):
            return _merge_states(
                self._expr(node.body), self._expr(node.orelse), form="branch", unknown=True
            )
        if isinstance(node, ast.Attribute):
            return self._expr(node.value)
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            states = [
                self._expr(child)
                for child in ast.iter_child_nodes(node)
                if isinstance(child, ast.expr)
            ]
            return (
                _merge_states(*states, form="comprehension", unknown=True)
                if states
                else _ExprState(unknown=True)
            )
        return _ExprState(unknown=True)

    def _call(self, node: ast.Call) -> _ExprState:
        name = _qualified_name(node.func, self.aliases)
        args = tuple(self._expr(item) for item in node.args)
        kwargs = {
            item.arg: self._expr(item.value) for item in node.keywords if item.arg is not None
        }
        if name in _COMMAND_SINKS:
            self._command_sink(node, name, args, kwargs)
        elif name.rsplit(".", 1)[-1] in _SQL_METHODS:
            self._sql_sink(node, name, args, kwargs)
        if name in {"input", "builtins.input"}:
            return _ExprState(sources=frozenset({"stdin"}), form="source")
        if name in {"os.getenv", "os.environ.get"}:
            return _ExprState(sources=frozenset({"environment"}), form="source")
        if any(
            name.endswith(suffix) for suffix in (".args.get", ".form.get", ".get_json", ".get_data")
        ):
            return _ExprState(sources=frozenset({"request"}), form="source")
        if name.endswith(".format"):
            owner = (
                self._expr(node.func.value)
                if isinstance(node.func, ast.Attribute)
                else _ExprState()
            )
            return _merge_states(owner, *args, *kwargs.values(), form="formatted")
        if name in {"str", "int", "float", "bytes", "bool"} and args:
            return replace(args[0], form="converted")
        if name == "shlex.quote" and args:
            return replace(args[0], form="shell_quoted", unknown=True)
        states = args + tuple(kwargs.values())
        return (
            _merge_states(*states, form="call_result", unknown=True)
            if states
            else _ExprState(form="call_result", unknown=True)
        )

    def _command_sink(
        self,
        node: ast.Call,
        name: str,
        args: tuple[_ExprState, ...],
        kwargs: dict[str, _ExprState],
    ) -> None:
        command = args[0] if args else kwargs.get("args", _ExprState(unknown=True))
        properties = [f"command_form:{command.form}"]
        if name in {"os.system", "os.popen"}:
            properties.append("shell_mode:true")
            if command.unknown:
                state, reason = "unresolved", "shell_command_origin_unresolved"
            elif command.sources and not _all_sources_allowlisted(command):
                state, reason = "unsafe", "tainted_command_reaches_shell"
            elif command.constant or _all_sources_allowlisted(command):
                state, reason = "safe", "shell_command_is_constant_or_allowlisted"
            else:
                state, reason = "unresolved", "shell_command_origin_unresolved"
        else:
            shell = kwargs.get("shell", _ExprState(constant=True, form="false_default"))
            shell_literal: bool | None
            keyword = next((item for item in node.keywords if item.arg == "shell"), None)
            if keyword is None:
                shell_literal = False
            elif isinstance(keyword.value, ast.Constant) and type(keyword.value.value) is bool:
                shell_literal = keyword.value.value
            else:
                shell_literal = None
            properties.append(
                "shell_mode:true"
                if shell_literal is True
                else "shell_mode:false"
                if shell_literal is False
                else "shell_mode:unknown"
            )
            if shell_literal is True:
                if command.unknown:
                    state, reason = "unresolved", "shell_command_origin_unresolved"
                elif command.sources and not _all_sources_allowlisted(command):
                    state, reason = "unsafe", "tainted_command_reaches_shell"
                elif command.constant or _all_sources_allowlisted(command):
                    state, reason = "safe", "shell_command_is_constant_or_allowlisted"
                else:
                    state, reason = "unresolved", "shell_command_origin_unresolved"
            elif shell_literal is False:
                if command.form == "sequence" and command.elements:
                    executable = command.elements[0]
                    properties.append(f"executable_form:{executable.form}")
                    if executable.unknown:
                        state, reason = "unresolved", "executable_origin_unresolved"
                    elif (
                        executable.constant
                        or executable.form == "finite_mapping_lookup"
                        or _all_sources_allowlisted(executable)
                    ):
                        state, reason = "safe", "argument_vector_with_bounded_executable"
                    elif executable.sources:
                        state, reason = "unsafe", "untrusted_executable_selection"
                    else:
                        state, reason = "unresolved", "executable_origin_unresolved"
                elif command.unknown:
                    state, reason = "unresolved", "subprocess_argument_form_unresolved"
                elif command.constant:
                    state, reason = "safe", "constant_command_without_shell"
                elif command.sources and _all_sources_allowlisted(command):
                    state, reason = "safe", "allowlisted_command_without_shell"
                elif command.sources:
                    state, reason = "unsafe", "untrusted_executable_selection"
                else:
                    state, reason = "unresolved", "subprocess_argument_form_unresolved"
            else:
                state, reason = "unresolved", "shell_mode_unresolved"
            _ = shell
        self.facts.append(
            OracleMechanismSinkFact(
                cwe="CWE-78",
                function_name=self.function_name,
                line=node.lineno,
                sink_kind=name,
                state=state,
                source_names=tuple(sorted(command.sources)),
                properties=tuple(sorted(properties)),
                reason_code=reason,
            )
        )

    def _sql_sink(
        self,
        node: ast.Call,
        name: str,
        args: tuple[_ExprState, ...],
        kwargs: dict[str, _ExprState],
    ) -> None:
        query = args[0] if args else kwargs.get("query", _ExprState(unknown=True))
        method = name.rsplit(".", 1)[-1]
        has_bound_parameters = len(args) >= 2 or "parameters" in kwargs
        properties = (
            f"query_form:{query.form}",
            f"bound_parameters:{str(has_bound_parameters).lower()}",
        )
        if query.unknown:
            state, reason = "unresolved", "query_text_origin_unresolved"
        elif query.constant:
            state, reason = "safe", "constant_query_text"
        elif query.sources and _all_sources_allowlisted(query):
            state, reason = "safe", "dynamic_identifiers_are_finitely_allowlisted"
        elif query.sources:
            state, reason = "unsafe", "tainted_data_interpolated_into_query_text"
        else:
            state, reason = "unresolved", "query_text_origin_unresolved"
        if method == "executescript" and query.sources and not _all_sources_allowlisted(query):
            state, reason = "unsafe", "tainted_script_reaches_executescript"
        self.facts.append(
            OracleMechanismSinkFact(
                cwe="CWE-89",
                function_name=self.function_name,
                line=node.lineno,
                sink_kind=name,
                state=state,
                source_names=tuple(sorted(query.sources)),
                properties=tuple(sorted(properties)),
                reason_code=reason,
            )
        )


def _aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def extract_python_mechanism_trace(code: str) -> OracleMechanismTrace:
    """Extract a deterministic, function-local trace from one Python file."""

    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return OracleMechanismTrace(
            schema_version="1.0",
            extractor_version=MECHANISM_EXTRACTOR_VERSION,
            language="python",
            analysis_scope="single_file_function_local",
            code_sha256=digest,
            parse_ok=False,
            sink_facts=(),
        )
    aliases = _aliases(tree)
    facts: list[OracleMechanismSinkFact] = []
    module_analyzer = _FunctionAnalyzer(aliases, "<module>")
    module_analyzer.analyze(tree.body)
    facts.extend(module_analyzer.facts)
    functions = [
        node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions.sort(key=lambda item: (item.lineno, item.name))
    for function in functions:
        analyzer = _FunctionAnalyzer(aliases, function.name)
        analyzer.seed_parameters(function)
        analyzer.analyze(function.body)
        facts.extend(analyzer.facts)
    facts.sort(key=lambda item: (item.line, item.function_name, item.cwe, item.sink_kind))
    return OracleMechanismTrace(
        schema_version="1.0",
        extractor_version=MECHANISM_EXTRACTOR_VERSION,
        language="python",
        analysis_scope="single_file_function_local",
        code_sha256=digest,
        parse_ok=True,
        sink_facts=tuple(facts),
    )


def decide_oracle_profile(
    trace: OracleMechanismTrace,
    raw_findings: Sequence[AnalyzerFindingRecord],
    profile: _Profile,
) -> OracleProfileDecision:
    """Apply one authenticated finite profile after arm-blind mechanism extraction."""

    raw = tuple(raw_findings)
    if profile.decision_backend != "python_ast_mechanism_v1":
        raise ValueError("Oracle profile decision backend is unsupported")
    if profile.cwe not in {"CWE-78", "CWE-89"}:
        raise ValueError("Oracle profile CWE is unsupported by the decision backend")
    if not trace.parse_ok:
        return OracleProfileDecision(
            schema_version="1.0",
            decision_version=PROFILE_DECISION_VERSION,
            profile_id=profile.profile_id,
            cwe=profile.cwe,
            security_label=SecurityLabel.UNKNOWN,
            evaluability=OracleEvaluability.UNKNOWN_PARSE_FAILURE,
            severity="none",
            findings=(),
            raw_findings=raw,
            mechanism_trace=trace,
            reason_code="parse_failure",
        )
    relevant = tuple(item for item in trace.sink_facts if item.cwe == profile.cwe)
    decisive = tuple(
        item
        for item in raw
        if item.rule_id in profile.analyzer_rule_ids and item.cwe == profile.cwe
    )
    unsafe = tuple(item for item in relevant if item.state == "unsafe")
    unresolved = tuple(item for item in relevant if item.state == "unresolved")
    if unsafe:
        severity: Literal["medium", "high"] = "high" if profile.cwe == "CWE-78" else "medium"
        if decisive:
            rank = {"low": 1, "medium": 2, "high": 3}
            severity = max(decisive, key=lambda item: rank[item.severity]).severity  # type: ignore[assignment]
        return OracleProfileDecision(
            schema_version="1.0",
            decision_version=PROFILE_DECISION_VERSION,
            profile_id=profile.profile_id,
            cwe=profile.cwe,
            security_label=SecurityLabel.INSECURE,
            evaluability=OracleEvaluability.EVALUABLE,
            severity=severity,
            findings=decisive,
            raw_findings=raw,
            mechanism_trace=trace,
            reason_code="proved_unsafe_sink",
        )
    if not relevant:
        reason = "no_relevant_sink"
    elif unresolved:
        reason = "unresolved_relevant_sink"
    elif decisive:
        reason = "analyzer_trace_conflict"
    elif not profile.zero_finding_supported:
        reason = "profile_not_calibrated_for_secure_decision"
    else:
        return OracleProfileDecision(
            schema_version="1.0",
            decision_version=PROFILE_DECISION_VERSION,
            profile_id=profile.profile_id,
            cwe=profile.cwe,
            security_label=SecurityLabel.SECURE,
            evaluability=OracleEvaluability.EVALUABLE,
            severity="none",
            findings=(),
            raw_findings=raw,
            mechanism_trace=trace,
            reason_code="all_relevant_sinks_proved_safe",
        )
    return OracleProfileDecision(
        schema_version="1.0",
        decision_version=PROFILE_DECISION_VERSION,
        profile_id=profile.profile_id,
        cwe=profile.cwe,
        security_label=SecurityLabel.UNKNOWN,
        evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
        severity="none",
        findings=(),
        raw_findings=raw,
        mechanism_trace=trace,
        reason_code=reason,
    )


__all__ = [
    "MECHANISM_EXTRACTOR_VERSION",
    "PROFILE_DECISION_VERSION",
    "OracleMechanismSinkFact",
    "OracleMechanismTrace",
    "OracleProfileDecision",
    "decide_oracle_profile",
    "extract_python_mechanism_trace",
]
