from collections.abc import Iterable

from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType, TSGEdge, TSGNode, TSGRecord


PATH_KEYWORDS = [
    "file",
    "path",
    "directory",
    "upload",
    "read file",
    "open file",
    "filename",
]
PATH_GUARD_KEYWORDS = [
    "normalize",
    "canonicalize",
    "resolve",
    "allowlist",
    "base directory",
    "prevent traversal",
    "..",
    "path traversal",
    "rejects traversal",
    "reject traversal",
]
SQL_KEYWORDS = ["sql", "database", "query", "sqlite", "select", "insert", "update"]
SQL_GUARD_KEYWORDS = [
    "parameterized",
    "prepared statement",
    "bind parameter",
    "placeholder",
    "?",
    "%s",
]
SHELL_KEYWORDS = ["shell", "command", "subprocess", "os.system", "execute command", "terminal"]
SHELL_GUARD_KEYWORDS = ["shell=false", "list arguments", "avoid shell", "do not use shell=true"]
AUTH_KEYWORDS = ["delete", "update user", "admin", "account", "permission", "private", "sensitive"]
AUTH_GUARD_KEYWORDS = [
    "authorize",
    "authorization",
    "permission check",
    "role check",
    "admin only",
    "access control",
]
DESER_KEYWORDS = ["pickle", "yaml", "deserialize", "load object", "serialized"]
DESER_GUARD_KEYWORDS = ["safe_load", "allowlist", "trusted format", "json", "avoid pickle"]


def _contains_any(text: str, keywords: Iterable[str]) -> bool:
    return any(keyword in text for keyword in keywords)


class _GraphBuilder:
    def __init__(self) -> None:
        self.nodes: list[TSGNode] = []
        self.edges: list[TSGEdge] = []
        self._node_index = 0
        self._edge_index = 0
        self._by_key: dict[tuple[NodeType, str], str] = {}

    def node(self, node_type: NodeType, label: str, **attributes: object) -> str:
        key = (node_type, label)
        if key in self._by_key:
            return self._by_key[key]
        self._node_index += 1
        node_id = f"n{self._node_index}"
        self.nodes.append(
            TSGNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                attributes={k: v for k, v in attributes.items() if v is not None},
            )
        )
        self._by_key[key] = node_id
        return node_id

    def edge(self, src: str, dst: str, edge_type: EdgeType, **attributes: object) -> None:
        self._edge_index += 1
        self.edges.append(
            TSGEdge(
                edge_id=f"e{self._edge_index}",
                src=src,
                dst=dst,
                edge_type=edge_type,
                attributes={k: v for k, v in attributes.items() if v is not None},
            )
        )


def _add_flow(builder: _GraphBuilder, operation: str, data: str, sink: str) -> None:
    operation_id = builder.node(NodeType.TASK_OPERATION, operation)
    data_id = builder.node(NodeType.DATA_OBJECT, data)
    source_id = builder.node(NodeType.SOURCE, "user_input")
    sink_id = builder.node(NodeType.SINK, sink)
    boundary_id = builder.node(NodeType.TRUST_BOUNDARY, "untrusted_user_input")
    builder.edge(operation_id, data_id, EdgeType.OPERATES_ON)
    builder.edge(source_id, data_id, EdgeType.SOURCE_OF)
    builder.edge(boundary_id, source_id, EdgeType.RELATED_TO)
    builder.edge(data_id, sink_id, EdgeType.FLOWS_TO)


def _add_requirement(builder: _GraphBuilder, requirement: str, guard: str) -> None:
    requirement_id = builder.node(NodeType.PROMPT_REQUIREMENT, requirement)
    guard_id = builder.node(NodeType.GUARD, guard)
    builder.edge(requirement_id, guard_id, EdgeType.REQUIRES)


def _default_features() -> dict[str, bool]:
    return {
        "factor.input_validation_required": False,
        "factor.path_normalization_required": False,
        "factor.sql_parameterization_required": False,
        "factor.safe_subprocess_required": False,
        "factor.authorization_check_required": False,
        "factor.safe_deserialization_required": False,
        "motif.user_path_to_file_open_without_guard": False,
        "motif.user_string_to_sql_without_parameterization": False,
        "motif.user_input_to_shell_without_guard": False,
        "motif.sensitive_operation_without_auth_guard": False,
        "motif.untrusted_data_to_deserialization_sink": False,
        "motif.untrusted_source_to_sensitive_sink_without_guard": False,
    }


def extract_prompt_tsg(prompt: PromptRecord) -> TSGRecord:
    text = prompt.prompt.lower()
    builder = _GraphBuilder()
    features = _default_features()
    builder.node(NodeType.CWE, prompt.cwe)

    if _contains_any(text, PATH_KEYWORDS):
        operation = "write_file" if "write" in text or "upload" in text else "read_file"
        _add_flow(builder, operation, "user_path", "file_open")
        if _contains_any(text, PATH_GUARD_KEYWORDS):
            features["factor.path_normalization_required"] = True
            _add_requirement(builder, "require_path_normalization", "path_normalization")
        else:
            features["motif.user_path_to_file_open_without_guard"] = True

    if _contains_any(text, SQL_KEYWORDS):
        _add_flow(builder, "build_sql_query", "user_query_param", "sql_execute")
        if _contains_any(text, SQL_GUARD_KEYWORDS):
            features["factor.sql_parameterization_required"] = True
            _add_requirement(builder, "require_sql_parameterization", "sql_parameterization")
        else:
            features["motif.user_string_to_sql_without_parameterization"] = True

    if _contains_any(text, SHELL_KEYWORDS):
        _add_flow(builder, "execute_command", "command_arg", "shell_exec")
        if _contains_any(text, SHELL_GUARD_KEYWORDS):
            features["factor.safe_subprocess_required"] = True
            _add_requirement(builder, "require_safe_subprocess", "safe_subprocess")
        else:
            features["motif.user_input_to_shell_without_guard"] = True

    if _contains_any(text, AUTH_KEYWORDS):
        operation_id = builder.node(NodeType.TASK_OPERATION, "sensitive_operation")
        sink_id = builder.node(NodeType.SINK, "sensitive_action")
        builder.edge(operation_id, sink_id, EdgeType.FLOWS_TO)
        if _contains_any(text, AUTH_GUARD_KEYWORDS):
            features["factor.authorization_check_required"] = True
            _add_requirement(builder, "require_authorization_check", "auth_check")
        else:
            features["motif.sensitive_operation_without_auth_guard"] = True

    if _contains_any(text, DESER_KEYWORDS):
        _add_flow(builder, "deserialize_data", "serialized_input", "deserialization_sink")
        if _contains_any(text, DESER_GUARD_KEYWORDS):
            features["factor.safe_deserialization_required"] = True
            _add_requirement(builder, "require_safe_deserialization", "safe_deserialization")
        else:
            features["motif.untrusted_data_to_deserialization_sink"] = True

    return TSGRecord(
        graph_id=f"prompt:{prompt.prompt_id}",
        source_type="prompt",
        prompt_id=prompt.prompt_id,
        code_id=None,
        nodes=builder.nodes,
        edges=builder.edges,
        features=features,
    )
