import ast
from collections.abc import Iterable

from secaware.extractors.python_ast_utils import call_has_keyword, full_name, is_list_like, names_in
from secaware.schema.records import GeneratedCodeRecord
from secaware.schema.tsg import EdgeType, NodeType, TSGEdge, TSGNode, TSGRecord


SAFE_PARAM_NAMES = {"base_dir", "config", "safe_dir", "cursor", "conn", "connection", "db"}
SOURCE_NAME_HINTS = ("user", "input", "path", "filename", "query", "cmd", "command", "name", "option")


class _CodeGraphBuilder:
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


def _base_features(parse_ok: bool) -> dict[str, bool]:
    return {
        "code.parse_ok": parse_ok,
        "functionality.syntax_ok": parse_ok,
        "code.has_file_open": False,
        "code.has_path_normalization": False,
        "code.has_path_allowlist": False,
        "code.user_path_flows_to_file_open": False,
        "code.user_path_to_file_open_without_guard": False,
        "code.has_sql_execute": False,
        "code.has_sql_parameterization": False,
        "code.user_string_to_sql_without_parameterization": False,
        "code.has_shell_exec": False,
        "code.has_safe_subprocess": False,
        "code.user_input_to_shell_without_guard": False,
        "code.has_yaml_load": False,
        "code.has_pickle_load": False,
        "code.has_safe_deserialization": False,
        "code.untrusted_data_to_deserialization_sink": False,
        "code.has_auth_check": False,
        "code.sensitive_operation_without_auth_guard": False,
    }


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.features = _base_features(parse_ok=True)
        self.builder = _CodeGraphBuilder()
        self.tainted: set[str] = set()
        self.sanitized: set[str] = set()
        self.source_nodes: dict[str, str] = {}

    def _mark_source(self, name: str, source_label: str = "function_param") -> None:
        if name in SAFE_PARAM_NAMES:
            return
        self.tainted.add(name)
        source_id = self.builder.node(NodeType.SOURCE, source_label, variable=name)
        data_id = self.builder.node(NodeType.DATA_OBJECT, name)
        self.builder.edge(source_id, data_id, EdgeType.SOURCE_OF)
        self.source_nodes[name] = source_id

    def _contains_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted and node.id not in self.sanitized
        if isinstance(node, ast.Call) and full_name(node) == "input":
            return True
        if full_name(node).startswith("sys.argv"):
            return True
        if full_name(node) in {"request.args", "request.form", "request.json"}:
            return True
        return any(name in self.tainted and name not in self.sanitized for name in names_in(node))

    def _is_path_normalization(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = full_name(node.func)
        return name in {
            "os.path.abspath",
            "os.path.realpath",
            "os.path.normpath",
        } or name.endswith(".resolve")

    def _is_safe_deserialization(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Call) and full_name(node.func) in {"yaml.safe_load", "json.loads"}

    def _mark_guard(self, label: str) -> None:
        self.builder.node(NodeType.GUARD, label)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        lowered = node.name.lower()
        if any(hint in lowered for hint in ("auth", "permission", "role", "admin")):
            self.features["code.has_auth_check"] = True
            self._mark_guard("auth_check")
        for arg in node.args.args:
            self._mark_source(arg.arg)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        text = ast.unparse(node.test).lower()
        if any(name in self.tainted for name in names_in(node.test)):
            self.features["code.has_path_allowlist"] = self.features["code.has_path_allowlist"] or (
                "startswith" in text or "parents" in text or "base" in text
            )
            self._mark_guard("input_validation")
        if any(hint in text for hint in ("auth", "permission", "role", "admin")):
            self.features["code.has_auth_check"] = True
            self._mark_guard("auth_check")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if self._is_path_normalization(node.value):
            self.features["code.has_path_normalization"] = True
            self._mark_guard("path_normalization")
            for name in target_names:
                self.sanitized.add(name)
                self.tainted.discard(name)
        elif self._is_safe_deserialization(node.value):
            self.features["code.has_safe_deserialization"] = True
            self._mark_guard("safe_deserialization")
        elif self._contains_tainted(node.value):
            for name in target_names:
                self.tainted.add(name)
                self.sanitized.discard(name)
        elif isinstance(node.value, ast.Call) and full_name(node.value.func) == "input":
            for name in target_names:
                self._mark_source(name, "input")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None and self._contains_tainted(node.value):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = full_name(node.func)
        if self._is_path_normalization(node):
            self.features["code.has_path_normalization"] = True
            self._mark_guard("path_normalization")
        if self._is_safe_deserialization(node):
            self.features["code.has_safe_deserialization"] = True
            self._mark_guard("safe_deserialization")

        if name == "open" or name.endswith(".open"):
            self._handle_file_open(node)
        elif name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}:
            self._handle_shell(node, name)
        elif name.endswith(".execute") or name.endswith(".executemany"):
            self._handle_sql(node)
        elif name == "yaml.load":
            self._handle_deserialization(node, "yaml_load")
        elif name in {"pickle.load", "pickle.loads"}:
            self._handle_deserialization(node, "pickle_load")
        self.generic_visit(node)

    def _add_sink_flow(self, sink_label: str, tainted: bool) -> None:
        sink_id = self.builder.node(NodeType.SINK, sink_label)
        if tainted:
            source_id = self.builder.node(NodeType.SOURCE, "user_input")
            self.builder.edge(source_id, sink_id, EdgeType.FLOWS_TO, tainted=True)

    def _handle_file_open(self, node: ast.Call) -> None:
        self.features["code.has_file_open"] = True
        arg = node.args[0] if node.args else node.func
        tainted = self._contains_tainted(arg)
        guarded = (
            self.features["code.has_path_normalization"]
            or self.features["code.has_path_allowlist"]
            or (isinstance(arg, ast.Name) and arg.id in self.sanitized)
        )
        self._add_sink_flow("file_open", tainted)
        if tainted:
            self.features["code.user_path_flows_to_file_open"] = True
            self.features["code.user_path_to_file_open_without_guard"] = not guarded

    def _handle_sql(self, node: ast.Call) -> None:
        self.features["code.has_sql_execute"] = True
        parameterized = len(node.args) >= 2
        if parameterized:
            self.features["code.has_sql_parameterization"] = True
            self._mark_guard("sql_parameterization")
        query_arg = node.args[0] if node.args else node
        tainted = self._contains_tainted(query_arg)
        self._add_sink_flow("sql_execute", tainted)
        self.features["code.user_string_to_sql_without_parameterization"] = bool(
            tainted and not parameterized
        )

    def _handle_shell(self, node: ast.Call, name: str) -> None:
        self.features["code.has_shell_exec"] = True
        first_arg = node.args[0] if node.args else node
        shell_true = name == "os.system" or call_has_keyword(node, "shell", True)
        safe_list = is_list_like(first_arg) and not shell_true
        if safe_list:
            self.features["code.has_safe_subprocess"] = True
            self._mark_guard("safe_subprocess")
        tainted = self._contains_tainted(first_arg)
        self._add_sink_flow("shell_exec", tainted)
        self.features["code.user_input_to_shell_without_guard"] = bool(
            shell_true or (tainted and not safe_list)
        )

    def _handle_deserialization(self, node: ast.Call, sink_label: str) -> None:
        if sink_label == "yaml_load":
            self.features["code.has_yaml_load"] = True
        else:
            self.features["code.has_pickle_load"] = True
        tainted = any(self._contains_tainted(arg) for arg in node.args)
        self._add_sink_flow(sink_label, tainted)
        self.features["code.untrusted_data_to_deserialization_sink"] = True if tainted else False


def extract_code_tsg(code: GeneratedCodeRecord) -> TSGRecord:
    try:
        tree = ast.parse(code.code)
    except SyntaxError as exc:
        return TSGRecord(
            graph_id=f"code:{code.code_id}",
            source_type="code",
            prompt_id=code.prompt_id,
            code_id=code.code_id,
            nodes=[],
            edges=[],
            features={
                **_base_features(parse_ok=False),
                "parse_error": str(exc),
            },
        )

    visitor = _TaintVisitor()
    visitor.visit(tree)
    return TSGRecord(
        graph_id=f"code:{code.code_id}",
        source_type="code",
        prompt_id=code.prompt_id,
        code_id=code.code_id,
        nodes=visitor.builder.nodes,
        edges=visitor.builder.edges,
        features=visitor.features,
    )
