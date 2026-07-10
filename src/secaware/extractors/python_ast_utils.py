import ast


def full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return full_name(node.func)
    if isinstance(node, ast.Subscript):
        return full_name(node.value)
    return ""


def names_in(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def call_has_keyword(call: ast.Call, keyword: str, value: object) -> bool:
    for item in call.keywords:
        if item.arg != keyword:
            continue
        if isinstance(item.value, ast.Constant):
            return item.value.value == value
    return False


def is_list_like(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Tuple))
