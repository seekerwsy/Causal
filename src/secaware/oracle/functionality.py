import ast


REFUSAL_MARKERS = ["i can't", "cannot provide", "not able to", "unsafe", "as an ai"]


def evaluate_functionality(code: str) -> dict[str, bool]:
    stripped = code.strip()
    syntax_ok = True
    try:
        tree = ast.parse(code)
    except SyntaxError:
        syntax_ok = False
        tree = None

    not_empty = bool(stripped)
    no_refusal = not any(marker in stripped.lower() for marker in REFUSAL_MARKERS)
    has_callable_or_code = False
    if tree is not None:
        has_callable_or_code = any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Assign, ast.Expr))
            for node in tree.body
        )
    imports_ok = syntax_ok

    return {
        "syntax_ok": syntax_ok,
        "imports_ok": imports_ok,
        "has_callable_or_code": has_callable_or_code,
        "not_empty": not_empty,
        "no_obvious_refusal": no_refusal,
        "functional_ok": bool(syntax_ok and not_empty and no_refusal and has_callable_or_code),
    }
