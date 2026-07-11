from __future__ import annotations

import ast


def evaluate_functionality(code: str) -> dict[str, bool]:
    """Return syntax/structure status without making a security decision."""

    tree: ast.Module | None = None
    syntax_ok = False
    not_empty = False
    has_statement = False
    try:
        if type(code) is not str:
            return {
                "syntax_ok": False,
                "not_empty": False,
                "has_statement": False,
                "functional_ok": False,
            }
        not_empty = bool(code.strip())
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            tree = None
        else:
            syntax_ok = True
            has_statement = bool(tree.body)
        return {
            "syntax_ok": syntax_ok,
            "not_empty": not_empty,
            "has_statement": has_statement,
            "functional_ok": bool(syntax_ok and not_empty and has_statement),
        }
    finally:
        code = ""
        tree = None


__all__ = ["evaluate_functionality"]
