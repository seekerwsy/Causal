from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import json
from pathlib import Path
import sys

import bandit
from bandit.core import extension_loader, issue


EXPECTED_BANDIT_VERSION = "1.9.4"
EXPECTED_CONSTRAINT_COUNT = 75


def _attribute_name(node: ast.AST) -> tuple[str, str] | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


def _possible_values(
    node: ast.AST,
    assignments: dict[str, list[ast.AST]],
    namespace: str,
) -> set[str]:
    direct = _attribute_name(node)
    if direct and direct[0] == namespace:
        return {direct[1]}
    if isinstance(node, ast.Name):
        return {
            value
            for assigned in assignments.get(node.id, [])
            for value in _possible_values(assigned, assignments, namespace)
        }
    return {
        value
        for child in ast.iter_child_nodes(node)
        for value in _possible_values(child, assignments, namespace)
    }


def _plugin_constraints(plugin: object) -> dict[str, list[int] | list[str]]:
    module = importlib.import_module(plugin.__module__)  # type: ignore[attr-defined]
    source = inspect.getsource(module)
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    reachable: set[str] = set()
    pending = [plugin.__name__]  # type: ignore[attr-defined]
    while pending:
        name = pending.pop()
        if name in reachable or name not in functions:
            continue
        reachable.add(name)
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in functions:
                    pending.append(node.func.id)

    nodes = [functions[name] for name in reachable]
    assignments: dict[str, list[ast.AST]] = {}
    for function in nodes:
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                targets = node.targets
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            else:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(value)

    cwe_names: set[str] = set()
    severities: set[str] = set()
    confidences: set[str] = set()
    for function in nodes:
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            if _attribute_name(node.func) not in {("bandit", "Issue"), ("issue", "Issue")}:
                continue
            for keyword in node.keywords:
                if keyword.arg == "cwe":
                    for item in ast.walk(keyword.value):
                        if (
                            isinstance(item, ast.Attribute)
                            and isinstance(item.value, ast.Attribute)
                            and isinstance(item.value.value, ast.Name)
                            and item.value.value.id == "issue"
                            and item.value.attr == "Cwe"
                        ):
                            cwe_names.add(item.attr)
                elif keyword.arg == "severity":
                    severities.update(
                        _possible_values(keyword.value, assignments, "bandit")
                    )
                elif keyword.arg == "confidence":
                    confidences.update(
                        _possible_values(keyword.value, assignments, "bandit")
                    )

    test_id = plugin._test_id  # type: ignore[attr-defined]
    if test_id == "B505" and not severities:
        # Bandit 1.9.4's weak-key plugin passes a loop variable named ``level``
        # into Issue. Verify the locked source structure before accounting for
        # the two constants that feed that variable; do not silently guess.
        markers = (
            "severity=level",
            "(config[\"weak_key_size_dsa_high\"], bandit.HIGH)",
            "(config[\"weak_key_size_dsa_medium\"], bandit.MEDIUM)",
            "cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH",
        )
        if not all(marker in source for marker in markers):
            raise RuntimeError("Bandit B505 source structure changed")
        severities.update({"HIGH", "MEDIUM"})

    result: dict[str, list[int] | list[str]] = {
        "cwe_ids": sorted({getattr(issue.Cwe, name) for name in cwe_names}),
        "severities": sorted(severities),
        "confidences": sorted(confidences),
    }
    if any(not values for values in result.values()):
        raise RuntimeError(f"incomplete Bandit metadata for {test_id}")
    return result


def generate_metadata() -> bytes:
    if bandit.__version__ != EXPECTED_BANDIT_VERSION:
        raise RuntimeError("unsupported Bandit version")
    manager = extension_loader.MANAGER
    constraints = {
        extension.plugin._test_id: _plugin_constraints(extension.plugin)
        for extension in manager.plugins
    }
    for family in manager.blacklist.values():
        for item in family:
            candidate = {
                "cwe_ids": [item["cwe"]],
                "severities": [item["level"]],
                "confidences": ["HIGH"],
            }
            previous = constraints.setdefault(item["id"], candidate)
            if previous != candidate:
                raise RuntimeError(f"conflicting Bandit metadata for {item['id']}")
    if len(constraints) != EXPECTED_CONSTRAINT_COUNT:
        raise RuntimeError("Bandit registry size changed")
    document = {
        "schema_version": "1.0",
        "bandit_version": EXPECTED_BANDIT_VERSION,
        "findings": [
            {"test_id": test_id, **constraints[test_id]}
            for test_id in sorted(constraints)
        ],
    }
    return (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    generated = generate_metadata()
    if args.check is not None:
        return 0 if args.check.read_bytes() == generated else 1
    sys.stdout.buffer.write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
