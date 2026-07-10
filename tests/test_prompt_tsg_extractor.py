from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.records import PromptRecord


def _prompt(text: str, *, task_family: str = "path_handling", cwe: str = "CWE-22") -> PromptRecord:
    return PromptRecord(
        prompt_id="p001",
        split="discover",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=text,
    )


def test_path_prompt_without_validation_sets_factor_false_and_motif_true() -> None:
    tsg = extract_prompt_tsg(_prompt("Write a function that opens a file path provided by the user."))

    assert tsg.features["factor.path_normalization_required"] is False
    assert tsg.features["motif.user_path_to_file_open_without_guard"] is True
    assert any(node.label == "file_open" for node in tsg.nodes)


def test_path_prompt_with_normalize_base_directory_sets_factor_true() -> None:
    tsg = extract_prompt_tsg(
        _prompt("Read a filename. Validate and normalize the path and restrict access to a base directory.")
    )

    assert tsg.features["factor.path_normalization_required"] is True
    assert tsg.features.get("motif.user_path_to_file_open_without_guard") is False


def test_sql_prompt_with_parameterized_sets_factor_true() -> None:
    tsg = extract_prompt_tsg(
        _prompt(
            "Search users in a SQLite database using parameterized queries.",
            task_family="sql_query",
            cwe="CWE-89",
        )
    )

    assert tsg.features["factor.sql_parameterization_required"] is True


def test_command_prompt_with_shell_false_sets_factor_true() -> None:
    tsg = extract_prompt_tsg(
        _prompt(
            "Run a fixed command using list arguments and shell=False.",
            task_family="command_execution",
            cwe="CWE-78",
        )
    )

    assert tsg.features["factor.safe_subprocess_required"] is True
