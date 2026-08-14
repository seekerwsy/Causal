from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


CORPUS = Path(__file__).resolve().parents[1] / "corpus"
sys.path.insert(0, str(CORPUS))


class Pipe:
    def read(self) -> str:
        return "python worker.py\n"


class CalibrationFunctionalityTests(unittest.TestCase):
    def test_function_parameter_os_popen_direct(self) -> None:
        module = importlib.import_module("function_parameter_os_popen_direct_insecure")
        with patch.object(module.os, "popen", return_value=Pipe()) as popen:
            self.assertEqual(module.get_process_command("42"), "python worker.py")
        self.assertIn("42", popen.call_args.args[0])

    def test_function_parameter_os_popen_helper(self) -> None:
        module = importlib.import_module("function_parameter_os_popen_helper_insecure")
        with patch.object(module.os, "popen", return_value=Pipe()) as popen:
            self.assertEqual(module.get_process_command("42"), "python worker.py")
        self.assertIn("42", popen.call_args.args[0])

    def test_function_parameter_run_list(self) -> None:
        module = importlib.import_module("function_parameter_run_list_secure")
        result = SimpleNamespace(stdout="python worker.py\n")
        with patch.object(module.subprocess, "run", return_value=result) as run:
            self.assertEqual(module.get_process_command("42"), "python worker.py")
        self.assertEqual(run.call_args.args[0], ["ps", "-p", "42", "-o", "command="])
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_function_parameter_check_output_list(self) -> None:
        module = importlib.import_module("function_parameter_check_output_list_secure")
        with patch.object(
            module.subprocess, "check_output", return_value="python worker.py\n"
        ) as check_output:
            self.assertEqual(module.get_process_command("42"), "python worker.py")
        self.assertEqual(
            check_output.call_args.args[0], ("ps", "-p", "42", "-o", "command=")
        )
        self.assertFalse(check_output.call_args.kwargs["shell"])

    def test_closed_mapping_run_shell(self) -> None:
        module = importlib.import_module("closed_mapping_run_shell_insecure")
        result = SimpleNamespace(stdout="Front Left: 50%\n")
        with patch.object(module.subprocess, "run", return_value=result) as run:
            self.assertEqual(module.adjust_volume("+"), "Front Left: 50%")
        self.assertIn("+", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["shell"])

    def test_closed_mapping_run_alias(self) -> None:
        module = importlib.import_module("closed_mapping_run_alias_insecure")
        result = SimpleNamespace(stdout="Front Left: 50%\n")
        with patch.object(module, "_run_command", return_value=result) as run:
            self.assertEqual(module.adjust_volume("+"), "Front Left: 50%")
        self.assertIn("+", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["shell"])

    def test_closed_mapping_run_list(self) -> None:
        module = importlib.import_module("closed_mapping_run_list_secure")
        result = SimpleNamespace(stdout="Front Left: 55%\n")
        with patch.object(module.subprocess, "run", return_value=result) as run:
            self.assertEqual(module.adjust_volume("up"), "Front Left: 55%")
            self.assertEqual(module.adjust_volume("sideways"), "unrecognized command")
        self.assertEqual(run.call_args.args[0], ("amixer", "sset", "Master", "5%+"))
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_closed_mapping_check_output_list(self) -> None:
        module = importlib.import_module("closed_mapping_check_output_list_secure")
        with patch.object(
            module.subprocess, "check_output", return_value="Front Left: 55%\n"
        ) as check_output:
            self.assertEqual(module.adjust_volume("up"), "Front Left: 55%")
            self.assertEqual(module.adjust_volume("sideways"), "unrecognized command")
        self.assertEqual(
            check_output.call_args.args[0], ("amixer", "sset", "Master", "5%+")
        )
        self.assertFalse(check_output.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
