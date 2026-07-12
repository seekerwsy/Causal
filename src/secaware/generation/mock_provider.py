class MockProvider:
    def generate(self, prompt: str, *, model_id: str, seed: int, language: str) -> str:
        if language.lower() != "python":
            return "# Unsupported language for mock provider\n"
        text = prompt.lower()
        if any(
            keyword in text for keyword in ("sqlite", "sql", "database", "query", "orders", "users")
        ):
            return self._sql_code(text)
        if any(
            keyword in text
            for keyword in ("command", "subprocess", "shell", "command-line", "tool")
        ):
            return self._command_code(text)
        if any(keyword in text for keyword in ("pickle", "yaml", "deserialize", "serialized")):
            return self._deserialization_code(text)
        if any(keyword in text for keyword in ("file", "path", "filename", "directory")):
            return self._path_code(text)
        return "def generated_function(*args, **kwargs):\n    return None\n"

    def _path_code(self, text: str) -> str:
        safe = any(
            keyword in text
            for keyword in (
                "normalize",
                "canonicalize",
                "resolve",
                "base directory",
                "restrict",
                "reject traversal",
                "rejects traversal",
                "path traversal",
                "allowlist",
            )
        )
        if safe:
            return (
                "import os\n\n"
                "def read_file(user_path, base_dir='.'):\n"
                "    base = os.path.realpath(base_dir)\n"
                "    safe = os.path.realpath(os.path.join(base, user_path))\n"
                "    if not (safe == base or safe.startswith(base + os.sep)):\n"
                "        raise ValueError('path outside base directory')\n"
                "    with open(safe, 'r', encoding='utf-8') as handle:\n"
                "        return handle.read()\n"
            )
        return (
            "def read_file(user_path):\n"
            "    with open(user_path, 'r', encoding='utf-8') as handle:\n"
            "        return handle.read()\n"
        )

    def _sql_code(self, text: str) -> str:
        safe = any(
            keyword in text
            for keyword in (
                "parameterized",
                "prepared statement",
                "bind parameter",
                "placeholder",
            )
        )
        if safe:
            return (
                "def search_users(cursor, name):\n"
                "    sql = 'SELECT * FROM users WHERE name = ?'\n"
                "    return cursor.execute(sql, (name,)).fetchall()\n"
            )
        return (
            "def search_users(cursor, name):\n"
            '    sql = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
            "    return cursor.execute(sql).fetchall()\n"
        )

    def _command_code(self, text: str) -> str:
        safe = any(
            keyword in text
            for keyword in ("shell=false", "list arguments", "avoid shell", "do not use shell=true")
        )
        if safe:
            return (
                "import subprocess\n\n"
                "def run_tool(option):\n"
                "    return subprocess.run(['fixed-tool', option], shell=False, check=True)\n"
            )
        return "import os\n\ndef run_tool(option):\n    return os.system('fixed-tool ' + option)\n"

    def _deserialization_code(self, text: str) -> str:
        safe = any(
            keyword in text for keyword in ("safe_load", "json", "avoid pickle", "allowlist")
        )
        if safe:
            return (
                "import json\n\n"
                "def load_data(serialized_input):\n"
                "    return json.loads(serialized_input)\n"
            )
        return (
            "import pickle\n\n"
            "def load_data(serialized_input):\n"
            "    return pickle.loads(serialized_input)\n"
        )
