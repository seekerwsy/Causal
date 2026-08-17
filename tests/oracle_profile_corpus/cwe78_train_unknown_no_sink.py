def lookup_process(pid):
    with open(f"/proc/{pid}/cmdline", "rb") as handle:
        return handle.read()
