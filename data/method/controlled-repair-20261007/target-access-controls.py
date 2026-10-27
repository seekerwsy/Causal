import os
import subprocess


def solve(primary, comparison, tertiary=None):
    mode = os.environ['PMS_CONTROL_MODE']
    if mode == 'child_relative':
        result = subprocess.run(['grep', '-F', '--', 'alpha', 'shared.txt'], cwd=primary,
                                capture_output=True, check=True)
    elif mode == 'pattern_decoy':
        result = subprocess.run(['grep', '-F', '--', primary, os.path.join(comparison, 'shared.txt')],
                                capture_output=True)
    else:
        raise ValueError(mode)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode())
    return []
