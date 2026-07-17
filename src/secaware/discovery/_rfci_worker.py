"""Fixed RFCI subprocess entry point; never accepts executable code in its job."""

from __future__ import annotations

import os
import sys


def main() -> None:
    payload = b""
    try:
        if len(sys.argv) != 2:
            raise ValueError
        from secaware.discovery.rfci_backend import _execute_worker_job

        payload = _execute_worker_job(sys.argv[1])
        offset = 0
        descriptor = sys.stdout.fileno()
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written
        sys.stdout.flush()
    except BaseException:
        payload = b""
        raise SystemExit(1) from None
    finally:
        payload = b""


if __name__ == "__main__":
    main()
