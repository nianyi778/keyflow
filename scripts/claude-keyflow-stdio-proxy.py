#!/usr/bin/env python3

import os
import subprocess
import sys
import threading
from datetime import datetime


LOG_FILE = "/tmp/keyflow-claude-stdio-proxy.log"
CHUNK_PREVIEW = 512


def log(message: str) -> None:
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def preview(data: bytes) -> str:
    clipped = data[:CHUNK_PREVIEW]
    text = clipped.decode("utf-8", errors="replace")
    return repr(text)


def pump(reader, writer, label: str, flush: bool = False) -> None:
    try:
        while True:
            chunk = reader.read(4096)
            if not chunk:
                log(f"{label}: EOF")
                try:
                    writer.close()
                except Exception:
                    pass
                break
            log(f"{label}: {len(chunk)} bytes {preview(chunk)}")
            writer.write(chunk)
            if flush:
                writer.flush()
    except Exception as exc:
        log(f"{label}: ERROR {exc}")
        try:
            writer.close()
        except Exception:
            pass


def main() -> int:
    env = os.environ.copy()
    env["HOME"] = "/Users/likai"
    env["KEYFLOW_DATA_DIR"] = "/Users/likai/Library/Application Support/keyflow"

    log("starting stdio proxy")
    log(f"cwd={os.getcwd()}")
    log(f"HOME={env['HOME']}")
    log(f"KEYFLOW_DATA_DIR={env['KEYFLOW_DATA_DIR']}")

    child = subprocess.Popen(
        ["/Users/likai/.cargo/bin/kf", "serve"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    log(f"spawned child pid={child.pid}")

    stderr_thread = threading.Thread(
        target=pump, args=(child.stderr, sys.stderr.buffer, "child_stderr", True), daemon=True
    )
    stdin_thread = threading.Thread(
        target=pump, args=(sys.stdin.buffer, child.stdin, "client_to_child", True), daemon=True
    )
    stdout_thread = threading.Thread(
        target=pump, args=(child.stdout, sys.stdout.buffer, "child_to_client", True), daemon=True
    )

    stderr_thread.start()
    stdin_thread.start()
    stdout_thread.start()

    code = child.wait()
    log(f"child exit={code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
