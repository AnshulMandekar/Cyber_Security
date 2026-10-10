"""Entry point for the packaged OktaTrace API server (built with PyInstaller).

Double-click the exe (or run it from a terminal), then open
http://127.0.0.1:8000/docs. Generated data goes in a ``data`` folder next to the exe.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn

from oktatrace.api.app import app


def main() -> None:
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()
    os.environ.setdefault("OKTATRACE_DATA_DIR", str(base / "data"))
    port = int(os.getenv("OKTATRACE_PORT", "8000"))
    print(f"OktaTrace API on http://127.0.0.1:{port}/docs  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
