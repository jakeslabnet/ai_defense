#!/usr/bin/env python3
"""Docker health check for the most recent AI Defense API request."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    path = Path(os.getenv("HEALTH_STATUS_PATH", "/app/health_status.json"))
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"health status unavailable: {exc}", file=sys.stderr)
        return 1

    if state.get("status_code") != 200:
        print(f"last API status was {state.get('status_code')!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
