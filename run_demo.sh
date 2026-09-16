#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
CONFIG="${1:-config.example.json}"
PROFILE="${2:-full}"
python3 -m unittest discover -s tests -v
python3 -m py_compile runner.py runner_v3.py stub_upstream.py
exec python3 runner_v3.py --config "$CONFIG" --profile "$PROFILE"
