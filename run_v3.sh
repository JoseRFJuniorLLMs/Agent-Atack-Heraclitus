#!/usr/bin/env bash
set -euo pipefail
CONFIG="${1:-config.example.json}"
shift || true
exec python3 v3_runner.py "$CONFIG" "$@"
