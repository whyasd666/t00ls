#!/usr/bin/env bash
# whyasdscan launcher — passes all args to the Python engine
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/whyasdscan.py" "$@"
