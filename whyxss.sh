#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Try venv first, then system python
if [ -f ~/.whyasdscan-venv/bin/python3 ]; then
  exec ~/.whyasdscan-venv/bin/python3 "$SCRIPT_DIR/whyxss.py" "$@"
else
  exec python3 "$SCRIPT_DIR/whyxss.py" "$@"
fi
