#!/usr/bin/env bash
# whyhard.sh — единая точка входа whyhard.
#
# ./whyhard.sh                 # audit (read-only)
# sudo ./whyhard.sh --apply        # + безопасные фиксы
# sudo ./whyhard.sh --apply-risky  # + рискованные фиксы (sshd_config, сервисы)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/whyhard"

if [[ ! -x "$BIN" ]]; then
    echo "[whyhard.sh] бинарник не найден — собираю статический бинарник (CGO_ENABLED=0)..."

    if ! command -v go >/dev/null 2>&1; then
        echo "[whyhard.sh] go toolchain не найден в PATH." >&2
        echo "[whyhard.sh] Установите Go (apt install golang-go / см. https://go.dev/dl)" >&2
        echo "[whyhard.sh] либо положите готовый бинарник './whyhard' рядом с этим скриптом." >&2
        exit 1
    fi

    (
        cd "$SCRIPT_DIR"
        CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whyhard ./cmd/whyhard
    )
    echo "[whyhard.sh] сборка завершена: $BIN"
fi

exec "$BIN" "$@"
