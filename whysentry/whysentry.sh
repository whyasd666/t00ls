#!/usr/bin/env bash
# whysentry.sh — единая точка входа WhySentry.
#
# Поведение:
#   1. Если рядом со скриптом уже лежит собранный статический бинарник
#      ./whysentry — просто исполняет его (exec, без лишнего процесса).
#   2. Если бинарника нет, но есть go-toolchain — собирает его
#      (CGO_ENABLED=0, статически, без зависимостей от glibc/musl) и
#      затем запускает.
#   3. Если нет ни бинарника, ни go — печатает понятную ошибку.
#
# Использование:
#   ./whysentry.sh            # обычный запуск (рекомендуется sudo)
#   sudo ./whysentry.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/whysentry"

if [[ ! -x "$BIN" ]]; then
    echo "[whysentry.sh] бинарник не найден — собираю статический бинарник (CGO_ENABLED=0)..."

    if ! command -v go >/dev/null 2>&1; then
        echo "[whysentry.sh] go toolchain не найден в PATH." >&2
        echo "[whysentry.sh] Установите Go (apt install golang-go / см. https://go.dev/dl)" >&2
        echo "[whysentry.sh] либо положите готовый бинарник './whysentry' рядом с этим скриптом." >&2
        exit 1
    fi

    (
        cd "$SCRIPT_DIR"
        CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whysentry ./cmd/whysentry
    )
    echo "[whysentry.sh] сборка завершена: $BIN"
fi

exec "$BIN" "$@"
