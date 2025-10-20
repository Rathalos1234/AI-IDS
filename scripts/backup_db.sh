#!/usr/bin/env bash
set -euo pipefail
DB="${1:-ids_web.db}"
OUT_DIR="${2:-backups}"
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_DIR/ids_web_${STAMP}.sqlite"
sqlite3 "$DB" ".backup '$OUT'"
echo "Backup -> $OUT"
