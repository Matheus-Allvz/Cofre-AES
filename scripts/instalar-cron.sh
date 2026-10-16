#!/usr/bin/env bash
# Instala no crontab do usuário (idempotente) o backup diário às 03:30 (hora do host, UTC na
# VPS) via scripts/cron-backup.sh. Rodar de novo não duplica; uma linha antiga do mesmo script
# (outro horário) é substituída. Remover: crontab -l | grep -v cron-backup.sh | crontab -
set -euo pipefail
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$RAIZ/scripts/cron-backup.sh
LINHA="30 3 * * * $SCRIPT"

atual=$(crontab -l 2>/dev/null || true)
if grep -qxF "$LINHA" <<<"$atual"; then
  echo "cron já instalado: $LINHA"
  exit 0
fi
{
  if [[ -n $atual ]]; then grep -vF "$SCRIPT" <<<"$atual" || true; fi
  echo "$LINHA"
} | crontab -
echo "cron instalado: $LINHA"
