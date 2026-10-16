#!/usr/bin/env bash
# Entrada do cron (instalada por scripts/instalar-cron.sh): carrega o .env do projeto (só para
# o backup.sh; nenhum valor é impresso), roda scripts/backup.sh com a saída anexada a
# backups/backup.log (rotacionado ao passar de 1 MiB, 5 gerações) e, em saída ≠ 0, grava
# backups/ultimo_falhou ("<UTC> exit=<n>"); um backup bem-sucedido remove esse arquivo.
set -uo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:$PATH
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
DIR=${BACKUP_DIR:-$RAIZ/backups}
LOG=$DIR/backup.log
umask 077
mkdir -p "$DIR"

if [[ -f $LOG ]] && (($(wc -c <"$LOG") > 1048576)); then
  for i in 4 3 2 1; do
    if [[ -f $LOG.$i ]]; then mv -f "$LOG.$i" "$LOG.$((i + 1))"; fi
  done
  mv -f "$LOG" "$LOG.1"
fi

(
  set -a
  . "$RAIZ/.env" || exit 2
  set +a
  exec "$RAIZ/scripts/backup.sh"
) >>"$LOG" 2>&1
rc=$?

if ((rc)); then
  printf '%s exit=%s (detalhes em backups/backup.log e backups/status)\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" >"$DIR/ultimo_falhou"
else
  rm -f "$DIR/ultimo_falhou"
fi
exit "$rc"
