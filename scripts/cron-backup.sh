#!/usr/bin/env bash
# Entrada do cron (instalada por scripts/instalar-cron.sh): carrega o .env do projeto (só para
# o backup.sh; nenhum valor é impresso), roda scripts/backup.sh com a saída anexada a
# backups/backup.log (rotacionado ao passar de 1 MiB, 5 gerações) e, em saída ≠ 0, grava
# backups/ultimo_falhou ("<UTC> exit=<n>"); um backup bem-sucedido remove esse arquivo.
# Heartbeat: só em sucesso, se BACKUP_PING_URL (no .env) não for vazia, faz um GET nela (monitor
# Push do Uptime Kuma, heartbeat de 25 h): o Kuma alerta tanto na falha quanto no silêncio (cron
# que nem rodou). A URL tem o token do monitor e não é impressa.
set -uo pipefail
export PATH=$PATH:/usr/local/bin:/usr/bin:/bin # o cron só traz /usr/bin:/bin
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
  "$RAIZ/scripts/backup.sh" || exit
  if [[ -n ${BACKUP_PING_URL-} ]]; then
    curl -fsS -m 10 -o /dev/null "$BACKUP_PING_URL" 2>/dev/null ||
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) backup: AVISO: heartbeat (BACKUP_PING_URL) falhou"
  fi
) >>"$LOG" 2>&1
rc=$?

if ((rc)); then
  printf '%s exit=%s (detalhes em backups/backup.log e backups/status)\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$rc" >"$DIR/ultimo_falhou"
else
  rm -f "$DIR/ultimo_falhou"
fi
exit "$rc"
