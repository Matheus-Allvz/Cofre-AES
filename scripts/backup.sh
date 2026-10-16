#!/usr/bin/env bash
# Backup do banco (RNF-05): pg_dump -Fc do serviço db do compose, cifrado com age para a chave
# PÚBLICA (a privada fica fora do host), retenção local 7 diários + 4 semanais (domingo) + 3
# mensais (dia 1) e cópia para o Cloudflare R2 via rclone, com guarda de cota. Ver docs/operacao.md.
#
#   BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh
#   scripts/backup.sh --retencao < nomes      # imprime quais arquivos a retenção mantém
#
# Variáveis: BACKUP_AGE_RECIPIENT (obrigatória), BACKUP_DIR (padrão backups/), COMPOSE_PROJECT
# (projeto do compose; padrão: o do diretório), BACKUP_RCLONE_DEST (padrão r2:secrets-backup;
# vazia = só local), BACKUP_LIMITE_BYTES (padrão 9000000000 = 90% dos 10 GB grátis do R2).
# Saída: 0 ok; 2 configuração; 3 cota do destino; 4 falha no envio/medição do destino.
# O script nunca apaga nada no R2 (só copyto de arquivo novo); a validade lá é das regras de
# ciclo de vida do bucket (diario/ 8 dias, semanal/ 35, mensal/ 100).
set -euo pipefail

# Mantém (imprime) o mais novo de cada dia entre os 7 dias mais recentes com backup, dos 4
# domingos mais recentes e dos 3 dias 1 mais recentes. Entrada: nomes cofre-<UTC>.dump.age.
retencao() {
  local nome dia ultimo="" d=0 s=0 m=0 fica
  while read -r nome; do
    [[ $nome =~ ^cofre-([0-9]{8})T[0-9]{6}Z\.dump\.age$ ]] || continue
    dia=${BASH_REMATCH[1]}
    [[ $dia == "$ultimo" ]] && continue
    ultimo=$dia
    fica=0
    if ((d < 7)); then d=$((d + 1)) fica=1; fi
    if ((s < 4)) && [[ $(date -u -d "$dia" +%u) == 7 ]]; then s=$((s + 1)) fica=1; fi
    if ((m < 3)) && [[ ${dia:6:2} == 01 ]]; then m=$((m + 1)) fica=1; fi
    if ((fica)); then echo "$nome"; fi
  done < <(sort -r)
}

if [[ ${1-} == --retencao ]]; then
  retencao
  exit 0
fi

RAIZ=$(cd "$(dirname "$0")/.." && pwd)
DIR=${BACKUP_DIR:-$RAIZ/backups}
DEST=${BACKUP_RCLONE_DEST-r2:secrets-backup}
LIMITE=${BACKUP_LIMITE_BYTES:-9000000000}
AGORA=${BACKUP_AGORA:-$(date -u +%Y%m%dT%H%M%SZ)} # os testes fixam a data
NOME=cofre-$AGORA

log() { printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
status() { printf 'em=%s resultado=%s motivo=%s\n' "$AGORA" "$1" "$2" >"$DIR/status"; }
falhar() {
  log "FALHA: $2"
  status falha "$2"
  exit "$1"
}

mkdir -p "$DIR"
umask 077
[[ -n ${BACKUP_AGE_RECIPIENT-} ]] || falhar 2 "defina BACKUP_AGE_RECIPIENT (chave pública age)"
# Nunca a chave privada aqui: o host só cifra. (O valor não é impresso.)
[[ $BACKUP_AGE_RECIPIENT != AGE-SECRET-KEY-* ]] || falhar 2 "BACKUP_AGE_RECIPIENT é uma chave PRIVADA; use a pública (age1...)"
[[ $LIMITE =~ ^[0-9]+$ ]] || falhar 2 "BACKUP_LIMITE_BYTES deve ser um inteiro em bytes"
trap 'status falha "comando falhou (linha $LINENO)"' ERR

dc() { docker compose ${COMPOSE_PROJECT:+-p "$COMPOSE_PROJECT"} --project-directory "$RAIZ" -f "$RAIZ/docker-compose.yml" "$@"; }
cifrar() { age -r "$BACKUP_AGE_RECIPIENT"; }

parcial="$DIR/.parcial-$NOME"
trap 'rm -f "$parcial".*' EXIT
# Manifesto (contagens mínimas para o restaurar.sh --verifica) ANTES do dump: só tabelas que
# nunca perdem linhas (eventos é append-only; usuário removido é anonimizado, não apagado).
dc exec -T db psql -U cofre_dono -d cofre -At -v ON_ERROR_STOP=1 -c \
  "SELECT json_build_object('eventos', (SELECT count(*) FROM eventos),
     'organizacoes', (SELECT count(*) FROM organizacoes),
     'usuarios', (SELECT count(*) FROM usuarios))" | cifrar >"$parcial.manifesto.age"
dc exec -T db pg_dump -U cofre_dono -d cofre -Fc | cifrar >"$parcial.dump.age"
mv "$parcial.manifesto.age" "$DIR/$NOME.manifesto.age"
mv "$parcial.dump.age" "$DIR/$NOME.dump.age"
log "backup local: $NOME.dump.age ($(wc -c <"$DIR/$NOME.dump.age") bytes)"

# Retenção local.
manter=$(cd "$DIR" && ls -1 | retencao)
for f in "$DIR"/cofre-*.dump.age; do
  base=$(basename "$f")
  if ! grep -qxF "$base" <<<"$manter"; then
    rm -f "$f" "${f%.dump.age}.manifesto.age"
    log "retenção: removido $base"
  fi
done

# Cópia externa (R2). Sem destino utilizável: o backup local vale, com aviso.
externo="ok"
remoto=${DEST%%:*}
if [[ -z $DEST ]]; then
  externo="ignorado: BACKUP_RCLONE_DEST vazio"
elif ! command -v rclone >/dev/null; then
  externo="ignorado: rclone não instalado"
elif ! rclone listremotes | grep -qxF "$remoto:"; then
  externo="ignorado: remoto rclone '$remoto' não configurado"
else
  prefixos=(diario)
  [[ $(date -u -d "${AGORA:0:8}" +%u) == 7 ]] && prefixos+=(semanal)
  [[ ${AGORA:6:2} == 01 ]] && prefixos+=(mensal)
  novo=$(($(wc -c <"$DIR/$NOME.dump.age") + $(wc -c <"$DIR/$NOME.manifesto.age")))
  medida=$(rclone size --json --s3-no-check-bucket "$DEST") || falhar 4 "não foi possível medir o uso de $DEST"
  uso=$(sed -n 's/.*"bytes":[[:space:]]*\([0-9][0-9]*\).*/\1/p' <<<"$medida")
  [[ $uso =~ ^[0-9]+$ ]] || falhar 4 "resposta inesperada do rclone size"
  projetado=$((uso + novo * ${#prefixos[@]}))
  if ((projetado > LIMITE)); then
    falhar 3 "cota: uso atual $uso + novo $novo x ${#prefixos[@]} prefixo(s) = $projetado bytes passa do limite $LIMITE; nada enviado (backup local mantido)"
  fi
  for p in "${prefixos[@]}"; do
    for f in "$NOME.dump.age" "$NOME.manifesto.age"; do
      rclone copyto --s3-no-check-bucket --no-check-dest "$DIR/$f" "$DEST/$p/$f" ||
        falhar 4 "envio de $p/$f falhou"
    done
  done
  externo="ok: ${prefixos[*]} (uso projetado $projetado de $LIMITE bytes)"
fi
[[ $externo == ok* ]] || log "AVISO: cópia externa $externo"
log "cópia externa: $externo"
status ok "$externo"
printf '%s %s\n' "$AGORA" "$NOME.dump.age" >"$DIR/ultimo_ok"
