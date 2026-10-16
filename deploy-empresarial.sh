#!/usr/bin/env bash
# Deploy de produção (Fase 9). Uso: deploy-empresarial.sh empresarial | <sha>
# - CI: é o forced command da chave de deploy em ~/.ssh/authorized_keys; o workflow manda só o
#   SHA do push, que chega em $SSH_ORIGINAL_COMMAND.
# - Operador (chave pessoal): deploy-empresarial.sh empresarial (ponta) ou <sha> (rollback).
# O ref tem de ser exatamente "empresarial" ou um SHA hex de 7 a 40 caracteres, e o commit tem de
# estar na história de origin/empresarial; qualquer outra coisa é recusada (exit 2) sem efeito.
# O .env e backups/ ficam (ignorados pelo git). Falha (exit ≠ 0) se a API não responder /api/pronto.
set -euo pipefail
cd "$(dirname "$0")"

ref=${1-${SSH_ORIGINAL_COMMAND-}}
if [[ $ref == empresarial ]]; then
  alvo=origin/empresarial
elif [[ $ref =~ ^[0-9a-f]{7,40}$ ]]; then
  alvo=$ref
else
  echo "deploy: recusado: ref inválido (use 'empresarial' ou um SHA de 7 a 40 hex)" >&2
  exit 2
fi
git fetch --prune origin
if ! git merge-base --is-ancestor "$alvo" origin/empresarial 2>/dev/null; then
  echo "deploy: recusado: $ref não está na história de origin/empresarial" >&2
  exit 2
fi
# Sempre na branch local empresarial (descarta mudanças locais, como reset --hard).
git checkout -q -f -B empresarial "$alvo"
echo "deploy: $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
docker compose build
docker compose up -d --wait
curl -fsS --retry 10 --retry-delay 2 --retry-all-errors http://127.0.0.1:8098/api/pronto
echo
