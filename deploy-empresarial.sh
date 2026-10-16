#!/usr/bin/env bash
# Deploy de produção (Fase 9), rodado na VPS pelo workflow deploy-empresarial.yml a cada push na
# branch empresarial. Sem argumento implanta origin/empresarial; com um SHA (ou ref) implanta
# aquele commit, que é o rollback: deploy-empresarial.sh <sha>. O .env e backups/ ficam (fora
# do git). Falha (exit ≠ 0) se a API não responder /api/pronto.
set -euo pipefail
cd "$(dirname "$0")"

alvo=${1:-origin/empresarial}
git fetch --prune origin
git reset --hard "$alvo"
echo "deploy: $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
docker compose build
docker compose up -d --wait
curl -fsS --retry 10 --retry-delay 2 --retry-all-errors http://127.0.0.1:8098/api/pronto
echo
