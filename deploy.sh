#!/usr/bin/env bash
set -euo pipefail

echo "==> Atualizando codigo (origin/main)..."
git fetch origin main
git reset --hard origin/main

echo "==> Rebuild da imagem (sem cache)..."
docker compose build --no-cache

echo "==> Subindo container..."
docker compose up -d

echo "==> Checando saude em http://127.0.0.1:8095 ..."
sleep 3
curl -I -s http://127.0.0.1:8095

echo "==> Deploy concluido: https://vault.matheus-alves.dev"
