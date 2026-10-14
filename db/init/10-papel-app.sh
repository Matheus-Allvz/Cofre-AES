#!/bin/sh
# Cria o papel da aplicação no primeiro boot do container (volume vazio).
# Para recriar: docker compose down -v
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v senha="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE cofre_app LOGIN PASSWORD :'senha';
SQL
