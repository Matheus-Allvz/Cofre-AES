#!/usr/bin/env bash
# Verificação de restauração (RNF-06): restaura um backup do backup.sh num Postgres temporário
# em container próprio e confere que schema_migracoes = migrations deste repositório (versão e
# SHA-256) e que as contagens de linhas são >= o manifesto gravado no backup. Exit != 0 em
# qualquer falha (arquivo truncado/adulterado, chave errada, restauração ou conferência).
# O container temporário e os arquivos decifrados são apagados no fim, com ou sem falha.
#
#   AGE_IDENTITY=/caminho/da/chave-privada scripts/restaurar.sh backups/cofre-<UTC>.dump.age --verifica
#
# Restaurar de verdade sobre o banco do compose é procedimento manual: docs/operacao.md.
set -euo pipefail

uso() {
  echo "uso: AGE_IDENTITY=<chave privada age> $0 <cofre-<UTC>.dump.age> --verifica" >&2
  exit 2
}
falhar() {
  echo "restaurar: FALHA: $*" >&2
  exit 1
}

[[ $# -eq 2 && $2 == --verifica ]] || uso
arquivo=$1
[[ $arquivo == *.dump.age && -r $arquivo ]] || falhar "arquivo ilegível ou nome fora do padrão *.dump.age"
manifesto=${arquivo%.dump.age}.manifesto.age
[[ -r $manifesto ]] || falhar "manifesto ausente ao lado do backup"
[[ -n ${AGE_IDENTITY-} && -r $AGE_IDENTITY ]] || falhar "defina AGE_IDENTITY com o caminho legível da chave privada"
IMAGEM=${RESTAURAR_IMAGEM:-postgres:16-alpine}
RAIZ=$(cd "$(dirname "$0")/.." && pwd)

tmp=$(mktemp -d)
nome="cofre-restaura-$$-$RANDOM"
limpar() {
  docker rm -f "$nome" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap limpar EXIT

# age confere a autenticação de cada pedaço: truncado ou adulterado falha aqui.
age -d -i "$AGE_IDENTITY" -o "$tmp/dump" "$arquivo" || falhar "não decifrou o backup (truncado, adulterado ou chave errada)"
age -d -i "$AGE_IDENTITY" -o "$tmp/manifesto.json" "$manifesto" || falhar "não decifrou o manifesto"

senha=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
docker run -d --rm --name "$nome" -e POSTGRES_PASSWORD="$senha" -e POSTGRES_DB=cofre "$IMAGEM" >/dev/null
psql() { docker exec -i "$nome" psql -h 127.0.0.1 -U postgres -d cofre -At -v ON_ERROR_STOP=1 "$@"; }
# TCP (-h 127.0.0.1): o servidor provisório do initdb só escuta no socket.
for _ in $(seq 60); do
  psql -c 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
psql -c 'SELECT 1' >/dev/null || falhar "Postgres temporário não subiu"

docker exec -i "$nome" pg_restore -h 127.0.0.1 -U postgres -d cofre --no-owner --no-privileges \
  --exit-on-error <"$tmp/dump" || falhar "pg_restore falhou"

esperado=$(cd "$RAIZ/migracoes" && for f in [0-9][0-9][0-9][0-9]_*.sql; do
  printf '%s %s\n' "${f%.sql}" "$(sha256sum <"$f" | cut -d' ' -f1)"
done)
obtido=$(psql -c "SELECT versao || ' ' || sha256 FROM schema_migracoes ORDER BY versao" | tr -d '\r')
[[ $esperado == "$obtido" ]] || falhar "schema_migracoes do backup diverge das migrations do repositório"

for tabela in eventos organizacoes usuarios; do
  minimo=$(sed -n "s/.*\"$tabela\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" "$tmp/manifesto.json")
  [[ $minimo =~ ^[0-9]+$ ]] || falhar "manifesto sem a contagem de $tabela"
  atual=$(psql -c "SELECT count(*) FROM $tabela" | tr -d '\r')
  ((atual >= minimo)) || falhar "$tabela: $atual linhas < $minimo do manifesto"
  echo "restaurar: $tabela: $atual linhas (manifesto: $minimo)"
done
echo "restaurar: verificação ok ($(echo "$obtido" | wc -l) migrations)"
