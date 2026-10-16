# Operação

Backup, restauração, bootstrap e segredos do servidor. Riscos e controles: [`seguranca.md`](seguranca.md).
Produção (domínio, diretórios, deploy, rollback): README, seção "Produção (empresarial)". Comandos
na VPS rodam em `/home/deploy/cofre-empresa-api` (projeto compose `cofre-empresa`, definido no
`docker-compose.yml`).

## Pré-requisitos no host

- Docker com o compose do projeto rodando (serviço `db`).
- [`age`](https://github.com/FiloSottile/age) (só para cifrar: o host recebe a chave **pública**).
- `rclone` com um remoto `r2` configurado pelo operador (credencial do bucket `secrets-backup` com
  leitura/escrita de objetos; não precisa listar nem criar buckets). O script não cria remoto nem
  lida com chaves.

## Chaves do backup

```bash
age-keygen -o cofre-backup.key      # numa máquina FORA da VPS; imprime "Public key: age1..."
```

- A chave privada (`cofre-backup.key`) fica fora do servidor (cofre pessoal + cópia offline). Sem
  ela nenhum backup é legível; perdê-la = perder os backups.
- No host só vai a pública: `BACKUP_AGE_RECIPIENT=age1...`. O `backup.sh` recusa uma chave privada
  nessa variável (sem imprimi-la) e nunca usa `age -d`.

## Backup: `scripts/backup.sh`

```bash
BACKUP_AGE_RECIPIENT=age1... COMPOSE_PROJECT=<projeto> scripts/backup.sh
```

1. Grava o manifesto (contagens de `eventos`, `organizacoes`, `usuarios`, tabelas que nunca perdem
   linhas) e então `docker compose exec -T db pg_dump -Fc`, os dois cifrados no pipe com
   `age -r`. Resultado em `backups/` (`BACKUP_DIR`): `cofre-<UTC>.dump.age` e
   `cofre-<UTC>.manifesto.age`, com `umask 077`.
2. **Retenção local:** fica o backup mais novo de cada um dos 7 dias mais recentes, dos 4 domingos
   mais recentes e dos 3 dias 1 mais recentes (um arquivo pode contar em mais de uma regra); o resto
   é apagado (com o manifesto). `scripts/backup.sh --retencao < nomes` mostra o que ficaria.
3. **Cópia externa (R2):** destino `BACKUP_RCLONE_DEST` (padrão `r2:secrets-backup`). Prefixos
   fixos: `diario/` sempre, `semanal/` no domingo (UTC) e `mensal/` no dia 1 (UTC). Só
   `rclone copyto --s3-no-check-bucket --s3-no-head --no-check-dest` de arquivo novo: **o script nunca apaga
   nada no R2**. A validade lá é das regras de ciclo de vida do bucket: `diario/` 8 dias,
   `semanal/` 35, `mensal/` 100.
4. Só `BACKUP_RCLONE_DEST=` **vazio** (explícito) dispensa a cópia externa: o backup local vale,
   com `AVISO` no log e `motivo=ignorado: ...` no status. Com destino definido (inclusive o padrão
   `r2:secrets-backup` quando a variável não existe), `rclone` ausente, remoto inexistente, falha
   ao medir ou ao enviar → saída `4` e `resultado=falha`, nunca `ok` silencioso (o backup local fica).
5. Escreve `backups/status` (`em=<UTC> resultado=ok|falha motivo=...`) e, só em sucesso,
   `backups/ultimo_ok` (`<UTC> <arquivo>`). Log em stderr, sem segredos.

Saída: `0` ok · `1` um comando falhou no meio (`docker compose exec`, `psql`, `pg_dump`, `age`,
retenção; `set -e`, status `comando falhou (linha N)`) · `2` configuração · `3` guarda de cota ·
`4` destino externo indisponível ou falha ao medir/enviar. Em `1` não fica arquivo novo (os
parciais são apagados); em `3`/`4` o backup local fica e o status traz o motivo.

### Cron (produção)

```bash
scripts/instalar-cron.sh     # idempotente: 30 3 * * * /home/deploy/cofre-empresa-api/scripts/cron-backup.sh
crontab -l | grep cron-backup
```

`scripts/cron-backup.sh` carrega o `.env` do projeto (sem imprimir valores), roda o `backup.sh` e
anexa a saída a `backups/backup.log` (rotacionado ao passar de 1 MiB: `backup.log.1` … `.5`). Em
saída ≠ 0 grava `backups/ultimo_falhou` (`<UTC> exit=<n>`); um backup bem-sucedido o remove. O
alerta local é esse arquivo: confira `ls backups/ultimo_falhou` e `cat backups/status`.

**Heartbeat (alerta externo):** em sucesso, se `BACKUP_PING_URL` no `.env` não for vazia, o
`cron-backup.sh` faz `curl -fsS -m 10` nela (a URL não é impressa; falha do ping só gera `AVISO` no
log, não falha o backup). O operador cria no Uptime Kuma um monitor **Push** com heartbeat de
**25 h** e cola a URL de push no `.env` (`BACKUP_PING_URL=https://status.matheus-alves.dev/api/push/<token>?status=up&msg=OK`).
Sem ping dentro de 25 h (backup falhou, cron não rodou, host fora), o Kuma alerta pelos canais
dele. O `ntfy` da VPS não é usado (`auth-default-access: deny-all`; exigiria credencial própria).

### Guarda de cota do R2 (nunca passar de 90% do plano grátis)

Antes de enviar, o script mede o uso atual **do bucket** `secrets-backup` (`rclone size --json`) e
calcula

```
projetado = uso_atual + (tamanho do .dump.age + tamanho do .manifesto.age) × nº de prefixos do dia
```

Se `projetado > BACKUP_LIMITE_BYTES` (padrão `9000000000` = 9 GB = 90% dos 10 GB grátis), **nada é
enviado**, a saída é `3` e o motivo vai ao log e ao `backups/status`. O uso medido inclui objetos
que o ciclo de vida ainda vai expirar, então a conta é conservadora. Testado em
`tests/test_backup.py` com um `rclone` simulado no `PATH` (exatamente no limite passa, um byte acima
não envia nada).

A guarda mede só este bucket; a cota grátis do R2 (10 GB-mês de armazenamento, 1 M Class A e 10 M
Class B por mês) é **por conta**, somando todos os buckets. Se a conta tiver outros buckets, baixe
`BACKUP_LIMITE_BYTES` para 9 GB menos o que eles ocupam, ou acompanhe o uso no painel do R2.

Espaço em regime: com um backup por dia ficam no bucket ~8 cópias em `diario/`, ~5 em `semanal/` e
~4 em `mensal/` ≈ 17 cópias do dump. A guarda só dispara com dump perto de 9 GB / 17 ≈ 530 MB; o
cofre (blobs de até 64 KiB, dezenas de usuários) fica em poucos MB.

### Operações do R2 por mês (plano grátis: 1 milhão Class A, 10 milhões Class B)

| Operação do script | Classe | Por execução | Por mês (1 execução/dia) |
|---|---|---|---|
| `rclone size` (ListObjectsV2, até 1000 objetos por chamada; o bucket tem ~35) | A | 1 | 31 |
| `copyto` em `diario/` (PutObject × 2 arquivos; `--no-check-dest` evita o HEAD antes e `--s3-no-head` o HEAD de conferência depois) | A | 2 | 62 |
| `copyto` em `semanal/` (domingos) | A | 2 | ~10 |
| `copyto` em `mensal/` (dia 1) | A | 2 | 2 |
| `--s3-no-check-bucket` (sem HeadBucket/CreateBucket) | — | 0 | 0 |
| Expiração pelo ciclo de vida | grátis | — | — |
| **Total** | **A** | **3–7** | **≈ 105 (≤ 217 no pior caso)** |

Class A: ~105 de 1.000.000 por mês (0,01%; o teto de 90% é 900.000). Class B: o script não faz
leitura; uma restauração baixa 2 objetos (2 Class B, contra 9.000.000 de teto). Mesmo rodando o
backup de hora em hora (24×) ficaria em ~2.500 Class A/mês, longe do limite.

## Verificar a restauração: `scripts/restaurar.sh --verifica`

```bash
AGE_IDENTITY=/caminho/cofre-backup.key scripts/restaurar.sh backups/cofre-<UTC>.dump.age --verifica
```

Sobe um `postgres:16-alpine` temporário em container próprio, decifra com `age -d -i`, roda
`pg_restore --exit-on-error` e confere: `schema_migracoes` = migrations de `migracoes/` (versão e
SHA-256) e contagens ≥ o manifesto. Qualquer falha (arquivo truncado ou adulterado, chave errada,
`pg_restore`, conferência) → saída ≠ 0. O container e os arquivos decifrados somem no fim. Rode
numa máquina com a chave privada, nunca deixando a chave na VPS. Na máquina do operador (com Docker,
`age`, `rclone` com o mesmo remoto `r2` e um clone deste repositório na mesma versão de migrations):

```bash
rclone lsf r2:secrets-backup/diario/ | sort | tail -2          # o par mais recente
mkdir -p backups && rclone copy --s3-no-check-bucket --include 'cofre-<UTC>.*' r2:secrets-backup/diario/ backups/
AGE_IDENTITY=~/cofre-backup.key scripts/restaurar.sh backups/cofre-<UTC>.dump.age --verifica   # exit 0
```

Sem `rclone` local, copie da VPS: `scp -P 443 'deploy@<IP_DA_VPS>:/home/deploy/cofre-empresa-api/backups/cofre-<UTC>.*' backups/`. O CI roda backup → `--verifica` → arquivo truncado falha a cada PR (job `backup`).

## Restaurar de verdade (procedimento manual)

Reversão de migration = restaurar backup (D4). Regras: **primeiro um backup do estado atual**
(nada de `dropdb` sem ele) e a **decifragem acontece na máquina do operador** (`age -d -i` local);
o dump em claro vai à VPS pelo `ssh`, direto para o `pg_restore`, sem tocar o disco dela. A chave
privada nunca vai à VPS. Antes, rode `--verifica` no mesmo arquivo (seção acima).

Na máquina do operador, com `VPS=deploy@<IP_DA_VPS>` e `D=/home/deploy/cofre-empresa-api`:

```bash
ssh -p 443 $VPS "cd $D && scripts/cron-backup.sh; cat backups/status"   # 1. backup do estado atual: exige resultado=ok
ssh -p 443 $VPS "cd $D && docker compose stop api"                     # 2. API parada
ssh -p 443 $VPS "cd $D && docker compose exec -T db dropdb -U cofre_dono cofre && docker compose exec -T db createdb -U cofre_dono cofre"   # 3. banco vazio
age -d -i ~/cofre-backup.key backups/cofre-<UTC>.dump.age |
  ssh -p 443 $VPS "cd $D && docker compose exec -T db pg_restore -U cofre_dono -d cofre --exit-on-error"   # 4.
ssh -p 443 $VPS "cd $D && docker compose up -d --wait && curl -fsS http://127.0.0.1:8098/api/pronto"     # 5.
```

No passo 1 o `cron-backup.sh` carrega o `.env` (destinatário age e destino R2); não siga sem
`resultado=ok`. Se o passo 4 falhar, repita 3–4 com o backup do passo 1 para voltar ao estado anterior. O dump traz
os grants para `cofre_app` (o papel já existe no volume). Restaurar exige o mesmo `COFRE_SEGREDO`.

## Bootstrap

Ver o README: `docker compose up -d --build --wait`, depois `python -m app.cli criar-org` (uma vez
por instalação; em produção `docker compose -p cofre-empresa exec api python -m app.cli criar-org
--nome "<Empresa>" --email <owner>`; o link de convite do owner sai só nessa saída) e `reemitir-convite` se ele se
perder antes do aceite.

## `COFRE_SEGREDO` (pepper)

`COFRE_SEGREDO` (32 B em base64) gera as subchaves `pepper`, `prelogin` e `totp` (D19). **Trocar o
pepper invalida todos os logins**: o `auth_hash` guardado é `Argon2id(HMAC(pepper, authHash))`, então
nenhuma senha-mestra confere depois da troca; também deixam de valer os kits de recuperação
(`HMAC(pepper, recup_auth)`), os códigos de recuperação do MFA e todos os segredos TOTP (cifrados com a
subchave `totp`), e o `prelogin` falso muda de valor. Os dados cifrados no banco continuam
intactos, mas ninguém consegue entrar para abri-los. Não há rotação suave no MVP: trocar só em
comprometimento confirmado, com um plano de reemissão de acesso para todas as contas. Guarde o valor fora do servidor junto
com a chave privada do backup: restaurar um backup exige o mesmo `COFRE_SEGREDO`.
