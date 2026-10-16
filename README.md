# Cofre AES Empresarial — API

API do gerenciador de senhas corporativo zero-knowledge: toda cifragem acontece no
navegador; o servidor guarda só blobs cifrados, chaves públicas e hashes de autenticação.
Frontend: [Cofre-AES-Frontend](https://github.com/Matheus-Allvz/Cofre-AES-Frontend) (branch `empresarial`).

## Subir

```bash
cp .env.exemplo .env          # troque todos os valores
docker compose up -d --build --wait
curl -fsS http://127.0.0.1:8098/api/saude    # {"status":"ok"}
```

O `.env.exemplo` é para desenvolvimento local (`COOKIE_SECURE=false`). Com
`COOKIE_SECURE=true` a API recusa subir com `COFRE_SEGREDO` fraco ou de exemplo.

Organização e owner inicial (uma vez por instalação; o link de convite é
`https://<dominio>/#/convite/<token>`, entregue ao owner por canal próprio):

```bash
docker compose run --rm -T api python -m app.cli criar-org --nome "Minha Empresa" --email dono@empresa.com
# {"org_id": "...", "usuario_id": "...", "token": "..."}
```

Convite do owner inicial perdido ou vencido (só enquanto ele não aceitou; o anterior deixa de valer):

```bash
docker compose run --rm -T api python -m app.cli reemitir-convite --email dono@empresa.com
```

MFA (TOTP) é opcional por padrão desde a Fase 7; a org pode exigi-lo em `PUT /org/politica`.

O papel `cofre_app` é criado por `db/init/` só no primeiro boot (volume vazio).
Para recriar o banco do zero: `docker compose down -v`.

## Testar

```bash
docker compose -f docker-compose.teste.yml up -d --wait   # Postgres em 127.0.0.1:55432
python -m venv .venv && . .venv/bin/activate              # Windows: .venv/Scripts/activate
pip install -r requirements.txt -r requirements-dev.txt
ruff check . && ruff format --check .
pytest -q --cov=app --cov-fail-under=80
pip-audit -r requirements.txt
```

Outro Postgres de teste: `TEST_DATABASE_URL_DONO=postgresql://...`.

## Arquitetura

- FastAPI + `psycopg` 3 com pool, SQL puro, sem ORM.
- PostgreSQL 16 no compose, sem porta publicada; API em `127.0.0.1:8098`.
- Migrations em `migracoes/NNNN_nome.sql`, aplicadas por `app/migrar.py` (serviço `migrar`,
  forward-only, checksum SHA-256, advisory lock). Voltar atrás = restaurar backup.
- Dois papéis no banco: `cofre_dono` (migrations) e `cofre_app` (API, sem `UPDATE/DELETE`
  em `eventos`).
- Auditoria append-only em `eventos`: grant + trigger.
- Erros no formato `{"erro": "<codigo>"}`; toda resposta com `Cache-Control: no-store`.
- Logs JSON em stdout, sem corpo de requisição.
- `/api/saude` (processo) e `/api/pronto` (banco).
- Argon2 do servidor (64 MiB por hash) com no máximo `COFRE_ARGON2_CONCORRENCIA` (padrão 2)
  execuções simultâneas; o resto espera a vez (503 `ocupado` após 10 s). O `mem_limit` da api
  segue a conta ~60 MiB + concorrência × 64 MiB, com folga (ver `docker-compose.yml`). Carga de
  prova: `python scripts/carga_login.py --projeto <projeto compose> --n 40`.

## Backup e restauração

```bash
BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh          # pg_dump cifrado com age + retenção + R2
AGE_IDENTITY=chave.key scripts/restaurar.sh backups/cofre-<UTC>.dump.age --verifica
```

Detalhes (retenção 7+4+3, prefixos do R2, guarda de cota de 9 GB): [`docs/operacao.md`](docs/operacao.md).

## Produção (empresarial)

- Domínio: `https://secrets.matheus-alves.dev` (proxy da Cloudflare, SSL Full strict,
  Authenticated Origin Pulls). Cadeia: Cloudflare → `<IP_DA_VPS>:443` (sslh) → Caddy `:4443` →
  `/api/*` em `127.0.0.1:8098` (esta API) e o resto em `127.0.0.1:8097` (frontend).
- Diretório na VPS: `/home/deploy/cofre-empresa-api` (clone da branch `empresarial`), projeto
  compose `cofre-empresa` (containers `cofre-empresa-db|migrar|api`; `mem_limit` api 512m, db
  512m). O Postgres não publica porta. Frontend: `/home/deploy/cofre-empresa-front`.
- `.env` (modo 600, fora do git): `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, `COFRE_SEGREDO`,
  `COOKIE_SECURE=true`, `BACKUP_AGE_RECIPIENT` (chave **pública** age),
  `BACKUP_RCLONE_DEST=r2:secrets-backup` e, opcional, `BACKUP_PING_URL` (heartbeat do backup).
  Cópia dos segredos guardada fora da VPS.
- **Deploy:** automático. Push (merge) na `empresarial` → workflow `Deploy (empresarial)` roda os
  testes do `ci.yml` e, se passarem, o job `deploy` (Environment `producao-empresarial`, liberado
  só para a branch `empresarial`, com os secrets `EMP_DEPLOY_SSH_HOST/USER/KEY`) entra por SSH com
  uma chave **exclusiva** deste deploy, verificando a impressão digital do host. No
  `~/.ssh/authorized_keys` do `deploy` essa chave tem
  `command="/home/deploy/cofre-empresa-api/deploy-empresarial.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty`:
  não dá shell e só roda o script, que recebe o SHA do push em `$SSH_ORIGINAL_COMMAND`. O script
  aceita só `empresarial` ou um SHA hex de 7 a 40 caracteres que esteja na história de
  `origin/empresarial` (qualquer outra coisa: exit 2, sem efeito), faz
  `git checkout -f -B empresarial <ref>`, `docker compose build`, `up -d --wait` e falha se
  `/api/pronto` não responder 200. As chaves e os secrets do deploy acadêmico (`main`) não são usados.
  Manual (chave pessoal): `ssh deploy@<IP_DA_VPS> /home/deploy/cofre-empresa-api/deploy-empresarial.sh empresarial`.
- **Rollback:** `ssh deploy@<IP_DA_VPS> /home/deploy/cofre-empresa-api/deploy-empresarial.sh <sha>` (um commit
  da história da `empresarial`; põe a branch local `empresarial` nele e faz o mesmo build/subida).
  Migrations são forward-only: se o commit ruim aplicou migration, voltar o código não volta o
  banco; aí é restaurar backup ([`docs/operacao.md`](docs/operacao.md)).
  O próximo push na `empresarial` volta a implantar a ponta.
- **Organização inicial** (uma vez, depois do primeiro deploy):
  `docker compose -p cofre-empresa exec api python -m app.cli criar-org --nome "<Empresa>" --email <owner>`
  e entregar ao owner `https://secrets.matheus-alves.dev/#/convite/<token>`.
- **Backup:** cron diário às 03:30 UTC (`scripts/instalar-cron.sh`, idempotente) →
  `scripts/cron-backup.sh` → `scripts/backup.sh`; log em `backups/backup.log`, falha marcada em
  `backups/ultimo_falhou`; em sucesso, GET em `BACKUP_PING_URL` (monitor Push do Uptime Kuma,
  heartbeat de 25 h, criado pelo operador; vazio = desativado). Verificar restauração na máquina do operador (a chave privada nunca
  vai à VPS): [`docs/operacao.md`](docs/operacao.md#verificar-a-restauração-scriptsrestaurarsh---verifica).
- Saúde: `curl -fsS https://secrets.matheus-alves.dev/api/saude` e `/api/pronto`.

## Documentação

- [`docs/seguranca.md`](docs/seguranca.md): modelo de ameaças, riscos aceitos (inclusive "o servidor
  serve o JS" e as limitações de RF-O05) e matriz requisito → controle.
- [`docs/operacao.md`](docs/operacao.md): backup, restauração, bootstrap e `COFRE_SEGREDO`.
- [`docs/ropa.md`](docs/ropa.md): registro das operações de tratamento (LGPD).
- [`docs/incidente.md`](docs/incidente.md): resposta a incidente e prazo de comunicação à ANPD.
Plano completo, requisitos e decisões: [`docs/plano/`](docs/plano/).
