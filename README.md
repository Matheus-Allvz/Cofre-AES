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

Plano completo, requisitos e decisões: [`docs/plano/`](docs/plano/).
