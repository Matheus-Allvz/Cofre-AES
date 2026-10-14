import base64
import os
import secrets

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo

from app.migrar import migrar

URL_DONO = os.environ.get(
    "TEST_DATABASE_URL_DONO", "postgresql://postgres:postgres@127.0.0.1:55432/postgres"
)
SENHA_APP = "senha-de-teste-app"


@pytest.fixture(scope="session")
def banco():
    """Banco temporário por sessão: migrations como dono, app como cofre_app."""
    nome = f"cofre_teste_{secrets.token_hex(4)}"
    with psycopg.connect(URL_DONO, autocommit=True) as conn:
        # Service container do CI não roda db/init: o papel nasce aqui.
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'cofre_app'").fetchone():
            conn.execute("CREATE ROLE cofre_app LOGIN")
        conn.execute(sql.SQL("ALTER ROLE cofre_app PASSWORD {}").format(sql.Literal(SENHA_APP)))
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(nome)))
    urls = {
        "dono": make_conninfo(URL_DONO, dbname=nome),
        "app": make_conninfo(URL_DONO, dbname=nome, user="cofre_app", password=SENHA_APP),
    }
    migrar(urls["dono"])
    yield urls
    with psycopg.connect(URL_DONO, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(nome)))


@pytest.fixture(autouse=True)
def limpar(request):
    yield
    if "banco" not in request.fixturenames:
        return
    urls = request.getfixturevalue("banco")
    with psycopg.connect(urls["dono"]) as conn:
        tabelas = [
            t
            for (t,) in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                " AND tablename <> 'schema_migracoes'"
            )
        ]
        # O trigger de eventos barra TRUNCATE até do dono: desliga só aqui, na transação.
        conn.execute("ALTER TABLE eventos DISABLE TRIGGER USER")
        conn.execute(
            sql.SQL("TRUNCATE {} RESTART IDENTITY CASCADE").format(
                sql.SQL(", ").join(map(sql.Identifier, tabelas))
            )
        )
        conn.execute("ALTER TABLE eventos ENABLE TRIGGER USER")


def _ambiente(monkeypatch, database_url):
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("COFRE_SEGREDO", base64.b64encode(secrets.token_bytes(32)).decode())


@pytest.fixture
def cliente(banco, monkeypatch):
    _ambiente(monkeypatch, banco["app"])
    from app.main import app

    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def cliente_sem_banco(monkeypatch):
    # Porta fechada: simula banco parado.
    _ambiente(monkeypatch, "postgresql://cofre_app:x@127.0.0.1:1/cofre")
    from app.main import app

    with TestClient(app, base_url="https://testserver") as c:
        yield c
