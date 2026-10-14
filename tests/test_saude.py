import base64
import secrets
from pathlib import Path

import pytest
from fastapi import HTTPException

from app import config, db

RAIZ = Path(__file__).resolve().parent.parent


def test_saude(cliente):
    r = cliente.get("/api/saude")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["cache-control"] == "no-store"


def test_pronto_com_banco(cliente):
    r = cliente.get("/api/pronto")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"


def test_pronto_sem_banco_503(cliente_sem_banco):
    r = cliente_sem_banco.get("/api/pronto")
    assert r.status_code == 503
    assert r.json() == {"erro": "banco_indisponivel"}
    assert r.headers["cache-control"] == "no-store"


def test_rota_inexistente_formato_de_erro(cliente):
    r = cliente.get("/api/v1/nao-existe")
    assert r.status_code == 404
    assert r.json() == {"erro": "nao_encontrado"}
    assert r.headers["cache-control"] == "no-store"


def test_metodo_nao_permitido(cliente):
    r = cliente.delete("/api/saude")
    assert r.status_code == 405
    assert r.json() == {"erro": "metodo_nao_permitido"}


def test_erro_com_codigo_e_erro_interno(cliente):
    from app.main import app

    @app.get("/api/teste-erros/{tipo}")
    def _falha(tipo: str):
        if tipo == "codigo":
            raise HTTPException(409, "email_em_uso")
        raise RuntimeError("boom")

    try:
        r = cliente.get("/api/teste-erros/codigo")
        assert r.status_code == 409
        assert r.json() == {"erro": "email_em_uso"}
        assert r.headers["cache-control"] == "no-store"

        from fastapi.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get("/api/teste-erros/boom")
        assert r.status_code == 500
        assert r.json() == {"erro": "interno"}
        assert r.headers["cache-control"] == "no-store"
    finally:
        app.router.routes.pop()


def test_transacao_commit_e_rollback(banco):
    pool = db.criar_pool(banco["app"])
    try:
        with db.transacao(pool) as conn:
            conn.execute("INSERT INTO organizacoes (nome) VALUES ('fica')")
        with pytest.raises(RuntimeError), db.transacao(pool) as conn:
            conn.execute("INSERT INTO organizacoes (nome) VALUES ('some')")
            raise RuntimeError
        with db.transacao(pool) as conn:
            nomes = [n for (n,) in conn.execute("SELECT nome FROM organizacoes")]
        assert nomes == ["fica"]
    finally:
        pool.close()


def test_config(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("COFRE_SEGREDO", base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    assert config.carregar().cookie_secure is True
    monkeypatch.setenv("COOKIE_SECURE", "false")
    assert config.carregar().cookie_secure is False

    for ruim in ("não-base64!", base64.b64encode(bytes(16)).decode()):
        monkeypatch.setenv("COFRE_SEGREDO", ruim)
        with pytest.raises(RuntimeError):
            config.carregar()
    monkeypatch.delenv("COFRE_SEGREDO")
    with pytest.raises(RuntimeError):
        config.carregar()


def test_config_recusa_segredo_fraco_com_cookie_secure(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://x")
    exemplo = next(
        linha.split("=", 1)[1]
        for linha in (RAIZ / ".env.exemplo").read_text(encoding="utf-8").splitlines()
        if linha.startswith("COFRE_SEGREDO=")
    )
    fracos = [exemplo, base64.b64encode(bytes(32)).decode(), base64.b64encode(b"ab" * 16).decode()]
    for fraco in fracos:
        monkeypatch.setenv("COFRE_SEGREDO", fraco)
        monkeypatch.setenv("COOKIE_SECURE", "true")
        with pytest.raises(RuntimeError, match="fraco"):
            config.carregar()
        # Só em dev local sem HTTPS o segredo de exemplo passa.
        monkeypatch.setenv("COOKIE_SECURE", "false")
        assert config.carregar().cookie_secure is False
