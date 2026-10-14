"""RNF-01: 10 falhas por conta → bloqueio 15 min; 20 req/min por IP nas rotas públicas."""

import hashlib

import psycopg
import pytest
from conftest import EMAIL_OWNER, b64u


def _login(cliente, email, auth_hash):
    return cliente.post("/api/v1/login", json={"email": email, "auth_hash": auth_hash})


@pytest.mark.parametrize("existe", [True, False], ids=["conta_existente", "conta_inexistente"])
def test_11a_tentativa_429_mesmo_com_senha_correta(cliente, owner, existe, banco):
    email = EMAIL_OWNER if existe else "fantasma@teste.invalid"
    for _ in range(10):
        assert _login(cliente, email, b64u(32)).status_code == 401
    r = _login(cliente, email, owner["auth_hash"])  # 11ª, com a senha correta
    assert (r.status_code, r.json()) == (429, {"erro": "bloqueado"})
    assert 0 < int(r.headers["Retry-After"]) <= 15 * 60
    with psycopg.connect(banco["dono"]) as conn:
        bloqueios = conn.execute(
            "SELECT count(*) FROM eventos WHERE tipo = 'auth.bloqueio'"
        ).fetchone()[0]
    assert bloqueios == 1


def test_bloqueio_acaba_apos_15_min(cliente, owner, relogio):
    for _ in range(10):
        _login(cliente, EMAIL_OWNER, b64u(32))
    relogio.avancar(minutes=14)
    assert _login(cliente, EMAIL_OWNER, owner["auth_hash"]).status_code == 429
    relogio.avancar(minutes=1, seconds=1)
    assert _login(cliente, EMAIL_OWNER, owner["auth_hash"]).status_code == 200


def test_sucesso_zera_contagem(cliente, owner):
    for _ in range(9):
        _login(cliente, EMAIL_OWNER, b64u(32))
    assert _login(cliente, EMAIL_OWNER, owner["auth_hash"]).status_code == 200
    for _ in range(9):
        assert _login(cliente, EMAIL_OWNER, b64u(32)).status_code == 401


def test_21a_requisicao_por_minuto_do_ip_429(cliente, relogio):
    for _ in range(20):
        assert cliente.post("/api/v1/prelogin", json={"email": "a@t.invalid"}).status_code == 200
    r = cliente.post("/api/v1/prelogin", json={"email": "a@t.invalid"})
    assert r.status_code == 429 and "Retry-After" in r.headers
    relogio.avancar(minutes=1)
    assert cliente.post("/api/v1/prelogin", json={"email": "a@t.invalid"}).status_code == 200


def test_limites_usam_sha256_do_email(cliente, owner, banco):
    _login(cliente, EMAIL_OWNER, b64u(32))
    with psycopg.connect(banco["dono"]) as conn:
        chaves = [c for (c,) in conn.execute("SELECT chave FROM limites")]
    assert "conta:" + hashlib.sha256(EMAIL_OWNER.encode()).hexdigest() in chaves
    assert not any("@" in c for c in chaves)
