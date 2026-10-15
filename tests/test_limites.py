"""RNF-01: 10 falhas por conta → bloqueio 15 min; 20 req/min por IP nas rotas públicas."""

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from conftest import EMAIL_OWNER, b64u
from fastapi import HTTPException

from app import limites


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
    assert _login(cliente, EMAIL_OWNER, owner["auth_hash"]).status_code == 429  # bloqueia aqui
    relogio.avancar(minutes=14, seconds=59)
    r = _login(cliente, EMAIL_OWNER, owner["auth_hash"])
    assert r.status_code == 429 and r.headers["Retry-After"] == "1"  # bloqueio não se estende
    relogio.avancar(seconds=1)
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


def _em_paralelo(funcao, n=30):
    """Dispara n chamadas juntas (barreira) e devolve quantas passaram sem 429."""
    barreira = threading.Barrier(n)

    def uma(_):
        barreira.wait()
        try:
            funcao()
            return True
        except HTTPException as e:
            assert e.status_code == 429
            return False

    with ThreadPoolExecutor(n) as ex:
        return sum(ex.map(uma, range(n)))


def test_lockout_atomico_com_threads(cliente):
    """Corrida: 30 tentativas simultâneas da mesma conta → exatamente 10 passam."""
    from app.main import app

    pool = app.state.pool
    assert _em_paralelo(lambda: limites.tentar_conta(pool, "corrida@t.invalid")) == 10
    with pytest.raises(HTTPException):
        limites.tentar_conta(pool, "corrida@t.invalid")


def test_limite_de_ip_atomico_com_threads(cliente):
    from app.main import app

    pool = app.state.pool
    assert _em_paralelo(lambda: limites.contar_ip(pool, "192.0.2.1", "login")) == 20
