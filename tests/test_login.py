"""RF-I02 (login por authHash, sessão por cookie) e DoD 4/5/6/9 da Fase 3."""

import hashlib
import re
from pathlib import Path

import psycopg
from conftest import EMAIL_OWNER, H, b64u

from app import seguranca

APP = Path(__file__).resolve().parent.parent / "app"


def test_rota_de_dados_sem_cookie_401(cliente):
    r = cliente.get("/api/v1/eu")
    assert (r.status_code, r.json()) == (401, {"erro": "nao_autenticado"})
    cliente.cookies.set("sessao", "inventado", domain="testserver", path="/api")
    assert cliente.get("/api/v1/eu").status_code == 401


def test_nenhuma_rota_aceita_x_senha_mestra():
    codigo = "\n".join(p.read_text(encoding="utf-8") for p in APP.rglob("*.py"))
    assert not re.search(r"senha-mestra|x-senha", codigo, re.IGNORECASE)


def test_login_ok_devolve_perfil_e_cookie_seguro(cliente, org):
    from conftest import payload_aceite

    dados = payload_aceite(org["token"])
    cliente.post("/api/v1/convites/aceitar", json=dados)
    r = cliente.post("/api/v1/login", json={"email": EMAIL_OWNER, "auth_hash": dados["auth_hash"]})
    assert r.status_code == 200
    corpo = r.json()
    assert corpo["usuario"] == {
        "id": org["usuario_id"],
        "org_id": org["org_id"],
        "email": EMAIL_OWNER,
        "nome": "Pessoa Teste",
        "papel": "owner",
        "estado": "ativo",
    }
    for campo in ("kdf", "sal", "chave_usuario_cif", "chave_privada_cif", "chave_publica"):
        assert corpo[campo] == dados[campo]
    assert corpo["mfa_pendente"] is False and corpo["politica"] == {"inatividade_min": 15}

    # DoD 6: HttpOnly, Secure, SameSite=Strict, Path=/api.
    cookie = r.headers["set-cookie"]
    partes = {p.strip().split("=")[0].lower(): p.strip() for p in cookie.split(";")}
    assert {"httponly", "secure"} <= set(partes)
    assert partes["samesite"].lower() == "samesite=strict"
    assert partes["path"] == "Path=/api"
    assert cliente.get("/api/v1/eu").json()["usuario"]["id"] == org["usuario_id"]


def test_sessao_so_hash_no_banco(cliente, owner, banco):
    token = cliente.cookies.get("sessao")
    with psycopg.connect(banco["dono"]) as conn:
        (guardado,) = conn.execute("SELECT token_hash FROM sessoes").fetchone()
    assert guardado == hashlib.sha256(token.encode()).digest()
    assert len(seguranca.de_b64u(token)) == 32  # 256 bits


def test_post_autenticado_sem_x_cofre_403(cliente, owner):
    r = cliente.post("/api/v1/logout")
    assert (r.status_code, r.json()) == (403, {"erro": "csrf"})
    r = cliente.post("/api/v1/logout", headers={"X-Cofre": "0"})
    assert r.status_code == 403
    assert cliente.post("/api/v1/logout", headers=H).status_code == 204


def test_inexistente_e_senha_errada_identicos_com_uma_verificacao(cliente, owner, monkeypatch):
    """DoD 4 / RNF-01: mesmo status e corpo; exatamente 1 verificação Argon2 em cada caso."""
    chamadas = []
    original = seguranca.verificar_auth

    def espia(*args):
        chamadas.append(args[0])
        return original(*args)

    monkeypatch.setattr(seguranca, "verificar_auth", espia)
    respostas = []
    for email in ("ninguem@teste.invalid", EMAIL_OWNER):
        chamadas.clear()
        r = cliente.post("/api/v1/login", json={"email": email, "auth_hash": b64u(32)})
        respostas.append((r.status_code, r.content))
        assert len(chamadas) == 1
    assert respostas[0] == respostas[1] == (401, b'{"erro":"credenciais_invalidas"}')


def test_prelogin_falso_deterministico(cliente, owner):
    """DoD 5: e-mail inexistente → mesmo sal sempre; outro e-mail → outro sal; mesmo formato."""

    def pre(email):
        r = cliente.post("/api/v1/prelogin", json={"email": email})
        assert r.status_code == 200
        return r.json()

    a1, a2, b = pre("x@t.invalid"), pre("X@T.invalid "), pre("y@t.invalid")
    real = pre(EMAIL_OWNER)
    assert a1 == a2 and a1["sal"] != b["sal"]
    assert set(a1) == set(real) == {"kdf", "sal"}
    assert a1["kdf"] == real["kdf"] == {"tipo": "argon2id", "m": 65536, "t": 3, "p": 1}
    assert len(seguranca.de_b64u(a1["sal"])) == len(seguranca.de_b64u(real["sal"])) == 16


def test_prelogin_de_convidado_e_falso(cliente, org):
    # Convidado ainda não tem KDF: responde como inexistente, sem revelar o convite.
    assert cliente.post("/api/v1/prelogin", json={"email": EMAIL_OWNER}).status_code == 200
    r = cliente.post("/api/v1/login", json={"email": EMAIL_OWNER, "auth_hash": b64u(32)})
    assert r.status_code == 401


def test_eventos_de_login_sem_email_em_claro(cliente, owner, banco):
    """DoD 9: auth.login ok e falha; meta da falha só com sha256(email)[:8]."""
    cliente.post("/api/v1/login", json={"email": EMAIL_OWNER, "auth_hash": b64u(32)})
    cliente.post("/api/v1/login", json={"email": "fantasma@teste.invalid", "auth_hash": b64u(32)})
    with psycopg.connect(banco["dono"]) as conn:
        eventos = conn.execute(
            "SELECT tipo, resultado, org_id IS NULL, meta::text FROM eventos"
            " WHERE tipo = 'auth.login' ORDER BY id"
        ).fetchall()
    assert [(t, r) for t, r, _, _ in eventos] == [
        ("auth.login", "ok"),
        ("auth.login", "falha"),
        ("auth.login", "falha"),
    ]
    assert eventos[2][2] is True  # e-mail inexistente: sem org
    for _, _, _, meta in eventos:
        assert "@" not in meta
    assert hashlib.sha256(b"fantasma@teste.invalid").hexdigest()[:8] in eventos[2][3]


def test_logout_revoga_e_registra(cliente, owner, banco):
    assert cliente.post("/api/v1/logout", headers=H).status_code == 204
    with psycopg.connect(banco["dono"]) as conn:
        assert conn.execute("SELECT revogada_em IS NOT NULL FROM sessoes").fetchone()[0]
        assert conn.execute("SELECT count(*) FROM eventos WHERE tipo = 'auth.logout'").fetchone()[0]
