"""RF-I08 (Fase 3): expiração ociosa (15 min), absoluta (12 h) e logout."""

import psycopg
from conftest import EMAIL_OWNER, H, aceitar_e_logar


def _logado(cliente, org):
    aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    assert cliente.get("/api/v1/eu").status_code == 200


def test_ociosa_expira_401(cliente, org, relogio):
    _logado(cliente, org)
    relogio.avancar(minutes=15, seconds=1)
    assert cliente.get("/api/v1/eu").status_code == 401


def test_uso_renova_ociosa(cliente, org, relogio):
    _logado(cliente, org)
    for _ in range(3):
        relogio.avancar(minutes=14)
        assert cliente.get("/api/v1/eu").status_code == 200


def test_absoluta_12h_401_mesmo_em_uso(cliente, org, relogio):
    _logado(cliente, org)
    for _ in range(48):  # usa a cada 14min59s: chega a 11h59m12s sem ficar ociosa
        relogio.avancar(minutes=14, seconds=59)
        assert cliente.get("/api/v1/eu").status_code == 200
    relogio.avancar(minutes=14, seconds=59)  # 12h14m: só a absoluta venceu
    assert cliente.get("/api/v1/eu").status_code == 401


def test_ultimo_uso_antigo_no_banco_401(cliente, org, banco):
    """Checklist: cookie de sessão expirada alterando ultimo_uso no banco → 401."""
    _logado(cliente, org)
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE sessoes SET ultimo_uso = now() - interval '16 minutes'")
    assert cliente.get("/api/v1/eu").status_code == 401


def test_apos_logout_mesmo_cookie_401(cliente, org, novo_cliente):
    _logado(cliente, org)
    token = cliente.cookies.get("sessao")
    assert cliente.post("/api/v1/logout", headers=H).status_code == 204
    outro = novo_cliente()
    outro.cookies.set("sessao", token, domain="testserver", path="/api")
    assert outro.get("/api/v1/eu").status_code == 401
