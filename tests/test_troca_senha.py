"""RF-I10 (Fase 3, sem TOTP) e DoD 7: troca de senha-mestra re-envelopa a userKey."""

import psycopg
from conftest import EMAIL_OWNER, KDF, H, b64u, env_v1


def _troca(auth_atual, auth_nova, **extra):
    return {
        "auth_hash_atual": auth_atual,
        "kdf": dict(KDF),
        "sal": b64u(16),
        "auth_hash": auth_nova,
        "chave_usuario_cif": env_v1(),
        **extra,
    }


def _login(c, auth):
    return c.post("/api/v1/login", json={"email": EMAIL_OWNER, "auth_hash": auth})


def test_troca_mantem_sessao_atual_derruba_outras_e_senha_antiga(
    cliente, owner, novo_cliente, banco
):
    outra = novo_cliente()
    assert _login(outra, owner["auth_hash"]).status_code == 200
    nova = b64u(32)
    corpo = _troca(owner["auth_hash"], nova)
    assert cliente.post("/api/v1/eu/senha", json=corpo, headers=H).status_code == 204

    eu = cliente.get("/api/v1/eu")
    assert eu.status_code == 200  # sessão usada continua válida
    assert eu.json()["chave_usuario_cif"] == corpo["chave_usuario_cif"]
    assert eu.json()["sal"] == corpo["sal"]
    assert outra.get("/api/v1/eu").status_code == 401  # outra sessão caiu
    assert _login(novo_cliente(), owner["auth_hash"]).status_code == 401  # senha antiga
    assert _login(novo_cliente(), nova).status_code == 200
    with psycopg.connect(banco["dono"]) as conn:
        tipos = [t for (t,) in conn.execute("SELECT tipo FROM eventos WHERE resultado = 'ok'")]
    assert "auth.senha_trocada" in tipos


def test_troca_com_senha_atual_errada_401(cliente, owner):
    r = cliente.post("/api/v1/eu/senha", json=_troca(b64u(32), b64u(32)), headers=H)
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
    assert _login(cliente, owner["auth_hash"]).status_code == 200


def test_troca_exige_x_cofre_e_kdf_padrao(cliente, owner):
    corpo = _troca(owner["auth_hash"], b64u(32))
    assert cliente.post("/api/v1/eu/senha", json=corpo).status_code == 403
    corpo["kdf"]["t"] = 1
    assert cliente.post("/api/v1/eu/senha", json=corpo, headers=H).status_code == 422
