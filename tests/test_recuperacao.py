"""RF-U06: recuperação por kit (recup_auth) + MFA; novo kit; revoga sessões."""

import psycopg
import pytest
from conftest import (
    EMAIL_OWNER,
    KDF,
    ativar_mfa,
    b64u,
    codigo_totp,
    env_v1,
    ler,
    login,
    payload_aceite,
    politica,
)

from app import seguranca

INICIAR, CONCLUIR = "/api/v1/recuperar/iniciar", "/api/v1/recuperar/concluir"


@pytest.fixture
def conta(cliente, org, banco):
    """Owner aceito com recup_auth conhecido, logado em `cliente`, sem MFA obrigatório."""
    politica(banco, mfa_obrigatorio=False)
    dados = payload_aceite(org["token"])
    assert cliente.post("/api/v1/convites/aceitar", json=dados).status_code == 201
    assert login(cliente, dados["auth_hash"]).status_code == 200
    return dados


def _iniciar(c, recup, email=EMAIL_OWNER, **extra):
    return c.post(INICIAR, json={"email": email, "recup_auth": recup, **extra})


def _conclusao(token):
    return {
        "token": token,
        "kdf": dict(KDF),
        "sal": b64u(16),
        "auth_hash": b64u(32),
        "chave_usuario_cif": env_v1(),
        "chave_usuario_recup_cif": env_v1(),
        "recup_auth": b64u(32),
    }


def test_recuperar_troca_senha_e_kit_e_derruba_sessoes(cliente, conta, novo_cliente, banco):
    """DoD 7 (lado servidor): nova senha entra; senha antiga, kit antigo e sessões caem."""
    c = novo_cliente()
    r = _iniciar(c, conta["recup_auth"])
    assert r.status_code == 200
    corpo = r.json()
    assert set(corpo) == {"token", "usuario_id", "chave_usuario_recup_cif"}
    assert corpo["chave_usuario_recup_cif"] == conta["chave_usuario_recup_cif"]
    assert c.cookies.get("sessao") is None  # recuperar não abre sessão

    nova = _conclusao(corpo["token"])
    assert c.post(CONCLUIR, json=nova).status_code == 204
    assert cliente.get("/api/v1/eu").status_code == 401  # sessão anterior caiu
    assert login(novo_cliente(), conta["auth_hash"]).status_code == 401  # senha antiga
    nova_sessao = novo_cliente()
    r = login(nova_sessao, nova["auth_hash"])
    assert r.status_code == 200
    assert r.json()["chave_usuario_cif"] == nova["chave_usuario_cif"]
    assert r.json()["sal"] == nova["sal"]
    assert _iniciar(novo_cliente(), conta["recup_auth"]).status_code == 401  # kit antigo
    assert _iniciar(novo_cliente(), nova["recup_auth"]).status_code == 200  # kit novo
    r = c.post(CONCLUIR, json=_conclusao(corpo["token"]))  # token já usado
    assert (r.status_code, r.json()) == (401, {"erro": "token_invalido"})
    etapas = ler(
        banco,
        "SELECT resultado, meta->>'etapa' FROM eventos WHERE tipo = 'auth.recuperacao' ORDER BY id",
    )
    assert etapas == [
        ("ok", "iniciada"),
        ("ok", "concluida"),
        ("falha", None),  # kit antigo
        ("ok", "iniciada"),
    ]
    (guardado,) = ler(banco, "SELECT recup_auth_hmac, auth_hash FROM usuarios")
    assert guardado[1].startswith("$argon2id$")
    assert seguranca.de_b64u(nova["recup_auth"]) not in bytes(guardado[0])


def test_inexistente_e_kit_errado_identicos_em_bytes(cliente, conta):
    def tentar(email):
        r = _iniciar(cliente, b64u(32), email=email)
        return r.status_code, r.content, r.headers.get("content-length")

    existente, inexistente = tentar(EMAIL_OWNER), tentar("ninguem@teste.invalid")
    assert existente == inexistente
    assert existente[:2] == (401, b'{"erro":"credenciais_invalidas"}')


@pytest.mark.parametrize("existe", [True, False], ids=["conta_existente", "conta_inexistente"])
def test_11_tentativas_erradas_429(cliente, conta, existe):
    email = EMAIL_OWNER if existe else "fantasma@teste.invalid"
    for _ in range(10):
        assert _iniciar(cliente, b64u(32), email=email).status_code == 401
    r = _iniciar(cliente, conta["recup_auth"], email=email)  # 11ª, com o kit certo
    assert (r.status_code, r.json()) == (429, {"erro": "bloqueado"})
    assert "Retry-After" in r.headers


def test_com_mfa_so_entrega_chave_apos_os_dois_fatores(cliente, conta, novo_cliente, relogio):
    """Checklist: chave_usuario_recup_cif só sai com recup_auth E segundo fator válidos."""
    segredo, codigos = ativar_mfa(cliente)
    relogio.avancar(seconds=30)
    r = _iniciar(novo_cliente(), conta["recup_auth"])
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_requerido"})
    errado = "000000" if codigo_totp(segredo) != "000000" else "111111"
    r = _iniciar(novo_cliente(), conta["recup_auth"], totp=errado)
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    r = _iniciar(novo_cliente(), b64u(32), totp=codigo_totp(segredo))  # kit errado
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
    r = _iniciar(novo_cliente(), conta["recup_auth"], totp=codigo_totp(segredo))
    assert r.status_code == 200 and "chave_usuario_recup_cif" in r.json()
    r = _iniciar(novo_cliente(), conta["recup_auth"], codigo_recuperacao=codigos[0])
    assert r.status_code == 200


def test_token_expirado_ou_inventado_401_sem_argon2(cliente, conta, banco, monkeypatch):
    """Checklist: concluir com token expirado (expira_em alterado) → 401."""
    token = _iniciar(cliente, conta["recup_auth"]).json()["token"]
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE recuperacoes SET expira_em = now() - interval '1 second'")
    chamadas = []
    monkeypatch.setattr(seguranca, "hash_auth", lambda *a: chamadas.append(a))
    for t in (token, "inventado"):
        r = cliente.post(CONCLUIR, json=_conclusao(t))
        assert (r.status_code, r.json()) == (401, {"erro": "token_invalido"})
    assert chamadas == []  # token inválido não gasta Argon2
    assert login(cliente, conta["auth_hash"]).status_code == 200  # nada mudou


def test_token_vale_5_minutos(cliente, conta, relogio):
    token = _iniciar(cliente, conta["recup_auth"]).json()["token"]
    relogio.avancar(minutes=5, seconds=1)
    assert cliente.post(CONCLUIR, json=_conclusao(token)).status_code == 401


def test_concluir_valida_formato(cliente, conta):
    token = _iniciar(cliente, conta["recup_auth"]).json()["token"]
    ruim = _conclusao(token) | {"kdf": {**KDF, "t": 1}}
    assert cliente.post(CONCLUIR, json=ruim).status_code == 422
    ruim = _conclusao(token) | {"chave_usuario_recup_cif": "v2.x.y"}
    assert cliente.post(CONCLUIR, json=ruim).status_code == 422
    assert cliente.post(CONCLUIR, json=_conclusao(token)).status_code == 204


def test_suspenso_nao_recupera(cliente, conta, banco):
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE usuarios SET estado = 'suspenso'")
    r = _iniciar(cliente, conta["recup_auth"])
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
