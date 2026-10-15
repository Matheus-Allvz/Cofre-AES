"""RF-I03 (TOTP + códigos de recuperação) e RF-I04/RF-P02 (MFA obrigatório por política)."""

import re
import threading
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from conftest import (
    EMAIL_OWNER,
    H,
    aceitar_e_logar,
    ativar_mfa,
    codigo_totp,
    ler,
    login,
    politica,
)
from fastapi import HTTPException

from app import db, mfa, seguranca, totp
from app.rotas.auth import SQL_USUARIO

V1 = re.compile(r"^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$")


def test_pendente_so_acessa_eu_mfa_e_logout_ate_confirmar(cliente, org, relogio, banco):
    """DoD 4 / RF-I04: política com MFA obrigatório + usuário sem MFA → login 200 com
    mfa_pendente (o padrão é opcional desde a Fase 7)."""
    politica(banco, mfa_obrigatorio=True)
    auth = aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    r = login(cliente, auth)
    assert r.status_code == 200 and r.json()["mfa_pendente"] is True
    assert cliente.get("/api/v1/eu").json()["mfa_pendente"] is True
    bloqueadas = [
        ("GET", "/api/v1/org", None),
        ("GET", "/api/v1/eu/sessoes", None),
        ("GET", "/api/v1/eu/eventos", None),
        ("POST", "/api/v1/convites", {"email": "x@t.invalid", "papel": "member"}),
        ("PUT", "/api/v1/org/politica", {"mfa_obrigatorio": False, "inatividade_min": 15}),
    ]
    for metodo, rota, corpo in bloqueadas:
        r = cliente.request(metodo, rota, json=corpo, headers=H)
        assert (r.status_code, r.json()) == (403, {"erro": "mfa_configuracao_requerida"}), rota

    ativar_mfa(cliente)
    assert cliente.get("/api/v1/org").status_code == 200  # mesma sessão, liberada
    eu = cliente.get("/api/v1/eu").json()
    assert (eu["mfa_ativo"], eu["mfa_pendente"]) == (True, False)


def test_ligar_politica_vale_na_hora_para_sessao_aberta(cliente, owner, banco):
    assert cliente.get("/api/v1/org").status_code == 200
    politica(banco, mfa_obrigatorio=True)
    assert cliente.get("/api/v1/org").json() == {"erro": "mfa_configuracao_requerida"}


def test_login_exige_totp_e_recusa_reuso_no_mesmo_passo(cliente, owner_mfa, novo_cliente, relogio):
    """RF-I03 / DoD 3."""
    auth, segredo = owner_mfa["auth_hash"], owner_mfa["segredo"]
    r = login(novo_cliente(), auth)
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_requerido"})
    r = login(novo_cliente(), auth, totp="000000" if codigo_totp(segredo) != "000000" else "111111")
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})

    codigo = codigo_totp(segredo)
    assert login(novo_cliente(), auth, totp=codigo).status_code == 200
    r = login(novo_cliente(), auth, totp=codigo)  # mesmo passo, de novo
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    r = login(novo_cliente(), auth, totp=codigo_totp(segredo, -1))  # passo anterior ao usado
    assert r.status_code == 401
    assert login(novo_cliente(), auth, totp=codigo_totp(segredo, +1)).status_code == 200  # ±1
    relogio.avancar(seconds=60)
    assert login(novo_cliente(), auth, totp=codigo_totp(segredo)).status_code == 200


def test_totp_mesmo_passo_em_paralelo_so_um_passa(cliente, owner_mfa):
    """Anti-replay atômico: 10 verificações simultâneas do mesmo código → exatamente 1 ok."""
    from app.main import app

    pool, segredo = app.state.pool, app.state.config.cofre_segredo
    with db.transacao(pool) as conn:
        u = db.linha(conn, SQL_USUARIO + " WHERE u.email = %s", (EMAIL_OWNER,))
    codigo = codigo_totp(owner_mfa["segredo"])
    barreira = threading.Barrier(10)

    def uma(_):
        barreira.wait()
        try:
            mfa.exigir_segundo_fator(pool, segredo, u, codigo, None, {})
            return 1
        except HTTPException as e:
            assert e.detail == "mfa_invalido"
            return 0

    with ThreadPoolExecutor(10) as ex:
        assert sum(ex.map(uma, range(10))) == 1


def test_codigo_de_recuperacao_uso_unico(cliente, owner_mfa, novo_cliente, banco):
    auth, codigos = owner_mfa["auth_hash"], owner_mfa["codigos"]
    assert len(codigos) == 10 == len(set(codigos))
    assert all(re.fullmatch(r"[A-Z2-7]{4}-[A-Z2-7]{4}", c) for c in codigos)
    assert login(novo_cliente(), auth, codigo_recuperacao=codigos[0]).status_code == 200
    r = login(novo_cliente(), auth, codigo_recuperacao=codigos[0])
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    # Aceita minúsculas e sem hífen.
    digitado = codigos[1].replace("-", "").lower()
    assert login(novo_cliente(), auth, codigo_recuperacao=digitado).status_code == 200
    assert login(novo_cliente(), auth, codigo_recuperacao="AAAA-AAAA").status_code == 401
    tipos = [t for (t,) in ler(banco, "SELECT tipo FROM eventos ORDER BY id")]
    assert tipos.count("mfa.codigo_recuperacao_usado") == 2


def test_segredo_cifrado_e_codigos_so_como_hmac(cliente, owner_mfa, banco):
    """DoD 3: totp_segredo_cif casa com v1 e não contém o base32; códigos só como HMAC."""
    from app.main import app

    b32 = totp.base32(owner_mfa["segredo"])
    ((cif,),) = ler(banco, "SELECT totp_segredo_cif FROM usuarios")
    assert V1.match(cif) and b32 not in cif
    hmacs = [bytes(h) for (h,) in ler(banco, "SELECT codigo_hmac FROM codigos_mfa")]
    servidor = app.state.config.cofre_segredo
    assert sorted(hmacs) == sorted(mfa.hmac_codigo(servidor, c) for c in owner_mfa["codigos"])
    tudo = " ".join(
        t
        for tabela in ("usuarios", "codigos_mfa", "eventos", "sessoes")
        for (t,) in ler(banco, f"SELECT row_to_json(x)::text FROM {tabela} x")  # noqa: S608
    )
    for proibido in [b32, owner_mfa["segredo"].hex(), *owner_mfa["codigos"]]:
        assert proibido not in tudo
    assert all(c.replace("-", "") not in tudo for c in owner_mfa["codigos"])


def test_iniciar_e_confirmar_erros(cliente, org, relogio):
    aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "123456"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "mfa_nao_iniciado"})
    r = cliente.post("/api/v1/eu/mfa/iniciar", headers=H)
    corpo = r.json()
    assert set(corpo) == {"segredo_base32", "otpauth_uri"}
    assert f"secret={corpo['segredo_base32']}" in corpo["otpauth_uri"]
    assert corpo["otpauth_uri"].startswith("otpauth://totp/Cofre%20AES%3Aowner%40teste.invalid?")
    r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "12345a"}, headers=H)
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    ativar_mfa(cliente)  # novo iniciar substitui o segredo não confirmado
    assert cliente.post("/api/v1/eu/mfa/iniciar", headers=H).json() == {"erro": "mfa_ja_ativo"}
    r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "123456"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "mfa_ja_ativo"})


def test_confirmar_errado_conta_contra_a_conta(cliente, org, relogio):
    auth = aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    cliente.post("/api/v1/eu/mfa/iniciar", headers=H)
    for _ in range(10):
        r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "abcdef"}, headers=H)
        assert r.status_code == 401
    r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "abcdef"}, headers=H)
    assert (r.status_code, r.json()) == (429, {"erro": "bloqueado"})
    assert login(cliente, auth).status_code == 429


def test_desativar_mfa(cliente, owner_mfa, novo_cliente, banco, relogio):
    auth, segredo = owner_mfa["auth_hash"], owner_mfa["segredo"]

    def desativar(a, codigo):
        corpo = {"auth_hash": a, "codigo": codigo}
        return cliente.request("DELETE", "/api/v1/eu/mfa", json=corpo, headers=H)

    r = desativar(auth, codigo_totp(segredo))
    assert (r.status_code, r.json()) == (403, {"erro": "politica_mfa"})  # checklist
    politica(banco, mfa_obrigatorio=False)
    r = desativar(seguranca.b64u(b"x" * 32), codigo_totp(segredo))
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
    r = desativar(auth, "999999" if codigo_totp(segredo) != "999999" else "888888")
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    assert desativar(auth, owner_mfa["codigos"][0]).status_code == 204  # código de recuperação
    assert ler(banco, "SELECT count(*) FROM codigos_mfa") == [(0,)]
    assert ler(banco, "SELECT totp_segredo_cif, totp_ultimo_passo FROM usuarios") == [(None, None)]
    r = desativar(auth, codigo_totp(segredo))
    assert (r.status_code, r.json()) == (409, {"erro": "mfa_inativo"})
    assert login(novo_cliente(), auth).status_code == 200  # sem fator
    tipos = [t for (t,) in ler(banco, "SELECT tipo FROM eventos WHERE resultado = 'ok'")]
    assert "mfa.ativado" in tipos and "mfa.desativado" in tipos


@pytest.mark.parametrize("rota", ["/api/v1/eu/mfa/iniciar", "/api/v1/eu/mfa/confirmar"])
def test_mfa_exige_sessao(cliente, rota):
    assert cliente.post(rota, json={"codigo": "123456"}, headers=H).status_code == 401


@pytest.mark.parametrize("adulteracao", ["outro_usuario", "bit_trocado"])
def test_segredo_totp_adulterado_401_com_evento(
    cliente, owner_mfa, novo_cliente, banco, adulteracao
):
    """Correção pós-validação: envelope do TOTP adulterado/trocado → 401 mfa_invalido, não 500."""
    from app import cifra_servidor
    from app.main import app

    servidor = app.state.config.cofre_segredo
    if adulteracao == "outro_usuario":  # envelope válido, mas de outro usuário (AAD diferente)
        cif = cifra_servidor.cifrar(servidor, "00000000-0000-0000-0000-000000000000", b"x" * 20)
    else:
        ((cif,),) = ler(banco, "SELECT totp_segredo_cif FROM usuarios")
        cif = cif[:-2] + ("AA" if cif[-2:] != "AA" else "BB")
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE usuarios SET totp_segredo_cif = %s", (cif,))
    r = login(novo_cliente(), owner_mfa["auth_hash"], totp=codigo_totp(owner_mfa["segredo"]))
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})
    eventos = ler(banco, "SELECT resultado, meta->>'metodo' FROM eventos WHERE tipo = 'auth.mfa'")
    assert eventos[-1] == ("falha", "totp_segredo_invalido")


def test_confirmar_com_segredo_adulterado_401(cliente, org, banco, relogio):
    aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    cliente.post("/api/v1/eu/mfa/iniciar", headers=H)
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute(
            "UPDATE usuarios SET totp_segredo_cif = 'v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA'"
        )
    r = cliente.post("/api/v1/eu/mfa/confirmar", json={"codigo": "123456"}, headers=H)
    assert (r.status_code, r.json()) == (401, {"erro": "mfa_invalido"})


def test_desativar_mfa_derruba_outras_sessoes(cliente, owner_mfa, novo_cliente, banco):
    """Correção pós-validação: desativar o MFA revoga as outras sessões do usuário."""
    politica(banco, mfa_obrigatorio=False)
    outra = novo_cliente()
    assert (
        login(outra, owner_mfa["auth_hash"], codigo_recuperacao=owner_mfa["codigos"][0]).status_code
        == 200
    )
    corpo = {"auth_hash": owner_mfa["auth_hash"], "codigo": codigo_totp(owner_mfa["segredo"])}
    assert cliente.request("DELETE", "/api/v1/eu/mfa", json=corpo, headers=H).status_code == 204
    assert outra.get("/api/v1/eu").status_code == 401
    assert cliente.get("/api/v1/eu").status_code == 200  # a sessão que desativou continua
