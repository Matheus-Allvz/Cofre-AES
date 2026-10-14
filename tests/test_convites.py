"""RF-I01 (convite de uso único, 72 h, hash no banco) e RF-U01 até `aceito`."""

import psycopg
import pytest
from conftest import EMAIL_OWNER, H, aceitar_e_logar, payload_aceite

from app import cli, seguranca

ACEITAR = "/api/v1/convites/aceitar"


def convidar(c, email, papel="member"):
    r = c.post("/api/v1/convites", json={"email": email, "papel": papel}, headers=H)
    assert r.status_code == 201, r.text
    return r.json() | {"token": r.json()["link"].removeprefix("/#/convite/")}


def test_aceitar_token_inexistente_404(cliente, org):
    r = cliente.post(ACEITAR, json=payload_aceite("nao-existe"))
    assert (r.status_code, r.json()) == (404, {"erro": "convite_invalido"})


def test_consultar_convite(cliente, org):
    r = cliente.post("/api/v1/convites/consultar", json={"token": org["token"]})
    assert r.status_code == 200
    assert r.json() == {
        "usuario_id": org["usuario_id"],
        "org_id": org["org_id"],
        "org_nome": "Org Teste",
        "email": EMAIL_OWNER,
        "papel": "owner",
    }
    r = cliente.post("/api/v1/convites/consultar", json={"token": "x"})
    assert (r.status_code, r.json()) == (404, {"erro": "convite_invalido"})


def test_bootstrap_vira_ativo_com_proprio_fingerprint(cliente, org, banco):
    dados = payload_aceite(org["token"])
    r = cliente.post(ACEITAR, json=dados)
    assert r.status_code == 201
    assert r.json() == {"usuario_id": org["usuario_id"], "estado": "ativo"}
    with psycopg.connect(banco["dono"]) as conn:
        fp, conf = conn.execute(
            "SELECT fingerprint_confirmado, confirmado_por::text FROM usuarios"
        ).fetchone()
    assert fp == seguranca.fingerprint(seguranca.de_b64u(dados["chave_publica"]))
    assert conf == org["usuario_id"]


def test_segundo_uso_410(cliente, org):
    assert cliente.post(ACEITAR, json=payload_aceite(org["token"])).status_code == 201
    r = cliente.post(ACEITAR, json=payload_aceite(org["token"]))
    assert (r.status_code, r.json()) == (410, {"erro": "convite_expirado"})
    r = cliente.post("/api/v1/convites/consultar", json={"token": org["token"]})
    assert (r.status_code, r.json()) == (410, {"erro": "convite_expirado"})


def test_expirado_410(cliente, banco, relogio):
    org = cli.criar_org(banco["app"], "Org", EMAIL_OWNER)
    relogio.avancar(hours=72, seconds=1)
    r = cliente.post(ACEITAR, json=payload_aceite(org["token"]))
    assert (r.status_code, r.json()) == (410, {"erro": "convite_expirado"})


def test_nao_existe_cadastro_aberto(cliente):
    assert cliente.post("/api/v1/usuarios", json={}).status_code in (404, 405)


@pytest.mark.parametrize(
    "kdf",
    [
        {"tipo": "argon2id", "m": 1024, "t": 3, "p": 1},
        {"tipo": "argon2id", "m": 65536.0, "t": 3, "p": 1},
        {"tipo": "argon2id", "m": 65536, "t": 3, "p": 1, "x": 1},
        {"tipo": "pbkdf2", "m": 65536, "t": 3, "p": 1},
    ],
)
def test_kdf_diferente_do_padrao_422(cliente, org, kdf):
    assert cliente.post(ACEITAR, json=payload_aceite(org["token"], kdf=kdf)).status_code == 422


@pytest.mark.parametrize(
    "campo,valor",
    [
        ("chave_usuario_cif", "v2.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA"),
        ("chave_privada_cif", "v1.curto.AAAAAAAAAAAAAAAAAAAAAA"),
        ("chave_usuario_recup_cif", "v1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAA=="),
        ("chave_usuario_cif", "v1.AAAAAAAAAAAAAAAA." + "A" * 70000),
        ("auth_hash", "A" * 42),
        ("recup_auth", "+" * 43),
        ("chave_publica", "A" * 44),
        ("sal", "A" * 21),
    ],
    ids=["v2", "iv_curto", "padding", "64KiB", "auth_42", "recup_b64", "pub_44", "sal_21"],
)
def test_formato_invalido_422(cliente, org, campo, valor):
    r = cliente.post(ACEITAR, json=payload_aceite(org["token"], **{campo: valor}))
    assert r.status_code == 422
    # Nada foi gravado: o convite continua utilizável.
    assert cliente.post(ACEITAR, json=payload_aceite(org["token"])).status_code == 201


def test_member_nao_convida_403(cliente, owner, novo_cliente):
    convite = convidar(cliente, "m@t.invalid")
    member = novo_cliente()
    aceitar_e_logar(member, convite["token"], "m@t.invalid")
    r = member.post("/api/v1/convites", json={"email": "x@t.invalid", "papel": "member"}, headers=H)
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})


def test_owner_convida_member_que_fica_aceito(cliente, owner, novo_cliente, banco):
    convite = convidar(cliente, "M@T.invalid")
    r = novo_cliente().post(ACEITAR, json=payload_aceite(convite["token"]))
    assert r.json() == {"usuario_id": convite["usuario_id"], "estado": "aceito"}
    with psycopg.connect(banco["dono"]) as conn:
        email, fp = conn.execute(
            "SELECT email, fingerprint_confirmado FROM usuarios WHERE id = %s",
            (convite["usuario_id"],),
        ).fetchone()
    assert email == "m@t.invalid"
    assert fp is None  # aceito -> ativo só com conferência do admin (Fase 5)


def test_convite_email_em_uso_409(cliente, owner):
    r = cliente.post("/api/v1/convites", json={"email": EMAIL_OWNER, "papel": "admin"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "email_em_uso"})


@pytest.mark.parametrize(
    "corpo",
    [{"email": "x@t.invalid", "papel": "owner"}, {"email": "sem-arroba", "papel": "member"}],
)
def test_convite_valida_entrada(cliente, owner, corpo):
    assert cliente.post("/api/v1/convites", json=corpo, headers=H).status_code == 422


def test_revogar_convite(cliente, owner):
    convite = convidar(cliente, "r@t.invalid")
    assert cliente.delete(f"/api/v1/convites/{convite['convite_id']}", headers=H).status_code == 204
    assert cliente.delete(f"/api/v1/convites/{convite['convite_id']}", headers=H).status_code == 204
    r = cliente.post(ACEITAR, json=payload_aceite(convite["token"]))
    assert (r.status_code, r.json()) == (410, {"erro": "convite_expirado"})
    convidar(cliente, "r@t.invalid")  # e-mail liberado para novo convite


def test_revogar_convite_usado_409_e_inexistente_404(cliente, owner, banco):
    with psycopg.connect(banco["dono"]) as conn:
        (bootstrap,) = conn.execute("SELECT id::text FROM convites").fetchone()
    r = cliente.delete(f"/api/v1/convites/{bootstrap}", headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "convite_usado"})
    r = cliente.delete("/api/v1/convites/00000000-0000-0000-0000-000000000000", headers=H)
    assert r.status_code == 404


def test_aceite_nao_guarda_segredo_em_claro(cliente, org, banco):
    """DoD 8: auth_hash só como $argon2id$; nada do auth_hash/recup_auth enviados no banco."""
    dados = payload_aceite(org["token"])
    assert cliente.post(ACEITAR, json=dados).status_code == 201
    with psycopg.connect(banco["dono"]) as conn:
        (auth_hash,) = conn.execute("SELECT auth_hash FROM usuarios").fetchone()
        tudo = " ".join(
            t
            for tabela in ("usuarios", "convites", "eventos")
            for (t,) in conn.execute(f"SELECT row_to_json(x)::text FROM {tabela} x")  # noqa: S608
        )
    assert auth_hash.startswith("$argon2id$")
    for campo in ("auth_hash", "recup_auth"):
        assert dados[campo] not in tudo
        assert seguranca.de_b64u(dados[campo]).hex() not in tudo  # bytea vira \x<hex>
    assert org["token"] not in tudo


def test_aceite_gera_evento(cliente, org, banco):
    cliente.post(ACEITAR, json=payload_aceite(org["token"]))
    with psycopg.connect(banco["dono"]) as conn:
        tipos = [t for (t,) in conn.execute("SELECT tipo FROM eventos ORDER BY id")]
    assert tipos == ["org.criada", "convite.criado", "convite.aceito"]
