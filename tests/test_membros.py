"""Fase 5 — membros da organização: RF-O02 (parcial), RF-U01, RF-U02, RNF-15d, RF-A01 (membro.*)."""

import threading
import uuid

import psycopg
import pytest
from conftest import (
    EMAIL_OWNER,
    KDF,
    H,
    aceitar_e_logar,
    ativar,
    b64u,
    convidar,
    env_v1,
    ler,
    login,
    payload_aceite,
)

from app import seguranca

M = "/api/v1/membros"
NADA = "00000000-0000-0000-0000-000000000000"


def _fp(pub: str) -> str:
    return seguranca.fingerprint(seguranca.de_b64u(pub))


def _estado(banco, uid):
    return ler(banco, "SELECT estado FROM usuarios WHERE id = %s", (uid,))[0][0]


def _alvo(gestor, novo_cliente, estado: str, email: str) -> dict:
    """Usuário no estado pedido, criado só pelos fluxos reais (convite, aceite, rotas da fase)."""
    if estado == "convidado":
        c = convidar(gestor, email)
        return {"id": c["usuario_id"], "chave_publica": b64u(32), "convite": c}
    if estado == "aceito":
        c = convidar(gestor, email)
        pub = b64u(32)
        cli = novo_cliente()
        aceite = payload_aceite(c["token"], chave_publica=pub)
        assert cli.post("/api/v1/convites/aceitar", json=aceite).status_code == 201
        return {"id": c["usuario_id"], "chave_publica": pub, "cliente": cli}
    m = ativar(gestor, novo_cliente, email)
    if estado == "suspenso":
        assert gestor.post(f"{M}/{m['id']}/suspender", headers=H).status_code == 200
    elif estado == "removido":
        assert gestor.delete(f"{M}/{m['id']}", headers=H).status_code == 200
    return m


def _executar(c, acao: str, alvo: dict, **extra):
    url = f"{M}/{alvo['id']}"
    if acao == "confirmar":
        fp = extra.get("fingerprint", _fp(alvo["chave_publica"]))
        return c.post(f"{url}/confirmar", json={"fingerprint": fp}, headers=H)
    if acao == "papel":
        return c.put(f"{url}/papel", json={"papel": extra.get("papel", "admin")}, headers=H)
    if acao == "remover":
        return c.delete(url, headers=H)
    return c.post(f"{url}/{acao}", headers=H)


# ---------- GET /membros ----------


def test_listar(cliente, owner, novo_cliente, banco):
    ativo = ativar(cliente, novo_cliente, "ativo@t.invalid")
    aceito = _alvo(cliente, novo_cliente, "aceito", "aceito@t.invalid")
    convidado = _alvo(cliente, novo_cliente, "convidado", "convidado@t.invalid")
    _alvo(cliente, novo_cliente, "removido", "removido@t.invalid")

    r = cliente.get(M)
    assert r.status_code == 200
    por_email = {m["email"]: m for m in r.json()}
    assert set(por_email) == {
        EMAIL_OWNER,
        "ativo@t.invalid",
        "aceito@t.invalid",
        "convidado@t.invalid",
    }
    assert set(por_email["ativo@t.invalid"]) == {
        "id",
        "email",
        "nome",
        "papel",
        "estado",
        "chave_publica",
        "fingerprint_confirmado",
    }
    assert por_email["ativo@t.invalid"] == {
        "id": ativo["id"],
        "email": "ativo@t.invalid",
        "nome": "Pessoa Teste",
        "papel": "member",
        "estado": "ativo",
        "chave_publica": ativo["chave_publica"],
        "fingerprint_confirmado": _fp(ativo["chave_publica"]),
    }
    assert por_email["aceito@t.invalid"]["chave_publica"] == aceito["chave_publica"]
    assert por_email["aceito@t.invalid"]["fingerprint_confirmado"] is None
    assert por_email["convidado@t.invalid"]["id"] == convidado["id"]
    assert por_email["convidado@t.invalid"]["chave_publica"] is None

    assert ativo["cliente"].get(M).status_code == 200  # member ativo lê
    assert novo_cliente().get(M).status_code == 401


def test_aceito_nao_lista(cliente, owner, novo_cliente):
    c = convidar(cliente, "n@t.invalid")
    n = novo_cliente()
    aceitar_e_logar(n, c["token"], "n@t.invalid")
    assert (n.get(M).status_code, n.get(M).json()) == (403, {"erro": "sem_permissao"})


# ---------- DoD 2: máquina de estados ----------

VALIDOS = {
    "confirmar": {"aceito": "ativo"},
    "suspender": {"ativo": "suspenso"},
    "reativar": {"suspenso": "ativo"},
    "papel": {"aceito": "aceito", "ativo": "ativo", "suspenso": "suspenso"},
    "remover": {"convidado": "removido", "aceito": "removido", "ativo": "removido"}
    | {"suspenso": "removido"},
}
ESTADOS = ["convidado", "aceito", "ativo", "suspenso", "removido"]


@pytest.mark.parametrize("estado", ESTADOS)
@pytest.mark.parametrize("acao", list(VALIDOS))
def test_transicoes(cliente, owner, novo_cliente, banco, acao, estado):
    alvo = _alvo(cliente, novo_cliente, estado, "alvo@t.invalid")
    r = _executar(cliente, acao, alvo)
    if estado in VALIDOS[acao]:
        assert r.status_code == 200, r.text
        assert _estado(banco, alvo["id"]) == VALIDOS[acao][estado]
    else:
        assert (r.status_code, r.json()) == (409, {"erro": "estado_invalido"})
        assert _estado(banco, alvo["id"]) == estado


@pytest.mark.parametrize("acao", list(VALIDOS))
def test_alvo_inexistente_404(cliente, owner, acao):
    r = _executar(cliente, acao, {"id": NADA, "chave_publica": b64u(32)})
    assert (r.status_code, r.json()) == (404, {"erro": "nao_encontrado"})
    assert cliente.post(f"{M}/nao-uuid/suspender", headers=H).status_code == 422


# ---------- DoD 3: confirmação com fingerprint ----------


def test_confirmar_fingerprint(cliente, owner, novo_cliente, banco):
    alvo = _alvo(cliente, novo_cliente, "aceito", "a@t.invalid")
    certo = _fp(alvo["chave_publica"])
    errado = _fp(b64u(32))
    r = _executar(cliente, "confirmar", alvo, fingerprint=errado)
    assert (r.status_code, r.json()) == (422, {"erro": "fingerprint_divergente"})
    assert _estado(banco, alvo["id"]) == "aceito"
    assert ler(banco, "SELECT count(*) FROM eventos WHERE tipo = 'membro.confirmado'") == [(0,)]

    # Conferido por voz/chat: aceita sem espaços e em minúsculas.
    r = _executar(cliente, "confirmar", alvo, fingerprint=certo.replace(" ", "").lower())
    assert r.status_code == 200
    assert r.json() == {"id": alvo["id"], "estado": "ativo", "fingerprint_confirmado": certo}
    assert ler(
        banco,
        "SELECT estado, fingerprint_confirmado, confirmado_por::text FROM usuarios WHERE id = %s",
        (alvo["id"],),
    ) == [("ativo", certo, owner["usuario_id"])]
    ((ator, alvo_id, meta),) = ler(
        banco, "SELECT ator_id::text, alvo_id, meta FROM eventos WHERE tipo = 'membro.confirmado'"
    )
    assert (ator, alvo_id, meta) == (owner["usuario_id"], alvo["id"], {})


def test_confirmado_usa_sessao_existente(cliente, owner, novo_cliente):
    c = convidar(cliente, "s@t.invalid")
    m = novo_cliente()
    pub = b64u(32)
    auth = b64u(32)
    m.post("/api/v1/convites/aceitar", json=payload_aceite(c["token"], auth, chave_publica=pub))
    assert login(m, auth, "s@t.invalid").status_code == 200
    assert m.get("/api/v1/org").status_code == 403
    _executar(cliente, "confirmar", {"id": c["usuario_id"], "chave_publica": pub})
    assert m.get("/api/v1/org").status_code == 200


# ---------- DoD 4: suspensão ----------


def test_suspender_derruba_sessoes_e_login(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "m@t.invalid")
    outra = novo_cliente()
    assert login(outra, m["auth_hash"], "m@t.invalid").status_code == 200
    assert _executar(cliente, "suspender", m).json() == {"id": m["id"], "estado": "suspenso"}

    assert m["cliente"].get("/api/v1/eu").status_code == 401
    assert outra.get("/api/v1/eu").status_code == 401
    assert ler(
        banco,
        "SELECT count(*) FROM sessoes WHERE usuario_id = %s AND revogada_em IS NULL",
        (m["id"],),
    ) == [(0,)]
    r = login(novo_cliente(), m["auth_hash"], "m@t.invalid")
    assert (r.status_code, r.json()) == (403, {"erro": "conta_suspensa"})
    assert ler(banco, "SELECT count(*) FROM eventos WHERE tipo = 'membro.suspenso'") == [(1,)]

    # Reativar devolve o login, não as sessões antigas.
    assert _executar(cliente, "reativar", m).json() == {"id": m["id"], "estado": "ativo"}
    assert m["cliente"].get("/api/v1/eu").status_code == 401
    assert login(novo_cliente(), m["auth_hash"], "m@t.invalid").status_code == 200
    assert ler(banco, "SELECT count(*) FROM eventos WHERE tipo = 'membro.reativado'") == [(1,)]


# ---------- Herdado: suspender/remover invalidam tokens de recuperação pendentes ----------


@pytest.mark.parametrize("acao", ["suspender_reativar", "remover"])
def test_suspender_ou_remover_invalida_recuperacao(cliente, owner, novo_cliente, banco, acao):
    recup = b64u(32)
    c = convidar(cliente, "r@t.invalid")
    m, pub = novo_cliente(), b64u(32)
    aceite = payload_aceite(c["token"], recup_auth=recup, chave_publica=pub)
    assert m.post("/api/v1/convites/aceitar", json=aceite).status_code == 201
    alvo = {"id": c["usuario_id"], "chave_publica": pub}
    _executar(cliente, "confirmar", alvo)
    r = m.post("/api/v1/recuperar/iniciar", json={"email": "r@t.invalid", "recup_auth": recup})
    assert r.status_code == 200
    token = r.json()["token"]

    if acao == "remover":
        assert _executar(cliente, "remover", alvo).status_code == 200
    else:  # dentro dos 5 min do token
        assert _executar(cliente, "suspender", alvo).status_code == 200
        assert _executar(cliente, "reativar", alvo).status_code == 200
    corpo = {
        "token": token,
        "kdf": dict(KDF),
        "sal": b64u(16),
        "auth_hash": b64u(32),
        "chave_usuario_cif": env_v1(),
        "chave_usuario_recup_cif": env_v1(),
        "recup_auth": b64u(32),
    }
    r = novo_cliente().post("/api/v1/recuperar/concluir", json=corpo)
    assert (r.status_code, r.json()) == (401, {"erro": "token_invalido"})
    assert ler(
        banco,
        "SELECT count(*) FROM recuperacoes WHERE usuario_id = %s AND usado_em IS NULL",
        (alvo["id"],),
    ) == [(0,)]


def test_remover_convidado_revoga_convite(cliente, owner, novo_cliente):
    alvo = _alvo(cliente, novo_cliente, "convidado", "c@t.invalid")
    assert _executar(cliente, "remover", alvo).status_code == 200
    r = novo_cliente().post(
        "/api/v1/convites/aceitar", json=payload_aceite(alvo["convite"]["token"])
    )
    assert (r.status_code, r.json()) == (410, {"erro": "convite_expirado"})


# ---------- DoD 5: remoção anonimiza e preserva eventos ----------


def test_remover_anonimiza_e_preserva_eventos(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "Sai@T.invalid")
    contar = "SELECT count(*) FROM eventos WHERE ator_id = %s"
    antes = ler(banco, contar, (m["id"],))
    assert antes[0][0] >= 2  # convite.aceito, auth.login

    r = _executar(cliente, "remover", m)
    assert (r.status_code, r.json()) == (200, {"relatorio": []})
    assert "sai@t.invalid" not in cliente.get(M).text
    assert ler(banco, contar, (m["id"],)) == antes
    assert ler(
        banco, "SELECT email::text, nome, estado FROM usuarios WHERE id = %s", (m["id"],)
    ) == [(f"removido-{m['id']}@invalido", None, "removido")]
    assert m["cliente"].get("/api/v1/eu").status_code == 401
    r = login(novo_cliente(), m["auth_hash"], "sai@t.invalid")
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
    ((meta,),) = ler(banco, "SELECT meta::text FROM eventos WHERE tipo = 'membro.removido'")
    assert "sai@" not in meta.lower()

    # Reconvite do mesmo e-mail (ex.: perdeu o kit) funciona e vira outro usuário.
    novo = ativar(cliente, novo_cliente, "sai@t.invalid")
    assert novo["id"] != m["id"]


def test_eventos_de_membro_sem_email(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "ev@t.invalid")
    _executar(cliente, "papel", m)
    _executar(cliente, "suspender", m)
    _executar(cliente, "reativar", m)
    _executar(cliente, "remover", m)
    eventos = ler(
        banco, "SELECT tipo, meta FROM eventos WHERE left(tipo, 7) = 'membro.' ORDER BY id"
    )
    assert [t for t, _ in eventos] == [
        "membro.confirmado",
        "membro.papel_alterado",
        "membro.suspenso",
        "membro.reativado",
        "membro.removido",
    ]
    assert eventos[1][1] == {"antes": "member", "depois": "admin"}
    assert "ev@t.invalid" not in str(eventos)


# ---------- DoD 6: último owner, auto_acao, admin × owner ----------


def _segundo_owner(cliente, novo_cliente, banco, email="o2@t.invalid"):
    """Promoção a owner é da Fase 7: aqui o segundo owner nasce ativo pelo fluxo real e só o
    papel é ajustado no banco."""
    o = ativar(cliente, novo_cliente, email, "admin")
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE usuarios SET papel = 'owner' WHERE id = %s", (o["id"],))
    return o


@pytest.mark.parametrize("acao", ["suspender", "remover", "papel"])
def test_unico_owner_409(cliente, owner, novo_cliente, banco, acao):
    eu = {"id": owner["usuario_id"]}
    r = _executar(cliente, acao, eu, papel="member")
    assert (r.status_code, r.json()) == (409, {"erro": "ultimo_owner"})
    admin = ativar(cliente, novo_cliente, "adm@t.invalid", "admin")
    # Admin sobre owner é 403 antes de qualquer outra regra, mesmo com owner único.
    r = _executar(admin["cliente"], acao, eu, papel="member")
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    assert ler(banco, "SELECT papel, estado FROM usuarios WHERE id = %s", (eu["id"],)) == [
        ("owner", "ativo")
    ]


@pytest.mark.parametrize("acao", ["suspender", "remover", "papel"])
def test_admin_nao_altera_owner_403(cliente, owner, novo_cliente, banco, acao):
    o2 = _segundo_owner(cliente, novo_cliente, banco)
    admin = ativar(cliente, novo_cliente, "adm@t.invalid", "admin")
    r = _executar(admin["cliente"], acao, o2, papel="member")
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    assert ler(banco, "SELECT papel, estado FROM usuarios WHERE id = %s", (o2["id"],)) == [
        ("owner", "ativo")
    ]


def test_owner_rebaixa_e_suspende_outro_owner(cliente, owner, novo_cliente, banco):
    o2 = _segundo_owner(cliente, novo_cliente, banco)
    r = _executar(cliente, "papel", o2, papel="admin")
    assert (r.status_code, r.json()) == (200, {"id": o2["id"], "papel": "admin"})
    o3 = _segundo_owner(cliente, novo_cliente, banco, "o3@t.invalid")
    assert _executar(cliente, "suspender", o3).status_code == 200
    # O owner suspenso não conta: o que sobrou é o último.
    r = _executar(cliente, "suspender", {"id": owner["usuario_id"]})
    assert r.json() == {"erro": "ultimo_owner"}
    # Admin não reativa owner; owner reativa.
    assert _executar(o2["cliente"], "reativar", o3).status_code == 403
    assert _executar(cliente, "reativar", o3).status_code == 200


@pytest.mark.parametrize("acao", ["confirmar", "suspender", "reativar", "papel", "remover"])
def test_auto_acao_409(cliente, owner, novo_cliente, banco, acao):
    admin = ativar(cliente, novo_cliente, "adm@t.invalid", "admin")
    r = _executar(admin["cliente"], acao, {"id": admin["id"], "chave_publica": b64u(32)})
    assert (r.status_code, r.json()) == (409, {"erro": "auto_acao"})
    _segundo_owner(cliente, novo_cliente, banco)  # owner com outro owner: auto_acao também
    r = _executar(cliente, acao, {"id": owner["usuario_id"], "chave_publica": b64u(32)})
    assert (r.status_code, r.json()) == (409, {"erro": "auto_acao"})


def test_admin_suspende_outro_admin(cliente, owner, novo_cliente):
    a1 = ativar(cliente, novo_cliente, "a1@t.invalid", "admin")
    a2 = ativar(cliente, novo_cliente, "a2@t.invalid", "admin")
    assert _executar(a1["cliente"], "suspender", a2).status_code == 200


def test_papel_igual_e_noop_sem_evento(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "igual@t.invalid")
    r = _executar(cliente, "papel", m, papel="member")
    assert (r.status_code, r.json()) == (200, {"id": m["id"], "papel": "member"})
    assert ler(banco, "SELECT count(*) FROM eventos WHERE tipo = 'membro.papel_alterado'") == [(0,)]


def test_papel_vale_na_hora_para_sessao_aberta(cliente, owner, novo_cliente):
    a = ativar(cliente, novo_cliente, "a@t.invalid", "admin")
    corpo = {"email": "x@t.invalid", "papel": "member"}
    assert _executar(cliente, "papel", a, papel="member").status_code == 200
    r = a["cliente"].post("/api/v1/convites", json=corpo, headers=H)
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})


# ---------- Concorrência: dois owners se suspendendo ao mesmo tempo ----------


@pytest.mark.parametrize("acao", ["suspender", "remover", "papel"])
def test_owners_simultaneos_nao_zeram_owners(cliente, owner, novo_cliente, banco, acao):
    o2 = _segundo_owner(cliente, novo_cliente, banco)
    largada = threading.Barrier(2)
    status = {}

    def rodar(nome, c, alvo):
        largada.wait()
        status[nome] = _executar(c, acao, alvo, papel="admin").status_code

    t = [
        threading.Thread(target=rodar, args=("a", cliente, o2)),
        threading.Thread(target=rodar, args=("b", o2["cliente"], {"id": owner["usuario_id"]})),
    ]
    for x in t:
        x.start()
    for x in t:
        x.join()
    assert sorted(status.values())[0] == 200
    assert sorted(status.values())[1] in (401, 403, 409)
    assert ler(
        banco, "SELECT count(*) FROM usuarios WHERE papel = 'owner' AND estado = 'ativo'"
    ) == [(1,)]


# ---------- DoD 7: matriz papel × rota (§5.3) ----------

PAPEIS = ["owner", "admin", "member", "aceito", "sem_sessao"]


@pytest.fixture
def atores(cliente, owner, novo_cliente):
    a = ativar(cliente, novo_cliente, "admin@t.invalid", "admin")
    m = ativar(cliente, novo_cliente, "member@t.invalid", "member")
    c = convidar(cliente, "aceito@t.invalid")
    pendente = novo_cliente()
    aceitar_e_logar(pendente, c["token"], "aceito@t.invalid")
    return {
        "owner": cliente,
        "admin": a["cliente"],
        "member": m["cliente"],
        "aceito": pendente,
        "sem_sessao": novo_cliente(),
    }


def _req(cliente, novo_cliente, rota: str, n: int):
    """(método, url, corpo) com um alvo novo por chamada."""
    if rota in ("GET /org", "GET /membros"):
        return "GET", f"/api/v1{rota.split()[1]}", None
    if rota == "PUT /org/politica":
        return "PUT", "/api/v1/org/politica", {"mfa_obrigatorio": False, "inatividade_min": 20}
    if rota == "POST /convites":
        return "POST", "/api/v1/convites", {"email": f"novo{n}@t.invalid", "papel": "member"}
    if rota == "DELETE /convites/{id}":
        return (
            "DELETE",
            f"/api/v1/convites/{convidar(cliente, f'c{n}@t.invalid')['convite_id']}",
            None,
        )
    estado = {"confirmar": "aceito", "reativar": "suspenso"}.get(rota.split("/")[-1], "ativo")
    alvo = _alvo(cliente, novo_cliente, estado, f"alvo{n}@t.invalid")
    url = f"{M}/{alvo['id']}"
    return {
        "POST /membros/{id}/confirmar": (
            "POST",
            f"{url}/confirmar",
            {"fingerprint": _fp(alvo["chave_publica"])},
        ),
        "POST /membros/{id}/suspender": ("POST", f"{url}/suspender", None),
        "POST /membros/{id}/reativar": ("POST", f"{url}/reativar", None),
        "PUT /membros/{id}/papel": ("PUT", f"{url}/papel", {"papel": "admin"}),
        "DELETE /membros/{id}": ("DELETE", url, None),
    }[rota]


GESTAO = {"owner": 200, "admin": 200, "member": 403, "aceito": 403, "sem_sessao": 401}
LEITURA = {"owner": 200, "admin": 200, "member": 200, "aceito": 403, "sem_sessao": 401}
MATRIZ = {
    "GET /org": LEITURA,
    "PUT /org/politica": GESTAO,
    "GET /membros": LEITURA,
    "POST /convites": GESTAO | {"owner": 201, "admin": 201},
    "DELETE /convites/{id}": GESTAO | {"owner": 204, "admin": 204},
    "POST /membros/{id}/confirmar": GESTAO,
    "POST /membros/{id}/suspender": GESTAO,
    "POST /membros/{id}/reativar": GESTAO,
    "PUT /membros/{id}/papel": GESTAO,
    "DELETE /membros/{id}": GESTAO,
}


@pytest.mark.parametrize("rota", list(MATRIZ))
def test_matriz_papel_rota(cliente, atores, novo_cliente, rota):
    for i, papel in enumerate(PAPEIS):
        metodo, url, corpo = _req(cliente, novo_cliente, rota, i)
        r = atores[papel].request(metodo, url, json=corpo, headers=H)
        assert r.status_code == MATRIZ[rota][papel], (papel, r.text)
        if metodo != "GET":  # sem X-Cofre: 403 csrf antes de tudo
            r = atores[papel].request(metodo, url, json=corpo)
            assert (r.status_code, r.json()) == (403, {"erro": "csrf"}), papel


def test_member_403_identico_exista_ou_nao_o_alvo(cliente, atores, novo_cliente):
    alvo = ativar(cliente, novo_cliente, "x@t.invalid")
    existe = atores["member"].post(f"{M}/{alvo['id']}/suspender", headers=H)
    nao = atores["member"].post(f"{M}/{uuid.uuid4()}/suspender", headers=H)
    assert existe.status_code == nao.status_code == 403
    assert existe.content == nao.content
