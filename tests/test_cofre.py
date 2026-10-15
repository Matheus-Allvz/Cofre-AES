"""Fase 6 — coleções e itens: RF-O03/O04, RF-T01, RF-T06, RF-T07, RF-A02, RF-A03, RNF-C01."""

import threading
import uuid

import psycopg
import pytest
from conftest import (
    H,
    aceitar_e_logar,
    ativar,
    b64u,
    convidar,
    env_v1,
    esperar_trava,
    ler,
    payload_aceite,
)
from fastapi.testclient import TestClient

from app.rotas.convites import criar_convite

V = "/api/v1"
NIVEIS = [None, "ver_sem_revelar", "ver", "editar", "gerenciar"]
NAO_ENCONTRADO = b'{"erro":"nao_encontrado"}'


def x1() -> str:
    return f"x1.{b64u(32)}.{b64u(12)}.{b64u(48)}"


def novo_id() -> str:
    return str(uuid.uuid4())


def env(usuario_id, permissao="gerenciar") -> dict:
    return {"usuario_id": str(usuario_id), "permissao": permissao, "chave_colecao_cif": x1()}


def criar_colecao(c, envelopes, cid=None):
    corpo = {"id": cid or novo_id(), "nome_cif": env_v1(), "envelopes": envelopes}
    return c.post(f"{V}/colecoes", json=corpo, headers=H), corpo["id"]


def criar_item(c, cid, tipo="login", chave_ver=1, iid=None, **blobs):
    corpo = {
        "id": iid or novo_id(),
        "tipo": tipo,
        "chave_ver": chave_ver,
        "meta_cif": blobs.get("meta_cif", env_v1()),
        "segredo_cif": blobs.get("segredo_cif", env_v1()),
    }
    return c.post(f"{V}/colecoes/{cid}/itens", json=corpo, headers=H), corpo


def editar(c, iid, versao, chave_ver=1, **extra):
    corpo = {"chave_ver": chave_ver, "meta_cif": env_v1(), "segredo_cif": env_v1(), **extra}
    headers = H if versao is None else {**H, "If-Match": str(versao)}
    return c.put(f"{V}/itens/{iid}", json=corpo, headers=headers)


def eventos(banco, tipo, ator=None):
    sql = "SELECT count(*) FROM eventos WHERE tipo = %s AND (%s::uuid IS NULL OR ator_id = %s)"
    return ler(banco, sql, (tipo, ator, ator))[0][0]


@pytest.fixture
def cofre(cliente, owner):
    """Coleção do owner (só o envelope dele) com um item."""
    r, cid = criar_colecao(cliente, [env(owner["usuario_id"])])
    assert r.status_code == 201, r.text
    r, item = criar_item(cliente, cid)
    assert r.status_code == 201, r.text
    return {"col": cid, "item": item["id"], "segredo": item["segredo_cif"]}


def _ok(r, status=200):
    assert r.status_code == status, r.text
    return r


def _item(c, cid) -> str:
    r, item = criar_item(c, cid)
    _ok(r, 201)
    return item["id"]


# ---------- matriz permissão × rota ----------


def _rotas(ctx):
    """(nome, permissão mínima, chamada, status de sucesso). Um alvo por rota que muda estado."""
    col, a, b, l1, l2 = (ctx[k] for k in ("col", "a", "b", "l1", "l2"))
    nome = {"chave_ver": 1, "nome_cif": env_v1()}
    I = f"{V}/itens"  # noqa: E741, N806
    return [
        (
            "PUT colecao",
            "gerenciar",
            lambda c: c.put(f"{V}/colecoes/{col}", json=nome, headers=H),
            204,
        ),
        ("GET membros", "gerenciar", lambda c: c.get(f"{V}/colecoes/{col}/membros"), 200),
        ("POST item", "editar", lambda c: criar_item(c, col)[0], 201),
        ("PUT item", "editar", lambda c: editar(c, a, 2), 200),
        ("GET segredo", "ver", lambda c: c.get(f"{V}/itens/{a}/segredo"), 200),
        ("POST copiado", "ver", lambda c: c.post(f"{V}/itens/{a}/copiado", headers=H), 204),
        ("GET versoes", "ver", lambda c: c.get(f"{V}/itens/{a}/versoes"), 200),
        ("GET versao", "ver", lambda c: c.get(f"{V}/itens/{a}/versoes/1"), 200),
        ("DELETE item", "editar", lambda c: c.delete(f"{V}/itens/{b}", headers=H), 204),
        ("GET lixeira", "editar", lambda c: c.get(f"{V}/colecoes/{col}/lixeira"), 200),
        ("POST restaurar", "editar", lambda c: c.post(f"{I}/{l1}/restaurar", headers=H), 204),
        (
            "DELETE definitivo",
            "gerenciar",
            lambda c: c.delete(f"{I}/{l2}/definitivo", headers=H),
            204,
        ),
        # Autorizado, mas a coleção tem itens: o 409 prova que a permissão passou.
        ("DELETE colecao", "gerenciar", lambda c: c.delete(f"{V}/colecoes/{col}", headers=H), 409),
    ]


def _preparar_matriz(cliente, owner, membro_id, permissao):
    """Coleção do owner com o membro em `permissao` (None = sem envelope nela, mas com envelope
    em outra coleção: IDOR entre coleções). Itens: a (1 versão anterior), b; l1 e l2 na lixeira."""
    envs = [env(owner["usuario_id"])] + ([env(membro_id, permissao)] if permissao else [])
    col = _ok(criar_colecao(cliente, envs)[0], 201).json()["id"]
    outra = criar_colecao(cliente, [env(owner["usuario_id"]), env(membro_id, "gerenciar")])[0]
    _ok(outra, 201)
    ctx = {"col": col}
    for k in ("a", "b", "l1", "l2"):
        r, item = criar_item(cliente, col)
        _ok(r, 201)
        ctx[k] = item["id"]
    _ok(editar(cliente, ctx["a"], 1))
    for k in ("l1", "l2"):
        _ok(cliente.delete(f"{V}/itens/{ctx[k]}", headers=H), 204)
    return ctx


@pytest.mark.parametrize("permissao", NIVEIS)
def test_matriz_permissao_por_rota(cliente, owner, novo_cliente, banco, permissao):
    m = ativar(cliente, novo_cliente, "matriz@t.invalid")
    ctx = _preparar_matriz(cliente, owner, m["id"], permissao)
    c = m["cliente"]
    for nome, minimo, chamar, sucesso in _rotas(ctx):
        r = chamar(c)
        if permissao is None:
            esperado = 404
        elif NIVEIS.index(permissao) < NIVEIS.index(minimo):
            esperado = 403
        else:
            esperado = sucesso
        assert r.status_code == esperado, f"{nome} com {permissao}: {r.status_code} {r.text}"
        if esperado == 404:  # mesmo corpo de um id que não existe
            assert r.content == NAO_ENCONTRADO, nome
        if esperado == 403:
            assert r.json() == {"erro": "sem_permissao"}, nome
    # sync: a coleção aparece só com envelope; nunca com segredo_cif.
    s = _ok(c.get(f"{V}/sync"))
    assert (ctx["col"] in {x["id"] for x in s.json()["colecoes"]}) == (permissao is not None)
    assert "segredo_cif" not in s.text
    reveladas = eventos(banco, "item.revelado", m["id"])
    assert reveladas == (1 if permissao in ("ver", "editar", "gerenciar") else 0)


def _outra_org(banco, email) -> dict:
    """A CLI só cria uma org por instalação: a segunda nasce direto no banco (defesa em
    profundidade: toda consulta filtra org_id)."""
    with psycopg.connect(banco["app"]) as conn:
        (org_id,) = conn.execute(
            "INSERT INTO organizacoes (nome) VALUES ('Org B') RETURNING id"
        ).fetchone()
        conn.execute(
            "INSERT INTO politicas (org_id, mfa_obrigatorio) VALUES (%s, false)", (org_id,)
        )
        (uid,) = conn.execute(
            "INSERT INTO usuarios (org_id, email, papel) VALUES (%s, %s, 'owner') RETURNING id",
            (org_id, email),
        ).fetchone()
        _, token = criar_convite(
            conn, org_id=org_id, usuario_id=uid, papel="owner", criado_por=None
        )
    return {"org_id": str(org_id), "usuario_id": str(uid), "token": token}


def test_outra_org_recebe_404_em_tudo(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "membro@t.invalid")
    ctx = _preparar_matriz(cliente, owner, m["id"], "gerenciar")
    org_b = _outra_org(banco, "dona-b@t.invalid")
    intrusa = novo_cliente()
    aceitar_e_logar(intrusa, org_b["token"], "dona-b@t.invalid")
    for nome, _, chamar, _ in _rotas(ctx):
        r = chamar(intrusa)
        assert (r.status_code, r.content) == (404, NAO_ENCONTRADO), nome
    assert _ok(intrusa.get(f"{V}/sync")).json() == {"colecoes": [], "itens": []}
    # Nem o id da coleção da org A ela consegue usar para entrar com um envelope próprio.
    r, _ = criar_colecao(intrusa, [env(org_b["usuario_id"])], cid=ctx["col"])
    assert (r.status_code, r.json()) == (409, {"erro": "id_em_uso"})


def test_dod4_casos_nomeados(cliente, owner, novo_cliente):
    """DoD 4 literal: ver_sem_revelar não revela mas sincroniza; ver não cria; editar não
    apaga definitivo; sem envelope → 404."""
    pessoas = {p: ativar(cliente, novo_cliente, f"{p}@t.invalid") for p in NIVEIS[1:4]}
    envs = [env(owner["usuario_id"])] + [env(m["id"], p) for p, m in pessoas.items()]
    col = _ok(criar_colecao(cliente, envs)[0], 201).json()["id"]
    iid = _item(cliente, col)
    _ok(cliente.delete(f"{V}/itens/{iid}", headers=H), 204)
    _ok(cliente.post(f"{V}/itens/{iid}/restaurar", headers=H), 204)
    vsr, ver, edt = (pessoas[p]["cliente"] for p in NIVEIS[1:4])
    assert vsr.get(f"{V}/itens/{iid}/segredo").status_code == 403
    assert vsr.get(f"{V}/sync").status_code == 200
    assert criar_item(ver, col)[0].status_code == 403
    _ok(edt.delete(f"{V}/itens/{iid}", headers=H), 204)
    assert edt.delete(f"{V}/itens/{iid}/definitivo", headers=H).status_code == 403
    _ok(cliente.delete(f"{V}/itens/{iid}/definitivo", headers=H), 204)


# ---------- RF-A03 / DoD 2: listagens sem segredo_cif ----------


def test_sync_e_lixeira_sem_segredo_cif(cliente, cofre):
    r, item = criar_item(cliente, cofre["col"], tipo="nota")
    _ok(r, 201)
    _ok(cliente.delete(f"{V}/itens/{item['id']}", headers=H), 204)
    s = _ok(cliente.get(f"{V}/sync"))
    lx = _ok(cliente.get(f"{V}/colecoes/{cofre['col']}/lixeira"))
    for bruto in (s.text, lx.text):
        assert "segredo_cif" not in bruto
        assert cofre["segredo"] not in bruto and item["segredo_cif"] not in bruto
    assert [i["id"] for i in s.json()["itens"]] == [cofre["item"]]  # excluído some do sync
    assert [i["id"] for i in lx.json()] == [item["id"]]
    assert set(lx.json()[0]) == {
        "id", "colecao_id", "tipo", "versao", "chave_ver", "meta_cif", "excluido_em",
        "atualizado_por",
    }  # fmt: skip
    assert set(s.json()["colecoes"][0]) == {
        "id", "nome_cif", "chave_ver", "permissao", "chave_colecao_cif", "rotacao_pendente",
    }  # fmt: skip


# ---------- RF-A02 / DoD 3: evento na mesma transação ----------


@pytest.fixture
def quebrar_eventos(banco):
    """Instala (como dono) um trigger que faz RAISE em todo INSERT de eventos; devolve
    (instalar, remover). Sai sempre removido."""

    def instalar():
        with psycopg.connect(banco["dono"]) as conn:
            conn.execute(
                """CREATE FUNCTION falha_evento() RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN RAISE EXCEPTION 'falha forcada'; END $$"""
            )
            conn.execute(
                """CREATE TRIGGER eventos_falham BEFORE INSERT ON eventos
                   FOR EACH ROW EXECUTE FUNCTION falha_evento()"""
            )

    def remover():
        with psycopg.connect(banco["dono"]) as conn:
            conn.execute("DROP TRIGGER IF EXISTS eventos_falham ON eventos")
            conn.execute("DROP FUNCTION IF EXISTS falha_evento()")

    yield instalar, remover
    remover()


@pytest.mark.parametrize("rota", ["segredo", "versoes/1"])
def test_revelar_falha_se_o_evento_falha(cliente, cofre, banco, quebrar_eventos, rota):
    instalar, remover = quebrar_eventos
    _ok(editar(cliente, cofre["item"], 1))  # cria a versão 1
    (antigo,) = ler(banco, "SELECT segredo_cif FROM item_versoes")[0]
    (atual,) = ler(banco, "SELECT segredo_cif FROM itens")[0]
    tipo = "item.revelado" if rota == "segredo" else "item.versao_revelada"
    url = f"{V}/itens/{cofre['item']}/{rota}"
    c = TestClient(cliente.app, base_url="https://testserver", raise_server_exceptions=False)
    c.cookies = cliente.cookies
    instalar()
    r = c.get(url)
    assert (r.status_code, r.content) == (500, b'{"erro":"interno"}')
    assert eventos(banco, tipo) == 0
    remover()
    r = c.get(url)
    assert r.status_code == 200
    assert r.json()["segredo_cif"] == (atual if rota == "segredo" else antigo)
    assert eventos(banco, tipo) == 1


# ---------- histórico e If-Match (RF-T06 / DoD 5) ----------


def test_put_exige_if_match_e_versao_atual(cliente, cofre, banco):
    iid = cofre["item"]
    for sem in (None, "abc", "", "-1"):
        r = editar(cliente, iid, sem)
        assert (r.status_code, r.json()) == (428, {"erro": "versao_requerida"}), sem
    assert _ok(editar(cliente, iid, '"1"')).json() == {"versao": 2}  # ETag entre aspas vale
    r = editar(cliente, iid, 1)
    assert (r.status_code, r.json()) == (409, {"erro": "conflito_versao"})
    r = editar(cliente, iid, 2, chave_ver=2)
    assert (r.status_code, r.json()) == (409, {"erro": "chave_ver_desatualizada"})
    assert ler(banco, "SELECT versao FROM itens WHERE id = %s", (iid,)) == [(2,)]


@pytest.mark.parametrize("edicoes,linhas", [(3, 3), (12, 10)])
def test_historico_guarda_ate_10_versoes(cliente, cofre, banco, edicoes, linhas):
    iid = cofre["item"]
    blobs = []
    for v in range(1, edicoes + 1):
        blobs.append(ler(banco, "SELECT segredo_cif FROM itens WHERE id = %s", (iid,))[0][0])
        assert _ok(editar(cliente, iid, v)).json() == {"versao": v + 1}
    assert ler(banco, "SELECT count(*) FROM item_versoes")[0][0] == linhas
    lista = _ok(cliente.get(f"{V}/itens/{iid}/versoes")).json()
    assert [x["versao"] for x in lista] == list(range(edicoes, edicoes - linhas, -1))
    assert set(lista[0]) == {"versao", "chave_ver", "editado_por", "em"}
    # A versão n guardada é exatamente o blob que estava no item antes da edição n.
    v = lista[-1]["versao"]
    assert _ok(cliente.get(f"{V}/itens/{iid}/versoes/{v}")).json()["segredo_cif"] == blobs[v - 1]
    if edicoes == 12:
        assert cliente.get(f"{V}/itens/{iid}/versoes/2").status_code == 404


def test_senha_trocada_limpa_rotacao_pendente(cliente, cofre, banco):
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE itens SET rotacao_senha_pendente = true")
    sql = "SELECT rotacao_senha_pendente FROM itens"
    _ok(editar(cliente, cofre["item"], 1))
    assert ler(banco, sql) == [(True,)]
    _ok(editar(cliente, cofre["item"], 2, senha_trocada=True))
    assert ler(banco, sql) == [(False,)]


def test_dois_puts_com_o_mesmo_if_match(cliente, owner, novo_cliente):
    m = ativar(cliente, novo_cliente, "edita@t.invalid")
    col = _ok(criar_colecao(cliente, [env(owner["usuario_id"]), env(m["id"], "editar")])[0], 201)
    iid = _item(cliente, col.json()["id"])
    for versao in range(1, 6):
        largada, status = threading.Barrier(2), {}

        def rodar(nome, c, v=versao, largada=largada, status=status):
            largada.wait()
            r = editar(c, iid, v)
            status[nome] = (r.status_code, r.json())

        pares = (("a", cliente), ("b", m["cliente"]))
        t = [threading.Thread(target=rodar, args=(n, c)) for n, c in pares]
        for x in t:
            x.start()
        for x in t:
            x.join()
        assert sorted(status.values(), key=lambda s: s[0]) == [
            (200, {"versao": versao + 1}),
            (409, {"erro": "conflito_versao"}),
        ]


# ---------- coleções (DoD 6) ----------


def test_criar_colecao_exige_envelopes_dos_owners(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    dono2 = ativar(cliente, novo_cliente, "dono2@t.invalid")
    with psycopg.connect(banco["dono"]) as conn:  # promoção a owner é da Fase 7
        conn.execute("UPDATE usuarios SET papel = 'owner' WHERE id = %s", (dono2["id"],))
    conv = convidar(cliente, "aceito@t.invalid")
    _ok(novo_cliente().post(f"{V}/convites/aceitar", json=payload_aceite(conv["token"])), 201)
    suspenso = ativar(cliente, novo_cliente, "susp@t.invalid")
    _ok(cliente.post(f"{V}/membros/{suspenso['id']}/suspender", headers=H))
    casos = [
        ([env(eu)], 422, "envelopes_incompletos"),  # falta o owner ativo
        ([env(dono2["id"])], 422, "envelopes_incompletos"),  # falta o criador
        ([env(eu), env(dono2["id"], "editar")], 422, "envelopes_incompletos"),
        ([env(eu, "ver"), env(dono2["id"])], 422, "envelopes_incompletos"),
        ([env(eu), env(dono2["id"]), env(conv["usuario_id"], "ver")], 422, "destinatario_invalido"),
        ([env(eu), env(dono2["id"]), env(suspenso["id"], "ver")], 422, "destinatario_invalido"),
        ([env(eu), env(dono2["id"]), env(novo_id(), "ver")], 422, "destinatario_invalido"),
        ([env(eu), env(dono2["id"]), env(eu)], 422, "envelopes_duplicados"),
    ]
    for envs, status, erro in casos:
        r, _ = criar_colecao(cliente, envs)
        assert (r.status_code, r.json()) == (status, {"erro": erro}), envs
    assert ler(banco, "SELECT count(*) FROM colecoes")[0][0] == 0
    r, cid = criar_colecao(cliente, [env(eu), env(dono2["id"])])
    assert (r.status_code, r.json()) == (201, {"id": cid, "chave_ver": 1})
    assert eventos(banco, "colecao.criada") == 1
    r, _ = criar_colecao(cliente, [env(eu), env(dono2["id"])], cid=cid)
    assert (r.status_code, r.json()) == (409, {"erro": "id_em_uso"})


def test_validacao_de_formato_e_tamanho(cliente, cofre):
    grande = "v1." + b64u(12) + "." + "A" * (70 * 1024)
    r, _ = criar_item(cliente, cofre["col"], meta_cif=grande)
    assert (r.status_code, r.json()) == (422, {"erro": "blob_grande"})
    assert editar(cliente, cofre["item"], 1, segredo_cif=grande).json() == {"erro": "blob_grande"}
    corpo = {"id": novo_id(), "nome_cif": grande, "envelopes": [env(novo_id())]}
    r = cliente.post(f"{V}/colecoes", json=corpo, headers=H)
    assert r.json() == {"erro": "blob_grande"}
    assert criar_item(cliente, cofre["col"], tipo="cartao")[0].status_code == 422
    assert criar_item(cliente, cofre["col"], meta_cif="v2.x.y")[0].status_code == 422
    r, _ = criar_item(cliente, cofre["col"], chave_ver=2)
    assert (r.status_code, r.json()) == (409, {"erro": "chave_ver_desatualizada"})
    r, _ = criar_item(cliente, cofre["col"], iid=cofre["item"])
    assert (r.status_code, r.json()) == (409, {"erro": "id_em_uso"})


def test_tipos_crud(cliente, cofre, banco):
    for tipo in ("login", "nota", "chave_api"):
        r, item = criar_item(cliente, cofre["col"], tipo=tipo)
        assert (r.status_code, r.json()) == (201, {"versao": 1})
        _ok(editar(cliente, item["id"], 1))
        _ok(cliente.delete(f"{V}/itens/{item['id']}", headers=H), 204)
        assert cliente.delete(f"{V}/itens/{item['id']}", headers=H).json() == {
            "erro": "item_excluido"
        }
        assert editar(cliente, item["id"], 2).json() == {"erro": "item_excluido"}
    tipos = {i["tipo"] for i in _ok(cliente.get(f"{V}/colecoes/{cofre['col']}/lixeira")).json()}
    assert tipos == {"login", "nota", "chave_api"}


def test_renomear_e_excluir_colecao(cliente, cofre, banco):
    col = cofre["col"]
    r = cliente.put(f"{V}/colecoes/{col}", json={"chave_ver": 2, "nome_cif": env_v1()}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "chave_ver_desatualizada"})
    _ok(
        cliente.put(f"{V}/colecoes/{col}", json={"chave_ver": 1, "nome_cif": env_v1()}, headers=H),
        204,
    )
    _ok(cliente.delete(f"{V}/itens/{cofre['item']}", headers=H), 204)
    r = cliente.delete(f"{V}/colecoes/{col}", headers=H)  # a lixeira conta
    assert (r.status_code, r.json()) == (409, {"erro": "colecao_nao_vazia"})
    _ok(cliente.delete(f"{V}/itens/{cofre['item']}/definitivo", headers=H), 204)
    _ok(cliente.delete(f"{V}/colecoes/{col}", headers=H), 204)
    assert _ok(cliente.get(f"{V}/sync")).json() == {"colecoes": [], "itens": []}
    assert cliente.get(f"{V}/colecoes/{col}/membros").status_code == 404
    tipos = [
        t
        for (t,) in ler(
            banco, "SELECT tipo FROM eventos WHERE left(tipo, 8) = 'colecao.' ORDER BY id"
        )
    ]
    assert tipos == ["colecao.criada", "colecao.renomeada", "colecao.excluida"]


# ---------- lixeira (RF-T07 / DoD 7) ----------


def test_lixeira_restaurar_e_purga_de_30_dias(cliente, owner, cofre, banco, novo_cliente):
    ids = {}
    for dias in (31, 29):
        r, item = criar_item(cliente, cofre["col"])
        _ok(r, 201)
        _ok(cliente.delete(f"{V}/itens/{item['id']}", headers=H), 204)
        ids[dias] = item["id"]
        with psycopg.connect(banco["dono"]) as conn:
            conn.execute(
                "UPDATE itens SET excluido_em = now() - make_interval(days => %s) WHERE id = %s",
                (dias, item["id"]),
            )
    # Coleção de que o owner não participa: o sync dele não purga lá.
    m = ativar(cliente, novo_cliente, "alheio@t.invalid")
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE usuarios SET papel = 'owner' WHERE id = %s", (m["id"],))
    alheia = _ok(criar_colecao(m["cliente"], [env(m["id"]), env(owner["usuario_id"])])[0], 201)
    r, alheio = criar_item(m["cliente"], alheia.json()["id"])
    _ok(m["cliente"].delete(f"{V}/itens/{alheio['id']}", headers=H), 204)
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("DELETE FROM colecao_membros WHERE usuario_id = %s", (owner["usuario_id"],))
        conn.execute(
            "UPDATE itens SET excluido_em = now() - interval '40 days' WHERE id = %s",
            (alheio["id"],),
        )
        conn.execute(
            "INSERT INTO colecao_membros SELECT %s, %s, 'gerenciar', 1, %s",
            (cofre["col"], owner["usuario_id"], x1()),
        )
    _ok(cliente.get(f"{V}/sync"))
    lixo = [i["id"] for i in _ok(cliente.get(f"{V}/colecoes/{cofre['col']}/lixeira")).json()]
    assert lixo == [ids[29]]
    assert ler(banco, "SELECT count(*) FROM itens WHERE id = %s", (ids[31],)) == [(0,)]
    assert ler(banco, "SELECT count(*) FROM itens WHERE id = %s", (alheio["id"],)) == [(1,)]
    assert ler(banco, "SELECT alvo_id, meta->>'modo' FROM eventos WHERE tipo = 'item.purgado'") == [
        (ids[31], "automatico")
    ]
    _ok(cliente.get(f"{V}/sync"))  # segunda passada não repete o evento
    assert eventos(banco, "item.purgado") == 1
    # restaurar volta ao sync; restaurar de novo = 409
    _ok(cliente.post(f"{V}/itens/{ids[29]}/restaurar", headers=H), 204)
    assert ids[29] in [i["id"] for i in _ok(cliente.get(f"{V}/sync")).json()["itens"]]
    r = cliente.post(f"{V}/itens/{ids[29]}/restaurar", headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "fora_da_lixeira"})
    r = cliente.delete(f"{V}/itens/{ids[29]}/definitivo", headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "fora_da_lixeira"})


def test_definitivo_apaga_versoes(cliente, cofre, banco):
    _ok(editar(cliente, cofre["item"], 1))
    _ok(cliente.delete(f"{V}/itens/{cofre['item']}", headers=H), 204)
    _ok(cliente.delete(f"{V}/itens/{cofre['item']}/definitivo", headers=H), 204)
    assert ler(banco, "SELECT count(*) FROM item_versoes")[0][0] == 0
    assert ler(banco, "SELECT meta->>'modo' FROM eventos WHERE tipo = 'item.purgado'") == [
        ("manual",)
    ]


# ---------- corridas com o estado do usuário ----------


def test_revelar_durante_suspensao_nao_revela(cliente, owner, novo_cliente, banco):
    """A suspensão segura a linha do usuário; o revelar espera e, depois do commit dela,
    devolve 401 sem segredo e sem evento (sem a releitura FOR SHARE, revelaria)."""
    m = ativar(cliente, novo_cliente, "revela@t.invalid")
    col = _ok(criar_colecao(cliente, [env(owner["usuario_id"]), env(m["id"], "ver")])[0], 201)
    iid = _item(cliente, col.json()["id"])
    resposta = {}
    with psycopg.connect(banco["dono"]) as susp:
        susp.execute("SELECT 1 FROM usuarios WHERE id = %s FOR UPDATE", (m["id"],))
        t = threading.Thread(
            target=lambda: resposta.update(r=m["cliente"].get(f"{V}/itens/{iid}/segredo"))
        )
        t.start()
        esperar_trava(banco)
        susp.execute("UPDATE usuarios SET estado = 'suspenso' WHERE id = %s", (m["id"],))
        susp.execute("UPDATE sessoes SET revogada_em = now() WHERE usuario_id = %s", (m["id"],))
    t.join()
    assert (resposta["r"].status_code, resposta["r"].json()) == (401, {"erro": "nao_autenticado"})
    assert eventos(banco, "item.revelado") == 0
