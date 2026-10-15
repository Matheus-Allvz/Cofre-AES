"""Fase 7 — compartilhamento, revogação e offboarding: RF-O03/O04 (membros), RF-U03, RF-U04,
RF-U05, RF-A01 (`colecao.*`, `membro.papel_alterado`) e os herdados D13, chave_ver do item e
revelar na lixeira. Depois de cada teste, o invariante D13 é conferido no banco."""

import json
import threading
import time

import psycopg
import pytest
from conftest import H, aceitar_e_logar, ativar, convidar, env_v1, ler, payload_aceite
from test_cofre import (
    NAO_ENCONTRADO,
    NIVEIS,
    V,
    _ok,
    _outra_org,
    criar_colecao,
    criar_item,
    editar,
    env,
    eventos,
    x1,
)

from app import main

D13 = """SELECT c.id, u.id FROM colecoes c
    JOIN usuarios u ON u.org_id = c.org_id AND u.papel = 'owner' AND u.estado = 'ativo'
    LEFT JOIN colecao_membros cm ON cm.colecao_id = c.id AND cm.usuario_id = u.id
         AND cm.permissao = 'gerenciar' AND cm.chave_ver = c.chave_ver
    WHERE cm.usuario_id IS NULL"""


@pytest.fixture(autouse=True)
def invariante_d13(request):
    """D13 depois de TODA operação desta fase: toda coleção tem envelope `gerenciar` na
    chave_ver atual de todo owner ativo."""
    yield
    if "banco" in request.fixturenames:
        assert ler(request.getfixturevalue("banco"), D13) == []


def _col(c, *envs) -> str:
    return _ok(criar_colecao(c, list(envs))[0], 201).json()["id"]


def _item(c, col, **kw) -> str:
    r, item = criar_item(c, col, **kw)
    _ok(r, 201)
    return item["id"]


def corpo_rotacao(banco, col) -> dict:
    """Corpo completo e correto para o estado atual (blobs aleatórios: o servidor não decifra)."""
    (cv,) = ler(banco, "SELECT chave_ver FROM colecoes WHERE id = %s", (col,))[0]
    membros = ler(banco, "SELECT usuario_id FROM colecao_membros WHERE colecao_id = %s", (col,))
    itens = ler(banco, "SELECT id, versao FROM itens WHERE colecao_id = %s", (col,))
    versoes = ler(
        banco,
        """SELECT v.item_id, v.versao FROM item_versoes v JOIN itens i ON i.id = v.item_id
           WHERE i.colecao_id = %s""",
        (col,),
    )
    return {
        "chave_ver_atual": cv,
        "nome_cif": env_v1(),
        "envelopes": [{"usuario_id": str(u), "chave_colecao_cif": x1()} for (u,) in membros],
        "itens": [
            {"id": str(i), "versao": v, "meta_cif": env_v1(), "segredo_cif": env_v1()}
            for i, v in itens
        ],
        "versoes": [
            {"item_id": str(i), "versao": v, "meta_cif": env_v1(), "segredo_cif": env_v1()}
            for i, v in versoes
        ],
    }


def foto(banco, col):
    """Todas as linhas que a rotação mexe, para comparar antes/depois."""
    return (
        ler(
            banco,
            "SELECT chave_ver, nome_cif, rotacao_pendente FROM colecoes WHERE id = %s",
            (col,),
        ),
        ler(
            banco,
            """SELECT usuario_id, permissao, chave_ver, chave_colecao_cif FROM colecao_membros
               WHERE colecao_id = %s ORDER BY usuario_id""",
            (col,),
        ),
        ler(
            banco,
            """SELECT id, versao, chave_ver, meta_cif, segredo_cif, rotacao_senha_pendente,
                      excluido_em FROM itens WHERE colecao_id = %s ORDER BY id""",
            (col,),
        ),
        ler(
            banco,
            """SELECT v.item_id, v.versao, v.chave_ver, v.meta_cif, v.segredo_cif
               FROM item_versoes v JOIN itens i ON i.id = v.item_id
               WHERE i.colecao_id = %s ORDER BY 1, 2""",
            (col,),
        ),
    )


def rotacionar(c, col, corpo):
    return c.post(f"{V}/colecoes/{col}/rotacionar", json=corpo, headers=H)


def esperar_travas(banco, n, timeout=10):
    """Espera n conexões da app paradas em trava (linha ou consultiva)."""
    fim = time.monotonic() + timeout
    sql = """SELECT count(*) FROM pg_stat_activity
             WHERE usename = 'cofre_app' AND wait_event_type = 'Lock'"""
    while time.monotonic() < fim:
        if ler(banco, sql)[0][0] >= n:
            return
        time.sleep(0.02)
    raise AssertionError(f"menos de {n} requisições esperando trava")


def em_thread(fn):
    resultado = {}
    t = threading.Thread(target=lambda: resultado.update(r=fn()))
    t.start()
    return t, resultado


# ---------- matriz permissão × rotas novas ----------


def _rotas_fase7(ctx, banco):
    col = ctx["col"]
    M = f"{V}/colecoes/{col}/membros"  # noqa: N806
    novo = {
        "usuario_id": ctx["novo"],
        "permissao": "ver",
        "chave_ver": 1,
        "chave_colecao_cif": x1(),
    }
    return [
        ("POST membros", lambda c: c.post(M, json=novo, headers=H), 201),
        (
            "PUT membros",
            lambda c: c.put(f"{M}/{ctx['b']}", json={"permissao": "editar"}, headers=H),
            200,
        ),
        ("DELETE membros", lambda c: c.delete(f"{M}/{ctx['d']}", headers=H), 204),
        ("POST rotacionar", lambda c: rotacionar(c, col, corpo_rotacao(banco, col)), 200),
    ]


@pytest.mark.parametrize("permissao", NIVEIS)
def test_matriz_permissao_rotas_da_fase7(cliente, owner, novo_cliente, banco, permissao):
    """Todas as rotas novas exigem `gerenciar`: abaixo → 403; sem envelope → 404 com os mesmos
    bytes de id inexistente (com envelope em OUTRA coleção: IDOR entre coleções)."""
    m = ativar(cliente, novo_cliente, "matriz7@t.invalid")
    b = ativar(cliente, novo_cliente, "b7@t.invalid")
    d = ativar(cliente, novo_cliente, "d7@t.invalid")
    novo = ativar(cliente, novo_cliente, "novo7@t.invalid")
    eu = owner["usuario_id"]
    envs = [env(eu), env(b["id"], "ver"), env(d["id"], "ver")]
    col = _col(cliente, *envs, *([env(m["id"], permissao)] if permissao else []))
    _col(cliente, env(eu), env(m["id"], "gerenciar"))
    iid = _item(cliente, col)
    _ok(editar(cliente, iid, 1))
    ctx = {"col": col, "b": b["id"], "d": d["id"], "novo": novo["id"]}
    for nome, chamar, sucesso in _rotas_fase7(ctx, banco):
        r = chamar(m["cliente"])
        if permissao is None:
            assert (r.status_code, r.content) == (404, NAO_ENCONTRADO), nome
        elif permissao != "gerenciar":
            assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"}), nome
        else:
            assert r.status_code == sucesso, f"{nome}: {r.status_code} {r.text}"
    tipos = [
        "colecao.membro_adicionado",
        "colecao.permissao_alterada",
        "colecao.membro_removido",
        "colecao.rotacionada",
    ]
    for tipo in tipos:  # RF-A01: exatamente um evento por ação que passou
        assert eventos(banco, tipo, m["id"]) == (1 if permissao == "gerenciar" else 0), tipo
    if permissao in (None, "ver_sem_revelar", "ver", "editar"):
        assert ler(banco, "SELECT chave_ver FROM colecoes WHERE id = %s", (col,)) == [(1,)]


def test_outra_org_recebe_404_nas_rotas_da_fase7(cliente, owner, novo_cliente, banco):
    b = ativar(cliente, novo_cliente, "b@t.invalid")
    d = ativar(cliente, novo_cliente, "d@t.invalid")
    novo = ativar(cliente, novo_cliente, "n@t.invalid")
    col = _col(cliente, env(owner["usuario_id"]), env(b["id"], "ver"), env(d["id"], "ver"))
    org_b = _outra_org(banco, "dona-b7@t.invalid")
    intrusa = novo_cliente()
    aceitar_e_logar(intrusa, org_b["token"], "dona-b7@t.invalid")
    ctx = {"col": col, "b": b["id"], "d": d["id"], "novo": novo["id"]}
    for nome, chamar, _ in _rotas_fase7(ctx, banco):
        r = chamar(intrusa)
        assert (r.status_code, r.content) == (404, NAO_ENCONTRADO), nome


# ---------- membros da coleção (DoD 8) ----------


def test_adicionar_membro_so_ativo_e_chave_atual(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    col = _col(cliente, env(eu))
    url = f"{V}/colecoes/{col}/membros"
    aceito = convidar(cliente, "aceito@t.invalid")
    assert (
        novo_cliente()
        .post(f"{V}/convites/aceitar", json=payload_aceite(aceito["token"]))
        .status_code
        == 201
    )
    susp = ativar(cliente, novo_cliente, "susp@t.invalid")
    _ok(cliente.post(f"{V}/membros/{susp['id']}/suspender", headers=H))
    ativo = ativar(cliente, novo_cliente, "ativo@t.invalid")

    def adicionar(uid, **extra):
        corpo = {"usuario_id": uid, "permissao": "ver", "chave_ver": 1, "chave_colecao_cif": x1()}
        return cliente.post(url, json=corpo | extra, headers=H)

    antes = foto(banco, col)
    for uid in (aceito["usuario_id"], susp["id"], "00000000-0000-0000-0000-000000000000"):
        r = adicionar(uid)
        assert (r.status_code, r.json()) == (422, {"erro": "destinatario_invalido"})
    r = adicionar(ativo["id"], chave_ver=2)
    assert (r.status_code, r.json()) == (409, {"erro": "chave_ver_desatualizada"})
    r = adicionar(ativo["id"], chave_colecao_cif="v1.nao-e-x1")
    assert r.status_code == 422
    assert foto(banco, col) == antes
    r = adicionar(ativo["id"])
    assert (r.status_code, r.json()) == (
        201,
        {"usuario_id": ativo["id"], "permissao": "ver", "chave_ver": 1},
    )
    r = adicionar(ativo["id"])
    assert (r.status_code, r.json()) == (409, {"erro": "ja_membro"})
    # O membro novo enxerga a coleção no sync com o envelope dele.
    s = _ok(ativo["cliente"].get(f"{V}/sync")).json()
    assert [(c["id"], c["permissao"]) for c in s["colecoes"]] == [(col, "ver")]
    meta = ler(banco, "SELECT meta FROM eventos WHERE tipo = 'colecao.membro_adicionado'")
    assert meta == [({"usuario_id": ativo["id"], "permissao": "ver"},)]


def test_owner_gerencia_e_ultimo_gerente(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    g = ativar(cliente, novo_cliente, "g@t.invalid")
    col = _col(cliente, env(eu), env(g["id"], "gerenciar"))
    M = f"{V}/colecoes/{col}/membros"  # noqa: N806
    r = g["cliente"].put(f"{M}/{eu}", json={"permissao": "editar"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "owner_gerencia"})
    r = g["cliente"].delete(f"{M}/{eu}", headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "owner_gerencia"})
    # Mesma permissão: 200 sem evento.
    r = cliente.put(f"{M}/{g['id']}", json={"permissao": "gerenciar"}, headers=H)
    assert (r.status_code, r.json()) == (200, {"usuario_id": g["id"], "permissao": "gerenciar"})
    assert eventos(banco, "colecao.permissao_alterada") == 0
    r = cliente.put(f"{M}/{g['id']}", json={"permissao": "ver"}, headers=H)
    assert r.status_code == 200
    meta = ler(banco, "SELECT meta FROM eventos WHERE tipo = 'colecao.permissao_alterada'")
    assert meta == [({"usuario_id": g["id"], "antes": "gerenciar", "depois": "ver"},)]
    r = cliente.put(
        f"{M}/00000000-0000-0000-0000-000000000000", json={"permissao": "ver"}, headers=H
    )
    assert (r.status_code, r.content) == (404, NAO_ENCONTRADO)
    # Último gerente: só alcançável fora do D13 (coleção sem owner), montado direto no banco.
    col2 = _col(cliente, env(eu), env(g["id"], "gerenciar"))
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE usuarios SET papel = 'admin' WHERE id = %s", (eu,))
        conn.execute(
            "DELETE FROM colecao_membros WHERE colecao_id = %s AND usuario_id = %s", (col2, eu)
        )
    url = f"{V}/colecoes/{col2}/membros/{g['id']}"
    r = g["cliente"].put(url, json={"permissao": "editar"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "ultimo_gerente"})
    r = g["cliente"].delete(url, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "ultimo_gerente"})
    with psycopg.connect(banco["dono"]) as conn:  # devolve o D13 para o fixture conferir
        conn.execute("UPDATE usuarios SET papel = 'owner' WHERE id = %s", (eu,))
        conn.execute(
            "INSERT INTO colecao_membros VALUES (%s, %s, 'gerenciar', 1, %s)", (col2, eu, x1())
        )


def test_remover_membro_da_colecao_marca_rotacao(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    m = ativar(cliente, novo_cliente, "sai@t.invalid")
    col = _col(cliente, env(eu), env(m["id"], "editar"))
    outra = _col(cliente, env(eu), env(m["id"], "ver"))
    a, lixo = _item(cliente, col), _item(cliente, col)
    _item(cliente, outra)
    _ok(cliente.delete(f"{V}/itens/{lixo}", headers=H), 204)
    _ok(cliente.delete(f"{V}/colecoes/{col}/membros/{m['id']}", headers=H), 204)
    pend = dict(ler(banco, "SELECT id::text, rotacao_pendente FROM colecoes"))
    assert pend == {outra: False, col: True}
    pend = ler(banco, "SELECT id::text FROM itens WHERE rotacao_senha_pendente ORDER BY id")
    assert sorted(x for (x,) in pend) == sorted([a, lixo])
    r = m["cliente"].get(f"{V}/itens/{a}/segredo")
    assert (r.status_code, r.content) == (404, NAO_ENCONTRADO)
    r = cliente.delete(f"{V}/colecoes/{col}/membros/{m['id']}", headers=H)
    assert (r.status_code, r.content) == (404, NAO_ENCONTRADO)


# ---------- rotacionar (DoD 3, 4) ----------


@pytest.fixture
def rotacao(cliente, owner, novo_cliente, banco):
    """Coleção com owner + 2 membros, 3 itens (um com 2 versões, um na lixeira)."""
    eu = owner["usuario_id"]
    a = ativar(cliente, novo_cliente, "a@t.invalid")
    b = ativar(cliente, novo_cliente, "b@t.invalid")
    col = _col(cliente, env(eu), env(a["id"], "gerenciar"), env(b["id"], "ver"))
    i1, i2, i3 = (_item(cliente, col) for _ in range(3))
    _ok(editar(cliente, i1, 1))
    _ok(editar(cliente, i1, 2))
    _ok(cliente.delete(f"{V}/itens/{i3}", headers=H), 204)
    return {"col": col, "a": a, "b": b, "itens": [i1, i2, i3], "lixo": i3}


def test_rotacionar_erros_nao_mudam_nada(cliente, banco, rotacao):
    col = rotacao["col"]
    antes = foto(banco, col)

    def tentar(mudar, esperado):
        corpo = corpo_rotacao(banco, col)
        mudar(corpo)
        r = rotacionar(cliente, col, corpo)
        assert (r.status_code, r.json()) == esperado, mudar
        assert foto(banco, col) == antes

    incompleta = (422, {"erro": "rotacao_incompleta"})
    lixo = rotacao["lixo"]
    tentar(lambda c: c.update(itens=[i for i in c["itens"] if i["id"] != lixo]), incompleta)
    tentar(lambda c: c["versoes"].pop(), incompleta)
    tentar(lambda c: c["envelopes"].pop(), incompleta)
    tentar(
        lambda c: c["envelopes"].append(
            {"usuario_id": "00000000-0000-0000-0000-000000000000", "chave_colecao_cif": x1()}
        ),
        incompleta,
    )
    tentar(lambda c: c["envelopes"].append(dict(c["envelopes"][0])), incompleta)  # repetido
    tentar(lambda c: c["itens"].append(dict(c["itens"][0])), incompleta)
    tentar(
        lambda c: c["versoes"].append(
            {
                "item_id": rotacao["itens"][1],
                "versao": 1,
                "meta_cif": env_v1(),
                "segredo_cif": env_v1(),
            }
        ),
        incompleta,
    )
    tentar(
        lambda c: c.update(chave_ver_atual=c["chave_ver_atual"] + 1),
        (409, {"erro": "chave_ver_desatualizada"}),
    )
    tentar(
        lambda c: c["itens"][0].update(versao=c["itens"][0]["versao"] + 1),
        (409, {"erro": "conflito_versao"}),
    )
    grande = "v1.AAAAAAAAAAAAAAAA." + "A" * (64 * 1024)
    tentar(lambda c: c["versoes"][0].update(segredo_cif=grande), (422, {"erro": "blob_grande"}))
    assert eventos(banco, "colecao.rotacionada") == 0


def test_rotacionar_grava_tudo_com_chave_ver_mais_1(cliente, banco, rotacao):
    col = rotacao["col"]
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE colecoes SET rotacao_pendente = true WHERE id = %s", (col,))
    versao_antes = dict(
        ler(banco, "SELECT id::text, versao FROM itens WHERE colecao_id = %s", (col,))
    )
    corpo = corpo_rotacao(banco, col)
    r = rotacionar(cliente, col, corpo)
    assert (r.status_code, r.json()) == (200, {"chave_ver": 2})
    (colecao, membros, itens, versoes) = foto(banco, col)
    assert colecao == [(2, corpo["nome_cif"], False)]
    assert {(str(u), cv, cif) for u, _, cv, cif in membros} == {
        (e["usuario_id"], 2, e["chave_colecao_cif"]) for e in corpo["envelopes"]
    }
    assert {(str(i), v, cv, m, s) for i, v, cv, m, s, _, _ in itens} == {
        (i["id"], i["versao"], 2, i["meta_cif"], i["segredo_cif"]) for i in corpo["itens"]
    }
    assert {str(i): v for i, v, *_ in itens} == versao_antes  # rotação não muda versao
    assert {(str(i), v, cv, m, s) for i, v, cv, m, s in versoes} == {
        (x["item_id"], x["versao"], 2, x["meta_cif"], x["segredo_cif"]) for x in corpo["versoes"]
    }
    (meta,) = ler(banco, "SELECT meta FROM eventos WHERE tipo = 'colecao.rotacionada'")[0]
    assert meta == {"chave_ver": 2, "membros": 3, "itens": 3, "versoes": 2}
    # Depois da rotação o cliente grava com a chave nova; a velha é recusada.
    r, _ = criar_item(cliente, col, chave_ver=1)
    assert (r.status_code, r.json()) == (409, {"erro": "chave_ver_desatualizada"})
    assert criar_item(cliente, col, chave_ver=2)[0].status_code == 201
    s = _ok(cliente.get(f"{V}/sync")).json()
    assert {c["chave_ver"] for c in s["colecoes"]} == {2}
    assert all(i["chave_ver"] == 2 for i in s["itens"])


def test_dois_rotacionar_concorrentes_um_200_um_409(cliente, banco, rotacao, monkeypatch):
    """DoD 4: duas threads com Barrier; a trava FOR UPDATE da coleção serializa (o limite de
    um corpo grande por vez do processo é afrouxado aqui para as duas chegarem ao banco)."""
    monkeypatch.setattr(main, "MAX_GRANDES", 2)
    col, a = rotacao["col"], rotacao["a"]
    for _ in range(5):
        largada, status = threading.Barrier(2), {}
        corpos = [corpo_rotacao(banco, col), corpo_rotacao(banco, col)]

        def rodar(n, c, corpo, largada=largada, status=status):
            largada.wait()
            r = rotacionar(c, col, corpo)
            status[n] = (r.status_code, r.json())

        t = [
            threading.Thread(target=rodar, args=(n, c, corpos[n]))
            for n, c in enumerate((cliente, a["cliente"]))
        ]
        for x in t:
            x.start()
        for x in t:
            x.join()
        cv = ler(banco, "SELECT chave_ver FROM colecoes WHERE id = %s", (col,))[0][0]
        assert sorted(status.values(), key=lambda s: s[0]) == [
            (200, {"chave_ver": cv}),
            (409, {"erro": "chave_ver_desatualizada"}),
        ]
    assert eventos(banco, "colecao.rotacionada") == 5


def test_corpo_grande_concorrente_recebe_503(cliente, banco, rotacao, monkeypatch):
    monkeypatch.setattr(main, "_grandes", 1)  # outro corpo grande em andamento
    r = rotacionar(cliente, rotacao["col"], corpo_rotacao(banco, rotacao["col"]))
    assert (r.status_code, r.json(), r.headers["retry-after"]) == (503, {"erro": "ocupado"}, "5")


def _segura_item(banco, item_id):
    """Conexão do dono segurando um item: a rotação (ou a edição) para nele com a coleção já
    travada, e dá para enfileirar outra requisição atrás."""
    conn = psycopg.connect(banco["dono"])
    conn.execute("SELECT 1 FROM itens WHERE id = %s FOR UPDATE", (item_id,))
    return conn


def test_edicao_durante_rotacao_recebe_409(cliente, banco, rotacao):
    col, i2 = rotacao["col"], rotacao["itens"][1]
    corpo = corpo_rotacao(banco, col)
    trava = _segura_item(banco, i2)
    t1, rot = em_thread(lambda: rotacionar(cliente, col, corpo))
    esperar_travas(banco, 1)  # rotação com a coleção travada, parada no item
    t2, ed = em_thread(lambda: editar(rotacao["a"]["cliente"], i2, 1))
    esperar_travas(banco, 2)  # edição esperando a coleção
    trava.close()
    t1.join()
    t2.join()
    assert (rot["r"].status_code, rot["r"].json()) == (200, {"chave_ver": 2})
    assert (ed["r"].status_code, ed["r"].json()) == (409, {"erro": "chave_ver_desatualizada"})
    assert ler(banco, "SELECT versao, chave_ver FROM itens WHERE id = %s", (i2,)) == [(1, 2)]


def test_rotacao_durante_edicao_recebe_409_conflito_versao(cliente, banco, rotacao):
    col, i2 = rotacao["col"], rotacao["itens"][1]
    corpo = corpo_rotacao(banco, col)
    trava = _segura_item(banco, i2)
    t1, ed = em_thread(lambda: editar(rotacao["a"]["cliente"], i2, 1))
    esperar_travas(banco, 1)  # edição com a coleção FOR SHARE, parada no item
    t2, rot = em_thread(lambda: rotacionar(cliente, col, corpo))
    esperar_travas(banco, 2)
    trava.close()
    t1.join()
    t2.join()
    assert (ed["r"].status_code, ed["r"].json()) == (200, {"versao": 2})
    assert (rot["r"].status_code, rot["r"].json()) == (409, {"erro": "conflito_versao"})
    assert ler(banco, "SELECT chave_ver FROM colecoes WHERE id = %s", (col,)) == [(1,)]


def test_remocao_de_membro_durante_rotacao(cliente, banco, rotacao):
    """Rotação primeiro (envelope do b incluído) → remoção depois: b fica sem envelope e a
    coleção volta a pedir rotação."""
    col, b = rotacao["col"], rotacao["b"]
    corpo = corpo_rotacao(banco, col)
    trava = _segura_item(banco, rotacao["itens"][0])
    t1, rot = em_thread(lambda: rotacionar(cliente, col, corpo))
    esperar_travas(banco, 1)
    t2, rem = em_thread(
        lambda: rotacao["a"]["cliente"].delete(f"{V}/colecoes/{col}/membros/{b['id']}", headers=H)
    )
    esperar_travas(banco, 2)
    trava.close()
    t1.join()
    t2.join()
    assert rot["r"].status_code == 200 and rem["r"].status_code == 204
    assert ler(banco, "SELECT chave_ver, rotacao_pendente FROM colecoes WHERE id = %s", (col,)) == [
        (2, True)
    ]
    assert ler(banco, "SELECT 1 FROM colecao_membros WHERE usuario_id = %s", (b["id"],)) == []


def test_rotacao_depois_de_remocao_concorrente_recusa_envelope_que_sobra(cliente, banco, rotacao):
    col, b = rotacao["col"], rotacao["b"]
    corpo = corpo_rotacao(banco, col)  # montado ainda com o b
    trava = _segura_item(banco, rotacao["itens"][0])  # a remoção para ao marcar os itens
    t1, rem = em_thread(
        lambda: rotacao["a"]["cliente"].delete(f"{V}/colecoes/{col}/membros/{b['id']}", headers=H)
    )
    esperar_travas(banco, 1)
    t2, rot = em_thread(lambda: rotacionar(cliente, col, corpo))
    esperar_travas(banco, 2)
    trava.close()
    t1.join()
    t2.join()
    assert rem["r"].status_code == 204
    assert (rot["r"].status_code, rot["r"].json()) == (422, {"erro": "rotacao_incompleta"})


# ---------- offboarding (DoD 5) e senha trocada (DoD 6) ----------


def test_remover_pessoa_devolve_relatorio_e_marca_rotacao(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    m = ativar(cliente, novo_cliente, "offboard@t.invalid")
    c1 = _col(cliente, env(eu), env(m["id"], "ver"))
    c2 = _col(cliente, env(eu), env(m["id"], "gerenciar"))
    c3 = _col(cliente, env(eu))  # ele não alcança
    vazia = _col(cliente, env(eu), env(m["id"], "editar"))
    i1, i2 = _item(cliente, c1), _item(cliente, c1)
    i3 = _item(cliente, c2)
    i4 = _item(cliente, c3)
    _ok(cliente.delete(f"{V}/itens/{i2}", headers=H), 204)  # lixeira entra no relatório
    r = cliente.delete(f"{V}/membros/{m['id']}", headers=H)
    assert r.status_code == 200, r.text
    relatorio = {x["colecao_id"]: sorted(x["itens"]) for x in r.json()["relatorio"]}
    assert relatorio == {c1: sorted([i1, i2]), c2: [i3], vazia: []}
    pend = {str(c) for (c,) in ler(banco, "SELECT id FROM colecoes WHERE rotacao_pendente")}
    assert pend == {c1, c2, vazia}
    itens = {str(i) for (i,) in ler(banco, "SELECT id FROM itens WHERE rotacao_senha_pendente")}
    assert itens == {i1, i2, i3} and i4 not in itens
    assert ler(banco, "SELECT 1 FROM colecao_membros WHERE usuario_id = %s", (m["id"],)) == []
    (meta,) = ler(banco, "SELECT meta FROM eventos WHERE tipo = 'membro.removido'")[0]
    assert meta == {"colecoes": 3}
    # Pessoa sem coleção: relatório vazio.
    n = ativar(cliente, novo_cliente, "semcol@t.invalid")
    r = cliente.delete(f"{V}/membros/{n['id']}", headers=H)
    assert (r.status_code, r.json()) == (200, {"relatorio": []})


def test_senha_trocada_limpa_a_marca_so_com_true(cliente, owner, banco):
    col = _col(cliente, env(owner["usuario_id"]))
    a, b = _item(cliente, col), _item(cliente, col)
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE itens SET rotacao_senha_pendente = true")
    _ok(editar(cliente, a, 1, senha_trocada=True))
    _ok(editar(cliente, b, 1, senha_trocada=False))
    _ok(editar(cliente, b, 2))  # ausente = false
    marcas = dict(ler(banco, "SELECT id::text, rotacao_senha_pendente FROM itens"))
    assert marcas == {a: False, b: True}
    s = _ok(cliente.get(f"{V}/sync")).json()
    assert {i["id"]: i["rotacao_senha_pendente"] for i in s["itens"]} == {a: False, b: True}


# ---------- promoção / rebaixamento de owner (DoD 7) e reativação (herdado D13) ----------


def envelopes_owner(banco, colecoes=None):
    linhas = ler(banco, "SELECT id::text, chave_ver FROM colecoes ORDER BY id")
    return [
        {"colecao_id": c, "chave_ver": v, "chave_colecao_cif": x1()}
        for c, v in linhas
        if colecoes is None or c in colecoes
    ]


def test_promover_a_owner_exige_envelopes_de_todas(cliente, owner, novo_cliente, banco):
    eu = owner["usuario_id"]
    m = ativar(cliente, novo_cliente, "promo@t.invalid", "admin")
    c1 = _col(cliente, env(eu))
    c2 = _col(cliente, env(eu), env(m["id"], "gerenciar"))  # já gerencia: exigida mesmo assim
    url = f"{V}/membros/{m['id']}/papel"

    def promover(envs):
        return cliente.put(url, json={"papel": "owner", "envelopes": envs}, headers=H)

    todos = envelopes_owner(banco)
    falta = [e for e in todos if e["colecao_id"] != c2]
    for envs, esperado in (
        ([], (422, {"erro": "envelopes_incompletos"})),
        (falta, (422, {"erro": "envelopes_incompletos"})),
        (
            todos + [{**todos[0], "colecao_id": "00000000-0000-0000-0000-000000000000"}],
            (422, {"erro": "envelopes_incompletos"}),
        ),
        (todos + [todos[0]], (422, {"erro": "envelopes_duplicados"})),
        ([{**e, "chave_ver": 9} for e in todos], (409, {"erro": "chave_ver_desatualizada"})),
    ):
        r = promover(envs)
        assert (r.status_code, r.json()) == esperado
    assert ler(banco, "SELECT papel FROM usuarios WHERE id = %s", (m["id"],)) == [("admin",)]
    # admin não promove; envelopes fora da promoção são recusados.
    r = m["cliente"].put(f"{V}/membros/{eu}/papel", json={"papel": "admin"}, headers=H)
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    outro = ativar(cliente, novo_cliente, "outro@t.invalid", "admin")
    r = m["cliente"].put(
        f"{V}/membros/{outro['id']}/papel", json={"papel": "owner", "envelopes": todos}, headers=H
    )
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    r = cliente.put(url, json={"papel": "member", "envelopes": todos}, headers=H)
    assert (r.status_code, r.json()) == (422, {"erro": "envelopes_incompletos"})

    r = promover(todos)
    assert (r.status_code, r.json()) == (200, {"id": m["id"], "papel": "owner"})
    ger = ler(
        banco,
        "SELECT colecao_id::text, permissao FROM colecao_membros WHERE usuario_id = %s",
        (m["id"],),
    )
    assert sorted(ger) == sorted([(c1, "gerenciar"), (c2, "gerenciar")])
    meta = ler(banco, "SELECT meta FROM eventos WHERE tipo = 'membro.papel_alterado'")
    assert meta == [({"antes": "admin", "depois": "owner"},)]
    # O novo owner rebaixa o antigo; o último owner não cai.
    r = m["cliente"].put(f"{V}/membros/{eu}/papel", json={"papel": "admin"}, headers=H)
    assert (r.status_code, r.json()) == (200, {"id": eu, "papel": "admin"})
    r = cliente.put(f"{V}/membros/{m['id']}/papel", json={"papel": "admin"}, headers=H)
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})  # agora é admin
    terceiro = ativar(m["cliente"], novo_cliente, "t@t.invalid", "admin")
    r = m["cliente"].put(f"{V}/membros/{terceiro['id']}/papel", json={"papel": "owner"}, headers=H)
    assert (r.status_code, r.json()) == (422, {"erro": "envelopes_incompletos"})
    # O único owner ativo tenta se rebaixar.
    r = m["cliente"].put(f"{V}/membros/{m['id']}/papel", json={"papel": "admin"}, headers=H)
    assert (r.status_code, r.json()) == (409, {"erro": "ultimo_owner"})


def test_promover_so_ativo(cliente, owner, novo_cliente, banco):
    m = ativar(cliente, novo_cliente, "susp-promo@t.invalid")
    _ok(cliente.post(f"{V}/membros/{m['id']}/suspender", headers=H))
    r = cliente.put(
        f"{V}/membros/{m['id']}/papel", json={"papel": "owner", "envelopes": []}, headers=H
    )
    assert (r.status_code, r.json()) == (409, {"erro": "estado_invalido"})


def test_owner_reativado_exige_envelopes_das_colecoes_que_faltam(
    cliente, owner, novo_cliente, banco
):
    """Herdado D13: owner suspenso não recebe envelope das coleções criadas no intervalo;
    reativá-lo exige esses envelopes (fornecidos pelo cliente de quem reativa)."""
    eu = owner["usuario_id"]
    o2 = ativar(cliente, novo_cliente, "o2@t.invalid", "admin")
    _ok(
        cliente.put(
            f"{V}/membros/{o2['id']}/papel", json={"papel": "owner", "envelopes": []}, headers=H
        )
    )
    antiga = _col(cliente, env(eu), env(o2["id"]))
    _ok(cliente.post(f"{V}/membros/{o2['id']}/suspender", headers=H))
    nova = _col(cliente, env(eu))  # o2 suspenso: não é exigido
    url = f"{V}/membros/{o2['id']}/reativar"
    r = cliente.post(url, headers=H)
    assert (r.status_code, r.json()) == (422, {"erro": "envelopes_incompletos"})
    r = cliente.post(url, json={"envelopes": envelopes_owner(banco, {antiga})}, headers=H)
    assert (r.status_code, r.json()) == (422, {"erro": "envelopes_incompletos"})
    assert ler(banco, "SELECT estado FROM usuarios WHERE id = %s", (o2["id"],)) == [("suspenso",)]
    r = cliente.post(url, json={"envelopes": envelopes_owner(banco, {nova})}, headers=H)
    assert (r.status_code, r.json()) == (200, {"id": o2["id"], "estado": "ativo"})
    # (o fixture confere o D13 com o2 ativo: precisa de gerenciar em `antiga` e `nova`)
    # Membro comum reativa sem envelopes; com envelopes → 422.
    m = ativar(cliente, novo_cliente, "comum@t.invalid")
    _ok(cliente.post(f"{V}/membros/{m['id']}/suspender", headers=H))
    r = cliente.post(
        f"{V}/membros/{m['id']}/reativar", json={"envelopes": envelopes_owner(banco)}, headers=H
    )
    assert (r.status_code, r.json()) == (422, {"erro": "envelopes_incompletos"})
    assert cliente.post(f"{V}/membros/{m['id']}/reativar", headers=H).status_code == 200


# ---------- herdados: chave_ver do item, revelar na lixeira ----------


def test_segredo_devolve_chave_ver_do_item(cliente, owner, banco):
    col = _col(cliente, env(owner["usuario_id"]))
    iid = _item(cliente, col)
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE itens SET chave_ver = 7 WHERE id = %s", (iid,))
    r = _ok(cliente.get(f"{V}/itens/{iid}/segredo"))
    assert (r.json()["chave_ver"], r.json()["versao"]) == (7, 1)


@pytest.mark.parametrize("permissao", ["ver", "editar"])
def test_revelar_item_na_lixeira_exige_editar(cliente, owner, novo_cliente, banco, permissao):
    m = ativar(cliente, novo_cliente, f"lixo-{permissao}@t.invalid")
    col = _col(cliente, env(owner["usuario_id"]), env(m["id"], permissao))
    iid = _item(cliente, col)
    _ok(editar(cliente, iid, 1))
    _ok(cliente.delete(f"{V}/itens/{iid}", headers=H), 204)
    for rota in (f"{V}/itens/{iid}/segredo", f"{V}/itens/{iid}/versoes/1"):
        r = m["cliente"].get(rota)
        if permissao == "ver":
            assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"}), rota
        else:
            assert r.status_code == 200, rota
    reveladas = eventos(banco, "item.revelado", m["id"]) + eventos(
        banco, "item.versao_revelada", m["id"]
    )
    assert reveladas == (0 if permissao == "ver" else 2)


def test_eventos_da_fase7_sem_envelopes_nem_blobs(cliente, banco, rotacao):
    """RNF-C01: meta dos eventos sem envelope x1/v1 (nem pedaço base64 deles)."""
    col = rotacao["col"]
    _ok(rotacionar(cliente, col, corpo_rotacao(banco, col)))
    _ok(cliente.delete(f"{V}/colecoes/{col}/membros/{rotacao['b']['id']}", headers=H), 204)
    metas = json.dumps([m for (m,) in ler(banco, "SELECT meta FROM eventos")])
    assert "x1." not in metas and "v1." not in metas
