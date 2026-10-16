"""Fase 8 — consulta de auditoria (§5.5, RF-A06): papel, filtros, cursor e SQL só com bind."""

import inspect
from datetime import timedelta

import psycopg
from conftest import H, ativar, ler
from test_cofre import _item, _ok, criar_colecao, env

from app.rotas import auditoria

V = "/api/v1"


def test_member_403_e_anonimo_401(cliente, owner, novo_cliente):
    m = ativar(cliente, novo_cliente, "m-aud@t.invalid")
    r = m["cliente"].get(f"{V}/auditoria")
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    assert novo_cliente().get(f"{V}/auditoria").status_code == 401


def _revelacoes(cliente, owner, novo_cliente):
    """Owner e um member revelam itens: 3 item.revelado de cada, mais outros eventos."""
    m = ativar(cliente, novo_cliente, "revela@t.invalid")
    col = _ok(criar_colecao(cliente, [env(owner["usuario_id"]), env(m["id"], "ver")])[0], 201)
    col = col.json()["id"]
    itens = [_item(cliente, col) for _ in range(3)]
    for i in itens:
        _ok(m["cliente"].get(f"{V}/itens/{i}/segredo"))
        _ok(cliente.get(f"{V}/itens/{i}/segredo"))
    return m, itens


def test_filtro_tipo_e_ator_devolve_so_esses(cliente, owner, novo_cliente):
    m, itens = _revelacoes(cliente, owner, novo_cliente)
    r = _ok(cliente.get(f"{V}/auditoria", params={"tipo": "item.revelado", "ator_id": m["id"]}))
    eventos = r.json()
    assert len(eventos) == 3
    assert {(e["tipo"], e["ator_id"], e["resultado"]) for e in eventos} == {
        ("item.revelado", m["id"], "ok")
    }
    assert sorted(e["alvo_id"] for e in eventos) == sorted(itens)
    assert [e["id"] for e in eventos] == sorted((e["id"] for e in eventos), reverse=True)
    # Filtro por alvo e por tipo sem resultado.
    r = _ok(cliente.get(f"{V}/auditoria", params={"alvo_id": itens[0], "tipo": "item.revelado"}))
    assert len(r.json()) == 2 and {e["alvo_id"] for e in r.json()} == {itens[0]}
    assert _ok(cliente.get(f"{V}/auditoria", params={"tipo": "item.inexistente"})).json() == []


def test_paginacao_por_cursor_nao_repete_nem_pula(cliente, owner, novo_cliente, banco):
    _, itens = _revelacoes(cliente, owner, novo_cliente)
    todos = [e["id"] for e in _ok(cliente.get(f"{V}/auditoria", params={"limite": 200})).json()]
    assert len(todos) >= 7
    vistos, cursor = [], None
    for _ in range(3):
        params = {"limite": 2} | ({"antes_de_id": cursor} if cursor else {})
        pagina = _ok(cliente.get(f"{V}/auditoria", params=params)).json()
        assert len(pagina) == 2
        vistos += [e["id"] for e in pagina]
        cursor = pagina[-1]["id"]
        # Evento novo no meio da paginação não desloca as páginas seguintes.
        _ok(cliente.post(f"{V}/itens/{itens[0]}/copiado", headers=H), 204)
    assert vistos == todos[:6]
    assert len(set(vistos)) == 6


def test_filtro_por_data_e_limites_de_parametro(cliente, owner, banco):
    (em,) = ler(banco, "SELECT max(em) FROM eventos")[0]
    r = _ok(cliente.get(f"{V}/auditoria", params={"de": (em + timedelta(seconds=1)).isoformat()}))
    assert r.json() == []
    r = _ok(cliente.get(f"{V}/auditoria", params={"ate": (em - timedelta(days=1)).isoformat()}))
    assert r.json() == []
    r = _ok(cliente.get(f"{V}/auditoria", params={"de": em.isoformat(), "ate": em.isoformat()}))
    assert r.json() and all(e["em"] for e in r.json())
    for params in ({"limite": 201}, {"limite": 0}, {"antes_de_id": 0}, {"ator_id": "x"}):
        assert cliente.get(f"{V}/auditoria", params=params).status_code == 422, params


def test_filtros_vao_como_bind_nunca_no_texto_do_sql(cliente, owner, banco):
    """Checklist do validador: valor malicioso no filtro não muda a consulta (vai como parâmetro)
    e a fonte não monta SQL com f-string/format/concatenação."""
    malicioso = "x' OR '1'='1"
    r = _ok(cliente.get(f"{V}/auditoria", params={"alvo_id": malicioso}))
    assert r.json() == []
    r = cliente.get(f"{V}/auditoria", params={"tipo": "a.b' OR 1=1 --"})
    assert r.status_code == 422  # tipo tem formato fixo
    fonte = inspect.getsource(auditoria)
    assert auditoria.SQL.count("%(") == 14 and "{" not in auditoria.SQL
    assert ".format(" not in fonte and 'f"""' not in fonte and "SQL +" not in fonte


def test_so_eventos_da_propria_org(cliente, owner, banco):
    with psycopg.connect(banco["dono"]) as conn:
        (outra,) = conn.execute(
            "INSERT INTO organizacoes (nome) VALUES ('B') RETURNING id"
        ).fetchone()
        conn.execute(
            "INSERT INTO eventos (org_id, tipo, resultado) VALUES (%s, 'org.criada', 'ok')",
            (outra,),
        )
    eventos = _ok(cliente.get(f"{V}/auditoria", params={"limite": 200})).json()
    assert eventos
    (n,) = ler(banco, "SELECT count(*) FROM eventos WHERE org_id = %s", (owner["org_id"],))[0]
    assert len(eventos) == n


def test_minha_conta_ve_os_proprios_logins(cliente, owner, novo_cliente):
    """RF-A06 (segunda parte): GET /eu/eventos devolve só os eventos auth.* do próprio usuário."""
    from conftest import login

    m = ativar(cliente, novo_cliente, "proprio@t.invalid")
    login(novo_cliente(), "errado" * 7 + "a", "proprio@t.invalid")
    eventos = _ok(m["cliente"].get(f"{V}/eu/eventos")).json()
    assert eventos and all(e["tipo"].startswith("auth.") for e in eventos)
    assert {e["tipo"] for e in eventos} >= {"auth.login"}
    assert {e["resultado"] for e in eventos} == {"ok", "falha"}
