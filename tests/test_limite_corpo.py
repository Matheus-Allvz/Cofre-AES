"""Limite global do corpo (achado de segurança herdado na Fase 7): 413 antes do parse."""

import asyncio
import json
import time

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import main

V = "/api/v1"
GRANDE = b'{"email":"' + b"a" * (300 * 1024) + b'"}'
CORPO_GRANDE = {"erro": "corpo_grande"}


@pytest.mark.parametrize("rota", ["/prelogin", "/login", "/convites/aceitar", "/colecoes"])
def test_content_length_acima_do_limite_da_413_sem_cookie(cliente, rota):
    r = cliente.post(V + rota, content=GRANDE, headers={"Content-Type": "application/json"})
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    assert r.headers["cache-control"] == "no-store"


def test_chunked_sem_content_length_e_contado_no_stream(cliente):
    def pedacos():
        for _ in range(40):
            yield b"a" * (16 * 1024)

    r = cliente.post(
        f"{V}/prelogin", content=pedacos(), headers={"Content-Type": "application/json"}
    )
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)


def test_receive_conta_bytes_mesmo_com_content_length_mentiroso(cliente):
    """Content-Length pequeno e corpo maior: o servidor real (uvicorn) corta pelo header, mas
    o contador do middleware não confia nele."""

    msgs = [{"type": "http.request", "body": b"x" * 200_000, "more_body": True}] * 3
    enviados = []

    async def receive():
        return msgs.pop(0) if msgs else {"type": "http.disconnect"}

    async def send(m):
        enviados.append(m)

    async def app_que_le(scope, rec, snd):  # como o Starlette: desconexão no meio = exceção
        while True:
            msg = await rec()
            if msg["type"] == "http.disconnect":
                raise RuntimeError("cliente desconectou")
            if not msg.get("more_body"):
                break

    escopo = {"type": "http", "method": "POST", "path": "/api/v1/prelogin"}
    escopo["headers"] = [(b"content-length", b"10")]
    asyncio.run(main.LimiteCorpo(app_que_le)(escopo, receive, send))
    assert enviados[0]["status"] == 413
    assert json.loads(enviados[1]["body"]) == CORPO_GRANDE


def test_corpo_dentro_do_limite_segue_normal(cliente):
    r = cliente.post(f"{V}/prelogin", json={"email": "a" * (200 * 1024)})
    assert r.status_code == 422  # passou do limite de corpo e caiu na validação normal


URL_ROT = f"{V}/colecoes/00000000-0000-0000-0000-000000000000/rotacionar"
HJ = {"Content-Type": "application/json", "X-Cofre": "1"}
H = {"X-Cofre": "1"}
UM_MIB = b"{}" + b" " * (1 << 20)


def test_rota_grande_so_com_sessao_valida_aceita_ate_20_mib(cliente, owner, banco):
    from test_cofre import criar_colecao, env

    col = criar_colecao(cliente, [env(owner["usuario_id"])])[0].json()["id"]
    url = f"{V}/colecoes/{col}/rotacionar"
    r = cliente.post(url, content=UM_MIB, headers=HJ)  # sessão válida + gerenciar: passa
    assert r.status_code == 422 and "detail" in r.json()  # e cai na validação do corpo
    r = cliente.post(url, content=b" " * (main.LIMITE_GRANDE + 1), headers=HJ)
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    for metodo, rota in (("PUT", "/membros/x/papel"), ("POST", "/membros/x/reativar")):
        r = cliente.request(metodo, V + rota, content=UM_MIB, headers=HJ)
        assert r.status_code != 413, rota
    r = cliente.post(f"{V}/prelogin", content=UM_MIB, headers=HJ)  # sessão não abre as outras
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    # Coleção sem envelope dele (ou id inválido): sem a permissão da rota, limite pequeno.
    for outra in ("00000000-0000-0000-0000-000000000000", "nao-e-uuid"):
        r = cliente.post(f"{V}/colecoes/{outra}/rotacionar", content=UM_MIB, headers=HJ)
        assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    # Sessão revogada (ou de usuário suspenso) volta ao limite pequeno.
    with psycopg.connect(banco["dono"]) as conn:
        conn.execute("UPDATE sessoes SET revogada_em = now()")
    r = cliente.post(url, content=UM_MIB, headers=HJ)
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)


def test_corpo_grande_exige_a_permissao_da_rota(cliente, owner, novo_cliente, banco, caplog):
    """Herdado da Fase 7: a mesma consulta que valida a sessão confere a permissão da rota
    grande. `editar` na coleção não ganha 20 MiB para rotacionar; admin não ganha para
    papel/reativar (envelopes de todas as coleções só vão em promover/reativar OWNER, que só owner
    faz). Sem a permissão: 413 na hora, log com usuario_id e nenhuma vaga ocupada."""
    import logging

    from conftest import ativar
    from test_cofre import criar_colecao, env

    adm = ativar(cliente, novo_cliente, "adm-corpo@t.invalid", "admin")
    ed = ativar(cliente, novo_cliente, "ed-corpo@t.invalid")
    col = criar_colecao(cliente, [env(owner["usuario_id"]), env(ed["id"], "editar")])[0].json()
    url = f"{V}/colecoes/{col['id']}/rotacionar"
    with caplog.at_level(logging.WARNING, "cofre.corpo"):
        r = ed["cliente"].post(url, content=UM_MIB, headers=HJ)
        assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
        for metodo, rota in (("PUT", "papel"), ("POST", "reativar")):
            r = adm["cliente"].request(
                metodo, f"{V}/membros/{ed['id']}/{rota}", content=UM_MIB, headers=HJ
            )
            assert (r.status_code, r.json()) == (413, CORPO_GRANDE), rota
    recusas = [r for r in caplog.records if r.getMessage() == "corpo_recusado"]
    assert [(r.status, r.usuario_id) for r in recusas] == [
        (413, ed["id"]),
        (413, adm["id"]),
        (413, adm["id"]),
    ]
    assert main._grandes == 0
    # 413 não vira evento (só 408/503 de usuário autenticado).
    assert ler_eventos(banco, "requisicao.recusada") == []
    # Dentro do limite pequeno, nada muda: admin troca papel de member normalmente.
    r = adm["cliente"].put(f"{V}/membros/{ed['id']}/papel", json={"papel": "admin"}, headers=H)
    assert r.status_code == 200


def ler_eventos(banco, tipo):
    from conftest import ler

    return ler(
        banco,
        "SELECT ator_id::text, resultado, alvo_id, meta FROM eventos WHERE tipo = %s",
        (tipo,),
    )


def test_vaga_ocupada_503_vira_log_e_evento(cliente, owner, banco, monkeypatch, caplog):
    import logging

    from test_cofre import criar_colecao, env

    col = criar_colecao(cliente, [env(owner["usuario_id"])])[0].json()["id"]
    monkeypatch.setattr(main, "_grandes", 1)  # outra requisição grande em andamento
    url = f"{V}/colecoes/{col}/rotacionar"
    with caplog.at_level(logging.WARNING, "cofre.corpo"):
        r = cliente.post(url, content=UM_MIB, headers=HJ)
    assert (r.status_code, r.json()) == (503, {"erro": "ocupado"})
    assert r.headers["retry-after"] == "5"
    (reg,) = [r for r in caplog.records if r.getMessage() == "corpo_recusado"]
    assert (reg.status, reg.codigo, reg.usuario_id) == (503, "ocupado", owner["usuario_id"])
    assert ler_eventos(banco, "requisicao.recusada") == [
        (owner["usuario_id"], "falha", f"POST {url}", {"status": 503, "codigo": "ocupado"})
    ]


@pytest.mark.parametrize("cookie", [None, "falso", "sessao-qualquer-" + "x" * 30])
def test_cookie_falso_nao_ganha_limite_grande_nem_a_vaga(cliente, owner, monkeypatch, cookie):
    """Achado da validação: qualquer `sessao=` ganhava 20 MiB e a vaga única. Agora só sessão
    válida no banco; o resto leva 413 na hora, mesmo com a vaga ocupada (não 503)."""
    outro = TestClient(main.app, base_url="https://testserver")
    if cookie:
        outro.cookies.set("sessao", cookie)
    monkeypatch.setattr(main, "_grandes", 1)  # vaga ocupada por outra requisição
    r = outro.post(URL_ROT, content=UM_MIB, headers=HJ)
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)

    def devagar():
        for _ in range(40):
            yield b" " * (16 * 1024)

    r = outro.post(URL_ROT, content=devagar(), headers=HJ)  # chunked
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    assert main._grandes == 1  # não pegou nem soltou vaga


def test_corpo_grande_lento_com_sessao_valida_408_e_libera_a_vaga(
    cliente, owner, banco, monkeypatch
):
    """Sessão válida enviando devagar além do prazo → 408 corpo_lento e a vaga volta; uma
    rotação legítima logo depois (corpo > 256 KiB, que precisa da vaga) → 200."""
    from test_cofre import criar_colecao, env
    from test_compartilhar import corpo_rotacao

    monkeypatch.setattr(main, "PRAZO_CORPO_S", 0.3)
    r, col = criar_colecao(cliente, [env(owner["usuario_id"])])
    assert r.status_code == 201
    token = cliente.cookies["sessao"]
    msgs = [{"type": "http.request", "body": b"{", "more_body": True}]
    enviados = []

    async def receive():
        if msgs:
            return msgs.pop(0)
        await asyncio.sleep(5)  # cliente "parado" no meio do corpo
        return {"type": "http.request", "body": b"}", "more_body": False}

    async def send(m):
        enviados.append(m)

    async def app_que_le(scope, rec, snd):
        while True:
            msg = await rec()
            if msg["type"] == "http.disconnect":
                raise RuntimeError("cliente desconectou")
            if not msg.get("more_body"):
                break

    escopo = {
        "type": "http",
        "method": "POST",
        "path": f"/api/v1/colecoes/{col}/rotacionar",
        "headers": [(b"cookie", f"sessao={token}".encode()), (b"content-length", b"1000000")],
        "app": main.app,
    }
    inicio = time.monotonic()
    asyncio.run(main.LimiteCorpo(app_que_le)(escopo, receive, send))
    assert time.monotonic() - inicio < 3
    assert enviados[0]["status"] == 408
    assert json.loads(enviados[1]["body"]) == {"erro": "corpo_lento"}
    assert main._grandes == 0  # vaga liberada
    # Herdado: 408 de usuário autenticado vira evento de auditoria (e log com usuario_id).
    assert ler_eventos(banco, "requisicao.recusada") == [
        (
            owner["usuario_id"],
            "falha",
            f"POST /api/v1/colecoes/{col}/rotacionar",
            {"status": 408, "codigo": "corpo_lento"},
        )
    ]
    monkeypatch.setattr(main, "PRAZO_CORPO_S", 60)
    corpo = json.dumps(corpo_rotacao(banco, col)).encode() + b" " * (300 << 10)
    r = cliente.post(f"{V}/colecoes/{col}/rotacionar", content=corpo, headers=HJ)
    assert (r.status_code, r.json()) == (200, {"chave_ver": 2})
