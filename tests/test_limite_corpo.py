"""Limite global do corpo (achado de segurança herdado na Fase 7): 413 antes do parse."""

import json

import pytest

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
    import asyncio

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


def test_rota_grande_exige_cookie_e_aceita_ate_20_mib(cliente):
    url = f"{V}/colecoes/00000000-0000-0000-0000-000000000000/rotacionar"
    h = {"Content-Type": "application/json", "X-Cofre": "1"}
    r = cliente.post(url, content=b"{}" + b" " * (1 << 20), headers=h)
    assert (r.status_code, r.json()) == (401, {"erro": "nao_autenticado"})
    cliente.cookies.set("sessao", "invalida")
    r = cliente.post(url, content=b"{}" + b" " * (1 << 20), headers=h)
    assert (r.status_code, r.json()) == (401, {"erro": "nao_autenticado"})  # passou do limite
    r = cliente.post(url, content=b" " * (main.LIMITE_GRANDE + 1), headers=h)
    assert (r.status_code, r.json()) == (413, CORPO_GRANDE)
    for rota in ("/membros/x/papel", "/membros/x/reativar"):
        metodo = "PUT" if rota.endswith("papel") else "POST"
        r = cliente.request(metodo, V + rota, content=b" " * (1 << 20), headers=h)
        assert r.status_code != 413, rota
