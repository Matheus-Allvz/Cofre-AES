import asyncio
import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout
from starlette.requests import Request as RequestAsgi
from starlette.requests import cookie_parser

from app import auditoria, config, db, erros, logs, seguranca
from app.rotas import auditoria as rota_auditoria
from app.rotas import auth, cofre, conta, convites, membros, org

logs.configurar()
log = logging.getLogger("cofre.http")


@asynccontextmanager
async def ciclo(app: FastAPI):
    cfg = config.carregar()
    app.state.config = cfg
    app.state.pool = db.criar_pool(cfg.database_url)
    yield
    app.state.pool.close()


app = FastAPI(title="Cofre AES Empresarial", lifespan=ciclo, docs_url=None, redoc_url=None)
erros.registrar(app)
app.include_router(auth.rota, prefix="/api/v1")
app.include_router(convites.rota, prefix="/api/v1")
app.include_router(conta.rota, prefix="/api/v1")
app.include_router(org.rota, prefix="/api/v1")
app.include_router(membros.rota, prefix="/api/v1")
app.include_router(cofre.rota, prefix="/api/v1")
app.include_router(rota_auditoria.rota, prefix="/api/v1")


@app.middleware("http")
async def requisicao(request: Request, call_next):
    inicio = time.perf_counter()
    resposta = await call_next(request)
    resposta.headers["Cache-Control"] = "no-store"
    # Nunca o corpo nem a query string: só método, caminho, status e duração.
    log.info(
        "requisicao",
        extra={
            "metodo": request.method,
            "rota": request.url.path,
            "status": resposta.status_code,
            "duracao_ms": round((time.perf_counter() - inicio) * 1000, 1),
        },
    )
    return resposta


# ---------- limite de corpo (antes de qualquer parse) ----------

LIMITE_CORPO = 256 * 1024
LIMITE_GRANDE = 20 * 1024 * 1024
# Rotação (coleção inteira recifrada; exige `gerenciar` nela) e envelopes de owner para todas
# as coleções (promover a owner / reativar owner: só owner faz, então só owner ganha o limite).
ROTAS_GRANDES = re.compile(
    r"^(POST /api/v1/colecoes/(?P<colecao>[^/]+)/rotacionar|PUT /api/v1/membros/[^/]+/papel"
    r"|POST /api/v1/membros/[^/]+/reativar)$"
)
log_corpo = logging.getLogger("cofre.corpo")
# ponytail: um corpo grande (> 256 KiB) por vez no processo (o parse JSON de 20 MiB pesa
# várias vezes isso, ver mem_limit); o segundo recebe 503 ocupado + Retry-After e o cliente
# repete. Fila por usuário se rotações simultâneas virarem rotina.
MAX_GRANDES = 1
# Prazo para receber o corpo grande inteiro (20 MiB a 1 Mbit/s levam ~170 s; no uso real o
# front envia em poucos segundos). Configurável: COFRE_PRAZO_CORPO_S.
PRAZO_CORPO_S = float(os.environ.get("COFRE_PRAZO_CORPO_S", "60"))
_grandes = 0
_trava_grandes = threading.Lock()


def _registrar_recusa(scope, status: int, codigo: str, sessao) -> None:
    """408/413/503 do limite de corpo: log estruturado (com usuario_id quando a sessão foi
    consultada) e, para 408/503 de usuário autenticado, evento de auditoria. Nunca o corpo."""
    usuario_id = sessao and str(sessao[0])
    log_corpo.warning(
        "corpo_recusado",
        extra={
            "metodo": scope["method"],
            "rota": scope["path"],
            "status": status,
            "codigo": codigo,
            "usuario_id": usuario_id,
        },
    )
    if sessao is None or status == 413:
        return
    try:
        with db.transacao(scope["app"].state.pool) as conn:
            auditoria.registrar(
                conn,
                org_id=sessao[1],
                ator_id=sessao[0],
                tipo="requisicao.recusada",
                resultado="falha",
                alvo_tipo="rota",
                alvo_id=f"{scope['method']} {scope['path']}",
                meta={"status": status, "codigo": codigo},
                **seguranca.origem(RequestAsgi(scope)),
            )
    except Exception:  # a resposta de erro sai mesmo sem o evento
        log_corpo.exception("evento_recusa_falhou")


async def _erro(send, status: int, codigo: str, extra=()) -> None:
    corpo = json.dumps({"erro": codigo}, separators=(",", ":")).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(corpo)).encode()),
        (b"cache-control", b"no-store"),
        (b"connection", b"close"),
        *extra,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": corpo})


class LimiteCorpo:
    """Limite global do corpo, conferido no Content-Length e contado no stream (chunked):
    256 KiB. 20 MiB só nas ROTAS_GRANDES e só para sessão VÁLIDA com a permissão da rota
    (consultadas no banco, numa consulta, antes de ler o corpo), um corpo grande por vez e com
    prazo de leitura (PRAZO_CORPO_S): estourou → 408 e a vaga é liberada. Sem isso, POSTs de
    150 MB sem cookie matavam a API por OOM e um cookie qualquer segurava a vaga com um corpo
    enviado devagar."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        asgi = self.app
        if scope["type"] != "http":
            return await asgi(scope, receive, send)
        headers = dict(scope["headers"])
        tamanho = headers.get(b"content-length")
        sessao = None  # (usuario_id, org_id, permitido) quando a sessão foi consultada

        async def recusar(status, codigo, extra=()):
            await asyncio.to_thread(_registrar_recusa, scope, status, codigo, sessao)
            await _erro(send, status, codigo, extra)

        if tamanho is not None and not tamanho.isdigit():
            return await recusar(413, "corpo_grande")
        # Só quem pode passar do limite pequeno (Content-Length acima dele ou chunked) numa rota
        # grande custa a consulta da sessão; troca de papel comum segue sem banco nem fila.
        grande = False
        rota_grande = (tamanho is None or int(tamanho) > LIMITE_CORPO) and ROTAS_GRANDES.match(
            f"{scope['method']} {scope['path']}"
        )
        if rota_grande:
            cookie = headers.get(b"cookie", b"").decode("latin-1")
            token = cookie_parser(cookie).get(seguranca.COOKIE)
            if token:
                sessao = await asyncio.to_thread(
                    seguranca.sessao_corpo_grande,
                    scope["app"].state.pool,
                    token,
                    rota_grande["colecao"],
                    scope["path"].endswith("/rotacionar"),
                )
            grande = bool(sessao and sessao[2])
        limite = LIMITE_GRANDE if grande else LIMITE_CORPO
        if tamanho is not None and int(tamanho) > limite:
            return await recusar(413, "corpo_grande")
        lidos = 0
        completo = respondeu = False
        erro = None  # (status, código) que substitui a resposta do app
        prazo = time.monotonic() + PRAZO_CORPO_S if grande else None

        async def receber():
            # Passou do limite ou do prazo: para de ler e finge desconexão; a resposta que o
            # app montar (400/500 de corpo truncado) é trocada pelo erro em enviar().
            nonlocal lidos, completo, erro
            if erro:
                return {"type": "http.disconnect"}
            if prazo is None or completo:
                msg = await receive()
            else:
                try:
                    msg = await asyncio.wait_for(receive(), prazo - time.monotonic())
                except TimeoutError:
                    erro = (408, "corpo_lento")
                    return {"type": "http.disconnect"}
            if msg["type"] == "http.request":
                lidos += len(msg.get("body", b""))
                completo = not msg.get("more_body", False)
                if lidos > limite:
                    erro = (413, "corpo_grande")
                    return {"type": "http.disconnect"}
            return msg

        async def enviar(msg):
            nonlocal respondeu
            if msg["type"] == "http.response.start":
                respondeu = True
                if erro:
                    return await recusar(*erro)
            if not erro:
                await send(msg)

        async def seguir():
            try:
                await asgi(scope, receber, enviar)
            except Exception:
                if not erro or respondeu:
                    raise
                await recusar(*erro)

        if not grande:
            return await seguir()
        global _grandes
        with _trava_grandes:
            livre = _grandes < MAX_GRANDES
            _grandes += livre
        if not livre:
            return await recusar(503, "ocupado", [(b"retry-after", b"5")])
        try:
            await seguir()
        finally:
            with _trava_grandes:
                _grandes -= 1


@app.get("/api/saude")
def saude():
    return {"status": "ok"}


@app.get("/api/pronto")
def pronto(request: Request):
    try:
        with request.app.state.pool.connection(timeout=2) as conn:
            conn.execute("SELECT 1")
    except (psycopg.Error, PoolTimeout):
        return JSONResponse({"erro": "banco_indisponivel"}, status_code=503)
    return {"status": "ok"}


# Último add_middleware = mais externo: o corpo é barrado antes de qualquer leitura/parse.
app.add_middleware(LimiteCorpo)
