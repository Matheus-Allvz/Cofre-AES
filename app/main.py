import logging
import time
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout

from app import config, db, erros, logs
from app.rotas import auth, convites

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


@app.get("/api/saude")
def saude():
    return {"status": "ok"}


@app.get("/api/pronto")
def pronto(request: Request):
    try:
        with request.app.state.pool.connection(timeout=2) as conn:
            conn.execute("SELECT 1")
    except psycopg.Error, PoolTimeout:
        return JSONResponse({"erro": "banco_indisponivel"}, status_code=503)
    return {"status": "ok"}
