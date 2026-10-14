import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

log = logging.getLogger("cofre.erros")

# Erros gerados pelo próprio framework (detail = frase padrão do status).
PADRAO = {404: "nao_encontrado", 405: "metodo_nao_permitido"}


async def _http(request: Request, exc: HTTPException) -> JSONResponse:
    if exc.detail == HTTPStatus(exc.status_code).phrase:
        codigo = PADRAO.get(exc.status_code, "erro_http")
    else:
        codigo = exc.detail
    return JSONResponse({"erro": codigo}, status_code=exc.status_code, headers=exc.headers)


async def _interno(request: Request, exc: Exception) -> JSONResponse:
    log.error("erro_interno", exc_info=exc, extra={"rota": request.url.path})
    # Este handler roda fora dos middlewares: o no-store vai aqui também.
    return JSONResponse({"erro": "interno"}, status_code=500, headers={"Cache-Control": "no-store"})


def registrar(app: FastAPI) -> None:
    """Corpo de erro único {"erro": "<codigo>"}: rotas levantam HTTPException(status, "codigo")."""
    app.add_exception_handler(HTTPException, _http)
    app.add_exception_handler(Exception, _interno)
