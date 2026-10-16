"""Consulta de auditoria (§5.5, RF-A06): owner/admin, filtros e cursor `antes_de_id`."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request
from psycopg.rows import dict_row

from app import db, seguranca

rota = APIRouter()

# SQL fixo: todo filtro entra como parâmetro (bind); filtro ausente = NULL = não filtra.
# Usa o índice eventos (org_id, id DESC); o cursor é o id, estável mesmo com eventos novos.
SQL = """SELECT id, em, tipo, resultado, ator_id, alvo_tipo, alvo_id, host(ip) AS ip,
                user_agent, meta
         FROM eventos
         WHERE org_id = %(org)s
           AND (%(de)s::timestamptz IS NULL OR em >= %(de)s::timestamptz)
           AND (%(ate)s::timestamptz IS NULL OR em <= %(ate)s::timestamptz)
           AND (%(ator)s::uuid IS NULL OR ator_id = %(ator)s::uuid)
           AND (%(tipo)s::text IS NULL OR tipo = %(tipo)s::text)
           AND (%(alvo)s::text IS NULL OR alvo_id = %(alvo)s::text)
           AND (%(antes)s::bigint IS NULL OR id < %(antes)s::bigint)
         ORDER BY id DESC
         LIMIT %(limite)s"""


@rota.get("/auditoria")
def consultar(
    request: Request,
    sessao: seguranca.Gestor,
    de: datetime | None = None,
    ate: datetime | None = None,
    ator_id: UUID | None = None,
    tipo: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_]+\.[a-z_]+$")] = None,
    alvo_id: Annotated[str | None, Query(max_length=200)] = None,
    antes_de_id: Annotated[int | None, Query(ge=1)] = None,
    limite: Annotated[int, Query(ge=1, le=200)] = 50,
):
    """Eventos da organização do mais novo ao mais antigo; próxima página: antes_de_id = id do
    último recebido (página com menos de `limite` eventos = fim)."""
    params = {
        "org": sessao.org_id,
        "de": de,
        "ate": ate,
        "ator": ator_id,
        "tipo": tipo,
        "alvo": alvo_id,
        "antes": antes_de_id,
        "limite": limite,
    }
    with db.transacao(request.app.state.pool) as conn:
        return conn.cursor(row_factory=dict_row).execute(SQL, params).fetchall()
