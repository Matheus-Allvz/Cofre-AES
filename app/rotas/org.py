"""Organização e política (§5.3): RF-P03, RF-P07."""

from typing import Annotated

from fastapi import APIRouter, Request
from pydantic import Field, StrictBool, StrictInt

from app import auditoria, db, seguranca
from app.rotas.auth import Entrada

rota = APIRouter()
_CAMPOS = ("mfa_obrigatorio", "inatividade_min")


class Politica(Entrada):
    mfa_obrigatorio: StrictBool
    inatividade_min: Annotated[StrictInt, Field(ge=5, le=60)]


@rota.get("/org")
def org(request: Request, sessao: seguranca.Ativo):
    with db.transacao(request.app.state.pool) as conn:
        o = db.linha(
            conn,
            """SELECT o.id, o.nome, p.mfa_obrigatorio, p.inatividade_min
               FROM organizacoes o JOIN politicas p ON p.org_id = o.id WHERE o.id = %s""",
            (sessao.org_id,),
        )
    return {"id": o["id"], "nome": o["nome"], "politica": {k: o[k] for k in _CAMPOS}}


@rota.put("/org/politica")
def alterar_politica(dados: Politica, request: Request, sessao: seguranca.Gestor):
    depois = dados.model_dump()
    with db.transacao(request.app.state.pool) as conn:
        antes = db.linha(
            conn,
            "SELECT mfa_obrigatorio, inatividade_min FROM politicas WHERE org_id = %s FOR UPDATE",
            (sessao.org_id,),
        )
        conn.execute(
            """UPDATE politicas SET mfa_obrigatorio = %s, inatividade_min = %s,
                      atualizado_em = now() WHERE org_id = %s""",
            (dados.mfa_obrigatorio, dados.inatividade_min, sessao.org_id),
        )
        auditoria.registrar(
            conn,
            org_id=sessao.org_id,
            ator_id=sessao.usuario_id,
            tipo="politica.alterada",
            alvo_tipo="org",
            alvo_id=str(sessao.org_id),
            meta={"antes": antes, "depois": depois},
            **seguranca.origem(request),
        )
    return depois
