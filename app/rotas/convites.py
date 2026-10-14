"""Convites: criação pela CLI (bootstrap) ou por owner/admin; revogação (§5.3)."""

from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints

from app import auditoria, db, relogio, seguranca

VALIDADE = timedelta(hours=72)

Email = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$"
    ),
]

rota = APIRouter()


def criar_convite(conn, *, org_id, usuario_id, papel, criado_por, **origem) -> tuple[UUID, str]:
    """Grava o convite (só o hash do token) e o evento; devolve (convite_id, token)."""
    token, token_hash = seguranca.novo_token()
    (convite_id,) = conn.execute(
        """INSERT INTO convites (org_id, usuario_id, token_hash, papel, criado_por, expira_em)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
        (org_id, usuario_id, token_hash, papel, criado_por, relogio.agora() + VALIDADE),
    ).fetchone()
    auditoria.registrar(
        conn,
        org_id=org_id,
        ator_id=criado_por,
        tipo="convite.criado",
        alvo_tipo="usuario",
        alvo_id=str(usuario_id),
        meta={"papel": papel, "convite_id": str(convite_id)},
        **origem,
    )
    return convite_id, token


class NovoConvite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Email
    papel: Literal["admin", "member"]


@rota.post("/convites", status_code=201)
def convidar(
    dados: NovoConvite,
    request: Request,
    sessao: seguranca.Gestor,
):
    try:
        with db.transacao(request.app.state.pool) as conn:
            (usuario_id,) = conn.execute(
                "INSERT INTO usuarios (org_id, email, papel) VALUES (%s, %s, %s) RETURNING id",
                (sessao.org_id, dados.email, dados.papel),
            ).fetchone()
            convite_id, token = criar_convite(
                conn,
                org_id=sessao.org_id,
                usuario_id=usuario_id,
                papel=dados.papel,
                criado_por=sessao.usuario_id,
                **seguranca.origem(request),
            )
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "email_em_uso") from None
    # Fragmento: o browser não envia o token ao servidor ao abrir o link (§6).
    return {"convite_id": convite_id, "usuario_id": usuario_id, "link": f"/#/convite/{token}"}


@rota.delete("/convites/{convite_id}", status_code=204)
def revogar(
    convite_id: UUID,
    request: Request,
    sessao: seguranca.Gestor,
):
    erro = None
    with db.transacao(request.app.state.pool) as conn:
        c = db.linha(
            conn,
            "SELECT usuario_id, usado_em, revogado_em FROM convites"
            " WHERE id = %s AND org_id = %s FOR UPDATE",
            (convite_id, sessao.org_id),
        )
        if c is None:
            erro = (404, "nao_encontrado")
        elif c["usado_em"]:
            erro = (409, "convite_usado")
        elif not c["revogado_em"]:
            conn.execute(
                "UPDATE convites SET revogado_em = %s WHERE id = %s",
                (relogio.agora(), convite_id),
            )
            # Libera o e-mail para um novo convite (anonimiza como na remoção, §5.3).
            conn.execute(
                """UPDATE usuarios SET estado = 'removido', nome = NULL,
                          email = 'removido-' || id || '@invalido', atualizado_em = now()
                   WHERE id = %s AND estado = 'convidado'""",
                (c["usuario_id"],),
            )
            auditoria.registrar(
                conn,
                org_id=sessao.org_id,
                ator_id=sessao.usuario_id,
                tipo="convite.revogado",
                alvo_tipo="convite",
                alvo_id=str(convite_id),
                **seguranca.origem(request),
            )
    if erro:
        raise HTTPException(*erro)
    return Response(status_code=204)
