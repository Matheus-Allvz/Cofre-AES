"""Membros da organização (§5.3, Fase 5): listar, confirmar, suspender/reativar, papel, remover.

Promoção a owner e o relatório/rotação da remoção são da Fase 7.
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from psycopg.rows import dict_row
from pydantic import StringConstraints

from app import auditoria, db, relogio, seguranca
from app.rotas.auth import Entrada

rota = APIRouter()


class Confirmacao(Entrada):
    fingerprint: Annotated[str, StringConstraints(max_length=80)]


class NovoPapel(Entrada):
    papel: Literal["admin", "member"]  # owner: promoção é da Fase 7


@rota.get("/membros")
def listar(request: Request, sessao: seguranca.Ativo):
    with db.transacao(request.app.state.pool) as conn:
        membros = (
            conn.cursor(row_factory=dict_row)
            .execute(
                """SELECT id, email::text AS email, nome, papel, estado, chave_publica,
                          fingerprint_confirmado
                   FROM usuarios WHERE org_id = %s AND estado <> 'removido'
                   ORDER BY criado_em, id""",
                (sessao.org_id,),
            )
            .fetchall()
        )
    for m in membros:  # convidado ainda não tem chave
        m["chave_publica"] = m["chave_publica"] and seguranca.b64u(m["chave_publica"])
    return membros


def _acao(
    request: Request,
    sessao,
    alvo_id: UUID,
    tipo: str,
    estados: tuple,
    efeito,
    *,
    tira_owner: bool = True,
    meta=None,
):
    """Esqueleto comum, numa transação: trava a gestão da org e o alvo; checa, nesta ordem,
    404, último owner, auto_acao, admin sobre owner (403) e estado (409); aplica `efeito` e
    grava o evento. `tira_owner`: a ação deixa o alvo de contar como owner ativo."""
    with db.transacao(request.app.state.pool) as conn:
        # ponytail: uma trava por org serializa a gestão de membros (10–200 usuários); é ela
        # que impede dois owners de se suspenderem ao mesmo tempo e zerarem os owners.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"membros:{sessao.org_id}",)
        )
        # O ator pode ter sido suspenso/rebaixado enquanto esperava a trava.
        ator = db.linha(
            conn, "SELECT papel, estado FROM usuarios WHERE id = %s", (sessao.usuario_id,)
        )
        if ator["estado"] != "ativo" or ator["papel"] not in ("owner", "admin"):
            raise HTTPException(403, "sem_permissao")
        alvo = db.linha(
            conn,
            "SELECT * FROM usuarios WHERE id = %s AND org_id = %s FOR UPDATE",
            (alvo_id, sessao.org_id),
        )
        if alvo is None:
            raise HTTPException(404, "nao_encontrado")
        if tira_owner and alvo["papel"] == "owner" and alvo["estado"] == "ativo":
            (outros,) = conn.execute(
                """SELECT count(*) FROM usuarios WHERE org_id = %s AND papel = 'owner'
                   AND estado = 'ativo' AND id <> %s""",
                (sessao.org_id, alvo_id),
            ).fetchone()
            if outros == 0:
                raise HTTPException(409, "ultimo_owner")
        if alvo_id == sessao.usuario_id:
            raise HTTPException(409, "auto_acao")
        if alvo["papel"] == "owner" and ator["papel"] != "owner":
            raise HTTPException(403, "sem_permissao")
        if alvo["estado"] not in estados:
            raise HTTPException(409, "estado_invalido")
        resposta = efeito(conn, alvo)
        auditoria.registrar(
            conn,
            org_id=sessao.org_id,
            ator_id=sessao.usuario_id,
            tipo=tipo,
            alvo_tipo="usuario",
            alvo_id=str(alvo_id),
            meta=meta(alvo) if meta else None,
            **seguranca.origem(request),
        )
    return resposta


def _cortar_acesso(conn, usuario_id) -> None:
    """Sessões revogadas, recuperações e convites pendentes invalidados: nada do que o alvo
    tinha em mãos sobrevive a uma suspensão/remoção (nem depois de reativado)."""
    agora = relogio.agora()
    conn.execute(
        "UPDATE sessoes SET revogada_em = %s WHERE usuario_id = %s AND revogada_em IS NULL",
        (agora, usuario_id),
    )
    seguranca.invalidar_recuperacoes(conn, usuario_id)
    conn.execute(
        """UPDATE convites SET revogado_em = %s
           WHERE usuario_id = %s AND usado_em IS NULL AND revogado_em IS NULL""",
        (agora, usuario_id),
    )


def _estado(conn, usuario_id, estado: str) -> None:
    conn.execute(
        "UPDATE usuarios SET estado = %s, atualizado_em = now() WHERE id = %s",
        (estado, usuario_id),
    )


def _fp(texto: str) -> str:
    return "".join(texto.split()).upper()


@rota.post("/membros/{alvo_id}/confirmar")
def confirmar(alvo_id: UUID, dados: Confirmacao, request: Request, sessao: seguranca.Gestor):
    """aceito → ativo só se o fingerprint conferido fora de banda bate com a chave guardada."""

    def efeito(conn, alvo):
        calculado = seguranca.fingerprint(bytes(alvo["chave_publica"]))
        if _fp(dados.fingerprint) != _fp(calculado):
            raise HTTPException(422, "fingerprint_divergente")
        conn.execute(
            """UPDATE usuarios SET estado = 'ativo', fingerprint_confirmado = %s,
                      confirmado_por = %s, atualizado_em = now() WHERE id = %s""",
            (calculado, sessao.usuario_id, alvo["id"]),
        )
        return {"id": alvo["id"], "estado": "ativo", "fingerprint_confirmado": calculado}

    return _acao(
        request, sessao, alvo_id, "membro.confirmado", ("aceito",), efeito, tira_owner=False
    )


@rota.post("/membros/{alvo_id}/suspender")
def suspender(alvo_id: UUID, request: Request, sessao: seguranca.Gestor):
    def efeito(conn, alvo):
        _estado(conn, alvo["id"], "suspenso")
        _cortar_acesso(conn, alvo["id"])
        return {"id": alvo["id"], "estado": "suspenso"}

    return _acao(request, sessao, alvo_id, "membro.suspenso", ("ativo",), efeito)


@rota.post("/membros/{alvo_id}/reativar")
def reativar(alvo_id: UUID, request: Request, sessao: seguranca.Gestor):
    def efeito(conn, alvo):
        _estado(conn, alvo["id"], "ativo")
        return {"id": alvo["id"], "estado": "ativo"}

    return _acao(
        request, sessao, alvo_id, "membro.reativado", ("suspenso",), efeito, tira_owner=False
    )


@rota.put("/membros/{alvo_id}/papel")
def alterar_papel(alvo_id: UUID, dados: NovoPapel, request: Request, sessao: seguranca.Gestor):
    """admin ↔ member (owner/admin) e rebaixar owner (só owner). O papel é lido do banco a cada
    requisição: vale na hora para as sessões abertas do alvo, sem precisar revogá-las."""

    def efeito(conn, alvo):
        conn.execute(
            "UPDATE usuarios SET papel = %s, atualizado_em = now() WHERE id = %s",
            (dados.papel, alvo["id"]),
        )
        return {"id": alvo["id"], "papel": dados.papel}

    return _acao(
        request,
        sessao,
        alvo_id,
        "membro.papel_alterado",
        ("aceito", "ativo", "suspenso"),
        efeito,
        meta=lambda alvo: {"antes": alvo["papel"], "depois": dados.papel},
    )


@rota.delete("/membros/{alvo_id}")
def remover(alvo_id: UUID, request: Request, sessao: seguranca.Gestor):
    """Corta o acesso e anonimiza nome/e-mail (RNF-15d); eventos ficam com o ator_id.
    `relatorio` fica vazio até a Fase 7 (coleções/rotação)."""

    def efeito(conn, alvo):
        _cortar_acesso(conn, alvo["id"])
        conn.execute(
            """UPDATE usuarios SET estado = 'removido', nome = NULL,
                      email = 'removido-' || id || '@invalido', atualizado_em = now()
               WHERE id = %s""",
            (alvo["id"],),
        )
        return {"relatorio": []}

    return _acao(
        request,
        sessao,
        alvo_id,
        "membro.removido",
        ("convidado", "aceito", "ativo", "suspenso"),
        efeito,
    )
