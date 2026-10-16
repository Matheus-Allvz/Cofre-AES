"""Membros da organização (§5.3): listar, confirmar, suspender/reativar, papel, remover.

Fase 7: promoção a owner e reativação de owner com envelopes `gerenciar` (D13), remoção com
relatório de offboarding e marcação de rotação (RF-U03/U04/U05).
"""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from psycopg.rows import dict_row
from pydantic import Field, StringConstraints

from app import auditoria, db, relogio, seguranca
from app.rotas.auth import Entrada
from app.rotas.cofre import X1, marcar_rotacao

rota = APIRouter()


class Confirmacao(Entrada):
    fingerprint: Annotated[str, StringConstraints(max_length=80)]


class EnvelopeOwner(Entrada):
    colecao_id: UUID
    chave_ver: int = Field(ge=1)
    chave_colecao_cif: X1


class NovoPapel(Entrada):
    papel: Literal["owner", "admin", "member"]
    # Só na promoção a owner: um envelope `gerenciar` por coleção da org (D13).
    envelopes: list[EnvelopeOwner] = Field(default_factory=list, max_length=20_000)


class Reativacao(Entrada):
    # Só para owner: envelopes das coleções em que ele não tem `gerenciar` (criadas enquanto
    # estava suspenso). Quem reativa owner é owner e tem todas as collectionKeys (D13).
    envelopes: list[EnvelopeOwner] = Field(default_factory=list, max_length=20_000)


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


class SemMudanca(dict):
    """Resposta de uma ação que não mudou nada: sem UPDATE e sem evento."""


def _acao(
    request: Request,
    sessao,
    alvo_id: UUID,
    tipo: str,
    estados: tuple,
    efeito,
    *,
    tira_owner: bool = True,
    so_owner: bool = False,
    meta=None,
):
    """Esqueleto comum, numa transação: trava a gestão da org e o alvo; checa, nesta ordem,
    404, admin sobre owner (403), último owner, auto_acao e estado (409); aplica `efeito` e
    grava o evento (exceto se `efeito` devolver SemMudanca).
    `tira_owner`: a ação deixa o alvo de contar como owner ativo."""
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
        if so_owner and ator["papel"] != "owner":
            raise HTTPException(403, "sem_permissao")
        alvo = db.linha(
            conn,
            "SELECT * FROM usuarios WHERE id = %s AND org_id = %s FOR UPDATE",
            (alvo_id, sessao.org_id),
        )
        if alvo is None:
            raise HTTPException(404, "nao_encontrado")
        if alvo["papel"] == "owner" and ator["papel"] != "owner":
            raise HTTPException(403, "sem_permissao")
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
        if alvo["estado"] not in estados:
            raise HTTPException(409, "estado_invalido")
        resposta = efeito(conn, alvo)
        if isinstance(resposta, SemMudanca):
            return dict(resposta)
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


def envelopes_de_owner(conn, org_id, alvo_id, envelopes, todas: bool) -> int:
    """D13: o alvo passa a ter `gerenciar` (com o envelope recebido) nas coleções exigidas —
    `todas` as da org na promoção (substitui o envelope que ele já tiver: mesma chave); na
    reativação, exatamente as em que ele não tem envelope — um envelope que substituiria o atual
    é recusado (409 envelope_existente): o envelope guardado pode ser o de uma rotação feita
    enquanto ele estava suspenso e ninguém precisa trocá-lo. Trava as coleções da org (ordem de
    id): nenhuma é criada (trava consultiva) nem rotacionada no meio."""
    por = {e.colecao_id: e for e in envelopes}
    if len(por) != len(envelopes):
        raise HTTPException(422, "envelopes_duplicados")
    colecoes = dict(
        conn.execute(
            "SELECT id, chave_ver FROM colecoes WHERE org_id = %s ORDER BY id FOR UPDATE",
            (org_id,),
        ).fetchall()
    )
    tem = {
        cid
        for (cid,) in conn.execute(
            "SELECT colecao_id FROM colecao_membros WHERE usuario_id = %s", (alvo_id,)
        )
    }
    exigidas = set(colecoes) if todas else set(colecoes) - tem
    if not exigidas <= set(por) or not set(por) <= set(colecoes):
        raise HTTPException(422, "envelopes_incompletos")
    if not todas and set(por) & tem:
        raise HTTPException(409, "envelope_existente")
    if any(e.chave_ver != colecoes[cid] for cid, e in por.items()):
        raise HTTPException(409, "chave_ver_desatualizada")
    with conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO colecao_membros
                 (colecao_id, usuario_id, permissao, chave_ver, chave_colecao_cif)
               VALUES (%s, %s, 'gerenciar', %s, %s)
               ON CONFLICT (colecao_id, usuario_id) DO UPDATE
               SET permissao = 'gerenciar', chave_ver = EXCLUDED.chave_ver,
                   chave_colecao_cif = EXCLUDED.chave_colecao_cif""",
            [(cid, alvo_id, e.chave_ver, e.chave_colecao_cif) for cid, e in por.items()],
        )
    return len(por)


@rota.post("/membros/{alvo_id}/reativar")
def reativar(
    alvo_id: UUID, request: Request, sessao: seguranca.Gestor, dados: Reativacao | None = None
):
    """Owner reativado precisa de envelope das coleções criadas enquanto estava suspenso
    (422 envelopes_incompletos): quem reativa (owner) manda pelo cliente dele."""
    envelopes = dados.envelopes if dados else []

    def efeito(conn, alvo):
        if alvo["papel"] == "owner":
            envelopes_de_owner(conn, sessao.org_id, alvo["id"], envelopes, todas=False)
        elif envelopes:
            raise HTTPException(422, "envelopes_incompletos")
        _estado(conn, alvo["id"], "ativo")
        return {"id": alvo["id"], "estado": "ativo"}

    return _acao(
        request, sessao, alvo_id, "membro.reativado", ("suspenso",), efeito, tira_owner=False
    )


@rota.put("/membros/{alvo_id}/papel")
def alterar_papel(alvo_id: UUID, dados: NovoPapel, request: Request, sessao: seguranca.Gestor):
    """admin ↔ member (owner/admin); rebaixar owner e promover a owner (só owner). Promover exige
    alvo ativo e um envelope `gerenciar` de TODAS as coleções da org (RF-U05/D13). O papel é
    lido do banco a cada requisição: vale na hora para as sessões abertas do alvo."""
    promover = dados.papel == "owner"
    if dados.envelopes and not promover:
        raise HTTPException(422, "envelopes_incompletos")

    def efeito(conn, alvo):
        if alvo["papel"] == dados.papel:  # mesmo papel: 200 idempotente, sem evento
            return SemMudanca(id=alvo["id"], papel=dados.papel)
        if promover:
            envelopes_de_owner(conn, sessao.org_id, alvo["id"], dados.envelopes, todas=True)
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
        ("ativo",) if promover else ("aceito", "ativo", "suspenso"),
        efeito,
        so_owner=promover,
        meta=lambda alvo: {"antes": alvo["papel"], "depois": dados.papel},
    )


@rota.delete("/membros/{alvo_id}")
def remover(alvo_id: UUID, request: Request, sessao: seguranca.Gestor):
    """Corta o acesso e anonimiza nome/e-mail (RNF-15d); eventos ficam com o ator_id.
    RF-U03: apaga os envelopes dele, marca as coleções que ele alcançava `rotacao_pendente` e os
    itens delas (inclusive lixeira) `rotacao_senha_pendente`, e devolve o relatório."""
    relatorio = []

    def efeito(conn, alvo):
        _cortar_acesso(conn, alvo["id"])
        colecoes = [
            cid
            for (cid,) in conn.execute(
                """SELECT c.id FROM colecoes c JOIN colecao_membros cm ON cm.colecao_id = c.id
                   WHERE cm.usuario_id = %s ORDER BY c.id FOR UPDATE OF c""",
                (alvo["id"],),
            )
        ]
        itens = {cid: [] for cid in colecoes}
        for iid, cid in conn.execute(
            "SELECT id, colecao_id FROM itens WHERE colecao_id = ANY(%s) ORDER BY id",
            (colecoes,),
        ):
            itens[cid].append(iid)
        conn.execute("DELETE FROM colecao_membros WHERE usuario_id = %s", (alvo["id"],))
        marcar_rotacao(conn, colecoes)
        conn.execute(
            """UPDATE usuarios SET estado = 'removido', nome = NULL,
                      email = 'removido-' || id || '@invalido', atualizado_em = now()
               WHERE id = %s""",
            (alvo["id"],),
        )
        relatorio.extend(
            {"colecao_id": str(cid), "itens": [str(i) for i in itens[cid]]} for cid in colecoes
        )
        return {"relatorio": relatorio}

    return _acao(
        request,
        sessao,
        alvo_id,
        "membro.removido",
        ("convidado", "aceito", "ativo", "suspenso"),
        efeito,
        # Relatório de offboarding consultável depois (GET /auditoria): ids não são segredo.
        meta=lambda alvo: {"colecoes": len(relatorio), "relatorio": relatorio},
    )
