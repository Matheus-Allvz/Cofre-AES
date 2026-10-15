"""Coleções e itens (§5.4, Fase 6): sync, coleções, itens, revelar auditado, histórico, lixeira.

Membros de coleção (POST/PUT/DELETE) e rotação são da Fase 7. O servidor só guarda envelopes
opacos: confere formato, tamanho, permissão e versões; nunca decifra nada.

Toda rota abre UMA transação que (1) relê o estado do usuário FOR SHARE (suspender/remover
travam a mesma linha FOR UPDATE), (2) lê o envelope do usuário na coleção FOR SHARE e só então
(3) grava e audita. Sem envelope → 404 (não revela se a coleção/item existe).
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response
from psycopg.rows import dict_row
from pydantic import Field, StringConstraints

from app import auditoria, db, relogio, seguranca
from app.rotas.auth import Entrada

rota = APIRouter()

NIVEL = {"ver_sem_revelar": 0, "ver": 1, "editar": 2, "gerenciar": 3}
Permissao = Literal["ver_sem_revelar", "ver", "editar", "gerenciar"]
LIXEIRA = timedelta(days=30)
MAX_BLOB = 64 * 1024  # §3.1: 422 blob_grande acima
MAX_VERSOES = 10

# Formato v1 sem max_length: o tamanho é conferido na rota para responder 422 blob_grande.
Blob = Annotated[str, StringConstraints(pattern=r"^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$")]
X1 = Annotated[
    str,
    StringConstraints(
        pattern=r"^x1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$", max_length=1024
    ),
]


class Envelope(Entrada):
    usuario_id: UUID
    permissao: Permissao
    chave_colecao_cif: X1


class NovaColecao(Entrada):
    id: UUID
    nome_cif: Blob
    envelopes: list[Envelope] = Field(min_length=1, max_length=1000)


class Renomear(Entrada):
    chave_ver: int = Field(ge=1)
    nome_cif: Blob


class NovoItem(Entrada):
    id: UUID
    tipo: Literal["login", "nota", "chave_api"]
    chave_ver: int = Field(ge=1)
    meta_cif: Blob
    segredo_cif: Blob


class Edicao(Entrada):
    chave_ver: int = Field(ge=1)
    meta_cif: Blob
    segredo_cif: Blob
    senha_trocada: bool = False


def _tamanho(*blobs: str) -> None:
    if any(len(b) > MAX_BLOB for b in blobs):
        raise HTTPException(422, "blob_grande")


@contextmanager
def _transacao(request: Request, sessao) -> Iterator:
    with db.transacao(request.app.state.pool) as conn:
        seguranca.exigir_sessao_viva(conn, sessao, ("ativo",))
        yield conn


def _evento(conn, request, sessao, tipo, alvo_tipo, alvo_id, meta=None) -> None:
    auditoria.registrar(
        conn,
        org_id=sessao.org_id,
        ator_id=sessao.usuario_id,
        tipo=tipo,
        alvo_tipo=alvo_tipo,
        alvo_id=str(alvo_id),
        meta=meta,
        **seguranca.origem(request),
    )


def _exigir(linha: dict | None, minimo: str) -> dict:
    if linha is None:
        raise HTTPException(404, "nao_encontrado")
    if NIVEL[linha["permissao"]] < NIVEL[minimo]:
        raise HTTPException(403, "sem_permissao")
    return linha


_SQL_COLECAO = """SELECT c.id, c.chave_ver, cm.permissao
    FROM colecoes c JOIN colecao_membros cm ON cm.colecao_id = c.id AND cm.usuario_id = %s
    WHERE c.id = %s AND c.org_id = %s"""
# Leitura/criação de item: FOR SHARE na coleção (rotação e exclusão da coleção pegam UPDATE).
SQL_COLECAO_LER = _SQL_COLECAO + " FOR SHARE OF c, cm"
SQL_COLECAO_GRAVAR = _SQL_COLECAO + " FOR UPDATE OF c FOR SHARE OF cm"

_SQL_ITEM = """SELECT i.id, i.colecao_id, i.versao, i.excluido_em, i.segredo_cif,
           c.chave_ver, cm.permissao
    FROM itens i JOIN colecoes c ON c.id = i.colecao_id
    JOIN colecao_membros cm ON cm.colecao_id = c.id AND cm.usuario_id = %s
    WHERE i.id = %s AND c.org_id = %s"""
SQL_ITEM_LER = _SQL_ITEM + " FOR SHARE OF i, c, cm"
SQL_ITEM_GRAVAR = _SQL_ITEM + " FOR UPDATE OF i FOR SHARE OF c, cm"


def _colecao(conn, sessao, colecao_id, minimo, sql=SQL_COLECAO_LER) -> dict:
    return _exigir(db.linha(conn, sql, (sessao.usuario_id, colecao_id, sessao.org_id)), minimo)


def _item(conn, sessao, item_id, minimo, sql=SQL_ITEM_LER) -> dict:
    return _exigir(db.linha(conn, sql, (sessao.usuario_id, item_id, sessao.org_id)), minimo)


def _todos(conn, sql, params) -> list[dict]:
    return conn.cursor(row_factory=dict_row).execute(sql, params).fetchall()


# ---------- sync ----------


@rota.get("/sync")
def sync(request: Request, sessao: seguranca.Ativo):
    """Coleções com envelope do usuário e seus itens fora da lixeira, sem `segredo_cif`.
    Antes, purga (preguiçosa) os itens na lixeira há mais de 30 dias dessas coleções."""
    # ponytail: sem paginação; alvo ≤ alguns milhares de itens por usuário. Paginar por
    # (colecao_id, id) se o sync passar de alguns MB.
    with _transacao(request, sessao) as conn:
        purgados = conn.execute(
            """DELETE FROM itens i USING colecao_membros cm
               WHERE cm.colecao_id = i.colecao_id AND cm.usuario_id = %s
                 AND i.excluido_em < %s
               RETURNING i.id, i.colecao_id""",
            (sessao.usuario_id, relogio.agora() - LIXEIRA),
        ).fetchall()
        for item_id, colecao_id in purgados:
            _evento(
                conn,
                request,
                sessao,
                "item.purgado",
                "item",
                item_id,
                {"colecao_id": str(colecao_id), "modo": "automatico"},
            )
        colecoes = _todos(
            conn,
            """SELECT c.id, c.nome_cif, c.chave_ver, cm.permissao, cm.chave_colecao_cif,
                      c.rotacao_pendente
               FROM colecao_membros cm JOIN colecoes c ON c.id = cm.colecao_id
               WHERE cm.usuario_id = %s AND c.org_id = %s
               ORDER BY c.criada_em, c.id""",
            (sessao.usuario_id, sessao.org_id),
        )
        itens = _todos(
            conn,
            """SELECT i.id, i.colecao_id, i.tipo, i.versao, i.chave_ver, i.meta_cif,
                      i.rotacao_senha_pendente, i.atualizado_em, i.atualizado_por
               FROM itens i JOIN colecao_membros cm ON cm.colecao_id = i.colecao_id
               WHERE cm.usuario_id = %s AND i.excluido_em IS NULL
               ORDER BY i.criado_em, i.id""",
            (sessao.usuario_id,),
        )
    return {"colecoes": colecoes, "itens": itens}


# ---------- coleções ----------


@rota.post("/colecoes", status_code=201)
def criar_colecao(dados: NovaColecao, request: Request, sessao: seguranca.Ativo):
    """chave_ver=1. Envelope `gerenciar` obrigatório para o criador e todo owner ativo (D13);
    todo destinatário tem de ser usuário ativo da org."""
    _tamanho(dados.nome_cif)
    por_usuario = {e.usuario_id: e for e in dados.envelopes}
    if len(por_usuario) != len(dados.envelopes):
        raise HTTPException(422, "envelopes_duplicados")
    with db.transacao(request.app.state.pool) as conn:
        # Mesma trava da gestão de membros (antes de qualquer linha de usuarios, como lá): o
        # conjunto de ativos/owners não muda até o commit.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"membros:{sessao.org_id}",)
        )
        seguranca.exigir_sessao_viva(conn, sessao, ("ativo",))
        ativos = dict(
            conn.execute(
                "SELECT id, papel FROM usuarios WHERE org_id = %s AND estado = 'ativo'",
                (sessao.org_id,),
            ).fetchall()
        )
        if any(uid not in ativos for uid in por_usuario):
            raise HTTPException(422, "destinatario_invalido")
        obrigatorios = {sessao.usuario_id} | {u for u, papel in ativos.items() if papel == "owner"}
        if any(
            u not in por_usuario or por_usuario[u].permissao != "gerenciar" for u in obrigatorios
        ):
            raise HTTPException(422, "envelopes_incompletos")
        if not conn.execute(
            """INSERT INTO colecoes (id, org_id, nome_cif, criada_por, criada_em)
               VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING RETURNING 1""",
            (dados.id, sessao.org_id, dados.nome_cif, sessao.usuario_id, relogio.agora()),
        ).fetchone():
            raise HTTPException(409, "id_em_uso")
        with conn.cursor() as cur:
            cur.executemany(
                """INSERT INTO colecao_membros
                     (colecao_id, usuario_id, permissao, chave_ver, chave_colecao_cif)
                   VALUES (%s, %s, %s, 1, %s)""",
                [
                    (dados.id, e.usuario_id, e.permissao, e.chave_colecao_cif)
                    for e in dados.envelopes
                ],
            )
        _evento(
            conn,
            request,
            sessao,
            "colecao.criada",
            "colecao",
            dados.id,
            {"membros": len(dados.envelopes)},
        )
    return {"id": dados.id, "chave_ver": 1}


@rota.put("/colecoes/{colecao_id}", status_code=204)
def renomear_colecao(colecao_id: UUID, dados: Renomear, request: Request, sessao: seguranca.Ativo):
    _tamanho(dados.nome_cif)
    with _transacao(request, sessao) as conn:
        c = _colecao(conn, sessao, colecao_id, "gerenciar", SQL_COLECAO_GRAVAR)
        if dados.chave_ver != c["chave_ver"]:
            raise HTTPException(409, "chave_ver_desatualizada")
        conn.execute(
            "UPDATE colecoes SET nome_cif = %s WHERE id = %s", (dados.nome_cif, colecao_id)
        )
        _evento(conn, request, sessao, "colecao.renomeada", "colecao", colecao_id)
    return Response(status_code=204)


@rota.delete("/colecoes/{colecao_id}", status_code=204)
def excluir_colecao(colecao_id: UUID, request: Request, sessao: seguranca.Ativo):
    """Só vazia, contando a lixeira (criar item trava a coleção FOR SHARE: sem corrida)."""
    with _transacao(request, sessao) as conn:
        _colecao(conn, sessao, colecao_id, "gerenciar", SQL_COLECAO_GRAVAR)
        if conn.execute(
            "SELECT 1 FROM itens WHERE colecao_id = %s LIMIT 1", (colecao_id,)
        ).fetchone():
            raise HTTPException(409, "colecao_nao_vazia")
        conn.execute("DELETE FROM colecao_membros WHERE colecao_id = %s", (colecao_id,))
        conn.execute("DELETE FROM colecoes WHERE id = %s", (colecao_id,))
        _evento(conn, request, sessao, "colecao.excluida", "colecao", colecao_id)
    return Response(status_code=204)


@rota.get("/colecoes/{colecao_id}/membros")
def membros_colecao(colecao_id: UUID, request: Request, sessao: seguranca.Ativo):
    with _transacao(request, sessao) as conn:
        _colecao(conn, sessao, colecao_id, "gerenciar")
        return _todos(
            conn,
            """SELECT usuario_id, permissao, chave_ver FROM colecao_membros
               WHERE colecao_id = %s ORDER BY usuario_id""",
            (colecao_id,),
        )


@rota.get("/colecoes/{colecao_id}/lixeira")
def lixeira(colecao_id: UUID, request: Request, sessao: seguranca.Ativo):
    """Itens excluídos (só meta: o segredo sai apenas pela rota auditada)."""
    with _transacao(request, sessao) as conn:
        _colecao(conn, sessao, colecao_id, "editar")
        return _todos(
            conn,
            """SELECT id, colecao_id, tipo, versao, chave_ver, meta_cif, excluido_em,
                      atualizado_por
               FROM itens WHERE colecao_id = %s AND excluido_em IS NOT NULL
               ORDER BY excluido_em DESC, id""",
            (colecao_id,),
        )


# ---------- itens ----------


@rota.post("/colecoes/{colecao_id}/itens", status_code=201)
def criar_item(colecao_id: UUID, dados: NovoItem, request: Request, sessao: seguranca.Ativo):
    _tamanho(dados.meta_cif, dados.segredo_cif)
    with _transacao(request, sessao) as conn:
        c = _colecao(conn, sessao, colecao_id, "editar")
        if dados.chave_ver != c["chave_ver"]:
            raise HTTPException(409, "chave_ver_desatualizada")
        agora = relogio.agora()
        if not conn.execute(
            """INSERT INTO itens (id, colecao_id, tipo, chave_ver, meta_cif, segredo_cif,
                                  criado_por, criado_em, atualizado_por, atualizado_em)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (id) DO NOTHING RETURNING 1""",
            (
                dados.id,
                colecao_id,
                dados.tipo,
                dados.chave_ver,
                dados.meta_cif,
                dados.segredo_cif,
                sessao.usuario_id,
                agora,
                sessao.usuario_id,
                agora,
            ),
        ).fetchone():
            raise HTTPException(409, "id_em_uso")
        _evento(
            conn,
            request,
            sessao,
            "item.criado",
            "item",
            dados.id,
            {"colecao_id": str(colecao_id), "tipo": dados.tipo},
        )
    return {"versao": 1}


def _versao_esperada(if_match: str | None) -> int:
    """If-Match: 3, "3" ou W/"3"."""
    v = (if_match or "").strip().removeprefix("W/").strip('"')
    if not v.isascii() or not v.isdigit() or len(v) > 9:
        raise HTTPException(428, "versao_requerida")
    return int(v)


@rota.put("/itens/{item_id}")
def editar_item(
    item_id: UUID,
    dados: Edicao,
    request: Request,
    sessao: seguranca.Ativo,
    if_match: Annotated[str | None, Header()] = None,
):
    """A versão atual vai para item_versoes (máx. 10). O cliente cifrou com AAD versao+1:
    em 409 ele re-sincroniza e recifra."""
    esperada = _versao_esperada(if_match)
    _tamanho(dados.meta_cif, dados.segredo_cif)
    with _transacao(request, sessao) as conn:
        i = _item(conn, sessao, item_id, "editar", SQL_ITEM_GRAVAR)
        if i["excluido_em"] is not None:
            raise HTTPException(409, "item_excluido")
        if i["versao"] != esperada:
            raise HTTPException(409, "conflito_versao")
        if dados.chave_ver != i["chave_ver"]:
            raise HTTPException(409, "chave_ver_desatualizada")
        conn.execute(
            """INSERT INTO item_versoes
                 (item_id, versao, chave_ver, meta_cif, segredo_cif, editado_por, em)
               SELECT id, versao, chave_ver, meta_cif, segredo_cif, atualizado_por, atualizado_em
               FROM itens WHERE id = %s""",
            (item_id,),
        )
        conn.execute(
            "DELETE FROM item_versoes WHERE item_id = %s AND versao <= %s",
            (item_id, esperada - MAX_VERSOES),
        )
        conn.execute(
            """UPDATE itens SET versao = versao + 1, chave_ver = %s, meta_cif = %s,
                      segredo_cif = %s, atualizado_por = %s, atualizado_em = %s,
                      rotacao_senha_pendente = rotacao_senha_pendente AND NOT %s
               WHERE id = %s""",
            (
                dados.chave_ver,
                dados.meta_cif,
                dados.segredo_cif,
                sessao.usuario_id,
                relogio.agora(),
                dados.senha_trocada,
                item_id,
            ),
        )
        _evento(
            conn,
            request,
            sessao,
            "item.editado",
            "item",
            item_id,
            {"colecao_id": str(i["colecao_id"]), "versao": esperada + 1},
        )
    return {"versao": esperada + 1}


@rota.get("/itens/{item_id}/segredo")
def revelar(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    """RF-A02/A03: o evento item.revelado é gravado na mesma transação; se ele falhar, a
    transação cai e o segredo não sai (500 sem corpo útil)."""
    with _transacao(request, sessao) as conn:
        i = _item(conn, sessao, item_id, "ver")
        _evento(
            conn,
            request,
            sessao,
            "item.revelado",
            "item",
            item_id,
            {"colecao_id": str(i["colecao_id"]), "versao": i["versao"]},
        )
    return {"segredo_cif": i["segredo_cif"], "versao": i["versao"], "chave_ver": i["chave_ver"]}


@rota.post("/itens/{item_id}/copiado", status_code=204)
def copiado(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    """Melhor esforço: o cliente avisa que copiou (não há como o servidor saber)."""
    with _transacao(request, sessao) as conn:
        i = _item(conn, sessao, item_id, "ver")
        _evento(
            conn,
            request,
            sessao,
            "item.copiado",
            "item",
            item_id,
            {"colecao_id": str(i["colecao_id"])},
        )
    return Response(status_code=204)


@rota.get("/itens/{item_id}/versoes")
def versoes(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    with _transacao(request, sessao) as conn:
        _item(conn, sessao, item_id, "ver")
        return _todos(
            conn,
            """SELECT versao, chave_ver, editado_por, em FROM item_versoes
               WHERE item_id = %s ORDER BY versao DESC""",
            (item_id,),
        )


@rota.get("/itens/{item_id}/versoes/{versao}")
def revelar_versao(item_id: UUID, versao: int, request: Request, sessao: seguranca.Ativo):
    with _transacao(request, sessao) as conn:
        i = _item(conn, sessao, item_id, "ver")
        v = db.linha(
            conn,
            """SELECT meta_cif, segredo_cif, chave_ver FROM item_versoes
               WHERE item_id = %s AND versao = %s""",
            (item_id, versao),
        )
        if v is None:
            raise HTTPException(404, "nao_encontrado")
        _evento(
            conn,
            request,
            sessao,
            "item.versao_revelada",
            "item",
            item_id,
            {"colecao_id": str(i["colecao_id"]), "versao": versao},
        )
    return v


def _lixeira(request, sessao, item_id, minimo, na_lixeira: bool, efeito, params, tipo, meta=None):
    """Excluir / restaurar / apagar definitivo: trava o item e confere de que lado da lixeira
    ele está (409 item_excluido / fora_da_lixeira)."""
    with _transacao(request, sessao) as conn:
        i = _item(conn, sessao, item_id, minimo, SQL_ITEM_GRAVAR)
        if (i["excluido_em"] is not None) != na_lixeira:
            raise HTTPException(409, "fora_da_lixeira" if na_lixeira else "item_excluido")
        conn.execute(efeito, params)
        _evento(
            conn,
            request,
            sessao,
            tipo,
            "item",
            item_id,
            {"colecao_id": str(i["colecao_id"]), **(meta or {})},
        )
    return Response(status_code=204)


@rota.delete("/itens/{item_id}", status_code=204)
def excluir_item(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    return _lixeira(
        request,
        sessao,
        item_id,
        "editar",
        False,
        "UPDATE itens SET excluido_em = %s WHERE id = %s",
        (relogio.agora(), item_id),
        "item.excluido",
    )


@rota.post("/itens/{item_id}/restaurar", status_code=204)
def restaurar(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    return _lixeira(
        request,
        sessao,
        item_id,
        "editar",
        True,
        "UPDATE itens SET excluido_em = NULL WHERE id = %s",
        (item_id,),
        "item.restaurado",
    )


@rota.delete("/itens/{item_id}/definitivo", status_code=204)
def apagar_definitivo(item_id: UUID, request: Request, sessao: seguranca.Ativo):
    """Apaga item e versões (cascade). Não há tipo próprio em §5.6: item.purgado modo=manual."""
    return _lixeira(
        request,
        sessao,
        item_id,
        "gerenciar",
        True,
        "DELETE FROM itens WHERE id = %s",
        (item_id,),
        "item.purgado",
        {"modo": "manual"},
    )
