"""Própria conta (§5.2) da Fase 4: MFA, sessões ativas e eventos de autenticação."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import Field

from app import auditoria, cifra_servidor, db, limites, mfa, relogio, seguranca, totp
from app.rotas.auth import B64U32, SQL_USUARIO, Entrada

rota = APIRouter()


class Codigo(Entrada):
    codigo: str = Field(max_length=64)


class Desativar(Entrada):
    auth_hash: B64U32
    codigo: str = Field(max_length=64)


def _contexto(request: Request, sessao: seguranca.Sessao):
    pool, origem = request.app.state.pool, seguranca.origem(request)
    evento = {
        "org_id": sessao.org_id,
        "ator_id": sessao.usuario_id,
        "alvo_tipo": "usuario",
        "alvo_id": str(sessao.usuario_id),
        **origem,
    }

    def tentar():
        # Código/senha errados aqui contam contra a conta, como no login.
        limites.tentar_conta(
            pool,
            sessao.email,
            lambda conn: auditoria.registrar(conn, tipo="auth.bloqueio", **evento),
        )

    return pool, origem, request.app.state.config.cofre_segredo, evento, tentar


def _usuario(pool, sessao) -> dict:
    with db.transacao(pool) as conn:
        return db.linha(conn, SQL_USUARIO + " WHERE u.id = %s", (sessao.usuario_id,))


@rota.post("/eu/mfa/iniciar")
def mfa_iniciar(request: Request, sessao: seguranca.SessaoAtual):
    """Novo segredo TOTP (substitui um não confirmado). Só esta resposta o traz em claro."""
    pool, _, segredo, _, _ = _contexto(request, sessao)
    chave = totp.novo_segredo()
    cifrado = cifra_servidor.cifrar(segredo, sessao.usuario_id, chave)
    with db.transacao(pool) as conn:
        alterou = conn.execute(
            """UPDATE usuarios SET totp_segredo_cif = %s, atualizado_em = now()
               WHERE id = %s AND totp_ultimo_passo IS NULL RETURNING 1""",
            (cifrado, sessao.usuario_id),
        ).fetchone()
    if not alterou:
        raise HTTPException(409, "mfa_ja_ativo")
    return {"segredo_base32": totp.base32(chave), "otpauth_uri": totp.uri(chave, sessao.email)}


@rota.post("/eu/mfa/confirmar")
def mfa_confirmar(dados: Codigo, request: Request, sessao: seguranca.SessaoAtual):
    """Primeiro código válido ativa o MFA e devolve os 10 códigos de recuperação (uma vez)."""
    pool, _, segredo, evento, tentar = _contexto(request, sessao)
    u = _usuario(pool, sessao)
    if u["totp_ultimo_passo"] is not None:
        raise HTTPException(409, "mfa_ja_ativo")
    if u["totp_segredo_cif"] is None:
        raise HTTPException(409, "mfa_nao_iniciado")
    tentar()
    chave = cifra_servidor.decifrar(segredo, sessao.usuario_id, u["totp_segredo_cif"])
    passo = totp.verificar(chave, dados.codigo, relogio.agora().timestamp(), None)
    codigos = None
    with db.transacao(pool) as conn:
        # Atômico: o segredo confirmado é o que foi lido (um iniciar paralelo não passa).
        if (
            passo is not None
            and conn.execute(
                """UPDATE usuarios SET totp_ultimo_passo = %s, atualizado_em = now()
               WHERE id = %s AND totp_ultimo_passo IS NULL AND totp_segredo_cif = %s
               RETURNING 1""",
                (passo, sessao.usuario_id, u["totp_segredo_cif"]),
            ).fetchone()
        ):
            codigos = mfa.gravar_codigos(conn, segredo, sessao.usuario_id)
            auditoria.registrar(conn, tipo="mfa.ativado", **evento)
        else:
            auditoria.registrar(
                conn, tipo="auth.mfa", resultado="falha", meta={"metodo": "totp"}, **evento
            )
    if codigos is None:
        raise HTTPException(401, "mfa_invalido")
    limites.limpar_conta(pool, sessao.email)
    return {"codigos_recuperacao": codigos}


@rota.delete("/eu/mfa", status_code=204)
def mfa_desativar(dados: Desativar, request: Request, sessao: seguranca.SessaoAtual):
    pool, origem, segredo, evento, tentar = _contexto(request, sessao)
    u = _usuario(pool, sessao)
    if u["mfa_obrigatorio"]:
        raise HTTPException(403, "politica_mfa")
    if u["totp_ultimo_passo"] is None:
        raise HTTPException(409, "mfa_inativo")
    tentar()
    if not seguranca.verificar_auth(u["auth_hash"], segredo, seguranca.de_b64u(dados.auth_hash)):
        with db.transacao(pool) as conn:
            auditoria.registrar(conn, tipo="mfa.desativado", resultado="falha", **evento)
        raise HTTPException(401, "credenciais_invalidas")
    # 6 dígitos = TOTP; o resto é tratado como código de recuperação.
    eh_totp = dados.codigo.isdigit()
    mfa.exigir_segundo_fator(
        pool,
        segredo,
        u,
        dados.codigo if eh_totp else None,
        None if eh_totp else dados.codigo,
        origem,
    )
    limites.limpar_conta(pool, sessao.email)
    with db.transacao(pool) as conn:
        conn.execute(
            """UPDATE usuarios SET totp_segredo_cif = NULL, totp_ultimo_passo = NULL,
                      atualizado_em = now() WHERE id = %s""",
            (sessao.usuario_id,),
        )
        conn.execute("DELETE FROM codigos_mfa WHERE usuario_id = %s", (sessao.usuario_id,))
        auditoria.registrar(conn, tipo="mfa.desativado", **evento)
    return Response(status_code=204)


@rota.get("/eu/sessoes")
def sessoes(request: Request, sessao: seguranca.SessaoAtual):
    agora = relogio.agora()
    with db.transacao(request.app.state.pool) as conn:
        linhas = conn.execute(
            """SELECT s.id, s.criada_em, s.ultimo_uso, host(s.ip), s.user_agent
               FROM sessoes s
               JOIN usuarios u ON u.id = s.usuario_id
               JOIN politicas p ON p.org_id = u.org_id
               WHERE s.usuario_id = %(u)s AND s.revogada_em IS NULL AND s.expira_em > %(agora)s
                 AND s.ultimo_uso > %(agora)s - make_interval(mins => p.inatividade_min)
               ORDER BY s.ultimo_uso DESC""",
            {"u": sessao.usuario_id, "agora": agora},
        ).fetchall()
    return [
        {
            "id": i,
            "criada_em": c,
            "ultimo_uso": uso,
            "ip": ip,
            "user_agent": ua,
            "atual": i == sessao.id,
        }
        for i, c, uso, ip, ua in linhas
    ]


@rota.delete("/eu/sessoes/{sessao_id}", status_code=204)
def encerrar_sessao(sessao_id: UUID, request: Request, sessao: seguranca.SessaoAtual):
    with db.transacao(request.app.state.pool) as conn:
        revogada = conn.execute(
            """UPDATE sessoes SET revogada_em = %s
               WHERE id = %s AND usuario_id = %s AND revogada_em IS NULL RETURNING id""",
            (relogio.agora(), sessao_id, sessao.usuario_id),
        ).fetchone()
        if revogada:
            auditoria.registrar(
                conn,
                org_id=sessao.org_id,
                ator_id=sessao.usuario_id,
                tipo="auth.sessao_revogada",
                alvo_tipo="sessao",
                alvo_id=str(sessao_id),
                **seguranca.origem(request),
            )
    if not revogada:
        raise HTTPException(404, "nao_encontrado")  # de outro usuário = inexistente
    return Response(status_code=204)


@rota.get("/eu/eventos")
def eventos(
    request: Request,
    sessao: seguranca.SessaoAtual,
    antes_de_id: Annotated[int | None, Query(ge=1)] = None,
    limite: Annotated[int, Query(ge=1, le=200)] = 50,
):
    """Próprios eventos auth.*, do mais novo ao mais antigo; cursor = id do último recebido."""
    with db.transacao(request.app.state.pool) as conn:
        linhas = conn.execute(
            """SELECT id, em, tipo, resultado, host(ip), user_agent FROM eventos
               WHERE ator_id = %s AND tipo LIKE 'auth.%%'
                 AND (%s::bigint IS NULL OR id < %s)
               ORDER BY id DESC LIMIT %s""",
            (sessao.usuario_id, antes_de_id, antes_de_id, limite),
        ).fetchall()
    campos = ("id", "em", "tipo", "resultado", "ip", "user_agent")
    return [dict(zip(campos, linha, strict=True)) for linha in linhas]
