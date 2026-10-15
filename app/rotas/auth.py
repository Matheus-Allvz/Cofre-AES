"""Rotas públicas de conta (§5.1) e da própria conta (§5.2): convite, login, senha, recuperação."""

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request, Response
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app import auditoria, db, limites, mfa, relogio, seguranca
from app.rotas.convites import Email

KDF_PADRAO = {"tipo": "argon2id", "m": 65536, "t": 3, "p": 1}


def _kdf(v: dict) -> dict:
    """Ordem fixa: o jsonb do Postgres reordena as chaves e a resposta do prelogin de e-mail
    existente não pode diferir, nem em bytes, da do inexistente."""
    return {k: v[k] for k in ("tipo", "m", "t", "p")}


B64U32 = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
B64U16 = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{22}$")]
# Envelope v1 (§3.1); 64 KiB por campo.
V1 = Annotated[
    str, StringConstraints(pattern=r"^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$", max_length=65536)
]
Token = Annotated[str, StringConstraints(min_length=1, max_length=128)]

rota = APIRouter()


class Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _kdf_padrao(v: dict) -> dict:
    # Exatamente o padrão, com inteiros de verdade (65536.0/true não passam).
    if v != KDF_PADRAO or any(type(v[k]) is not int for k in ("m", "t", "p")):
        raise ValueError("kdf diferente do padrão")
    return v


class Prelogin(Entrada):
    email: Email


class Consulta(Entrada):
    token: Token


class Aceite(Entrada):
    token: Token
    nome: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
    kdf: dict
    sal: B64U16
    auth_hash: B64U32
    chave_usuario_cif: V1
    chave_usuario_recup_cif: V1
    recup_auth: B64U32
    chave_publica: B64U32
    chave_privada_cif: V1
    _kdf = field_validator("kdf")(_kdf_padrao)


class Login(Entrada):
    email: Email
    auth_hash: B64U32
    totp: str | None = Field(default=None, max_length=16)
    codigo_recuperacao: str | None = Field(default=None, max_length=64)


class TrocaSenha(Entrada):
    auth_hash_atual: B64U32
    totp: str | None = Field(default=None, max_length=16)
    kdf: dict
    sal: B64U16
    auth_hash: B64U32
    chave_usuario_cif: V1
    _kdf = field_validator("kdf")(_kdf_padrao)


class RecuperarIniciar(Entrada):
    email: Email
    recup_auth: B64U32
    totp: str | None = Field(default=None, max_length=16)
    codigo_recuperacao: str | None = Field(default=None, max_length=64)


class RecuperarConcluir(Entrada):
    token: Token
    kdf: dict
    sal: B64U16
    auth_hash: B64U32
    chave_usuario_cif: V1
    chave_usuario_recup_cif: V1
    recup_auth: B64U32
    _kdf = field_validator("kdf")(_kdf_padrao)


# Usuário + política da org: tudo que login, /eu, troca de senha e recuperação leem.
SQL_USUARIO = """SELECT u.id, u.org_id, u.email, u.nome, u.papel, u.estado, u.kdf, u.kdf_sal,
                      u.auth_hash, u.chave_usuario_cif, u.chave_privada_cif, u.chave_publica,
                      u.chave_usuario_recup_cif, u.recup_auth_hmac,
                      u.totp_segredo_cif, u.totp_ultimo_passo,
                      p.mfa_obrigatorio, p.inatividade_min
               FROM usuarios u JOIN politicas p ON p.org_id = u.org_id"""


def _segredo(request: Request) -> bytes:
    return request.app.state.config.cofre_segredo


def _perfil(u: dict) -> dict:
    return {
        "usuario": {k: u[k] for k in ("id", "org_id", "email", "nome", "papel", "estado")},
        "kdf": _kdf(u["kdf"]),
        "sal": seguranca.b64u(u["kdf_sal"]),
        "chave_usuario_cif": u["chave_usuario_cif"],
        "chave_privada_cif": u["chave_privada_cif"],
        "chave_publica": seguranca.b64u(u["chave_publica"]),
        "politica": {k: u[k] for k in ("mfa_obrigatorio", "inatividade_min")},
        "mfa_ativo": u["totp_ultimo_passo"] is not None,
        "mfa_pendente": u["mfa_obrigatorio"] and u["totp_ultimo_passo"] is None,
    }


@rota.post("/prelogin")
def prelogin(dados: Prelogin, request: Request):
    limites.contar_ip(request.app.state.pool, seguranca.origem(request)["ip"], "prelogin")
    with db.transacao(request.app.state.pool) as conn:
        u = db.linha(
            conn,
            "SELECT kdf, kdf_sal FROM usuarios WHERE email = %s AND auth_hash IS NOT NULL",
            (dados.email,),
        )
    if u:
        return {"kdf": _kdf(u["kdf"]), "sal": seguranca.b64u(u["kdf_sal"])}
    # E-mail inexistente: sal falso determinístico, mesmo formato (sem enumeração).
    chave = seguranca.subchave(_segredo(request), "prelogin")
    sal = hmac.new(chave, dados.email.encode(), hashlib.sha256).digest()[:16]
    return {"kdf": _kdf(KDF_PADRAO), "sal": seguranca.b64u(sal)}


def _convite(conn, token: str) -> dict:
    c = db.linha(
        conn,
        """SELECT c.id, c.org_id, c.usuario_id, c.papel, c.criado_por, c.expira_em, c.usado_em,
                  c.revogado_em, o.nome AS org_nome, u.email
           FROM convites c
           JOIN organizacoes o ON o.id = c.org_id
           JOIN usuarios u ON u.id = c.usuario_id
           WHERE c.token_hash = %s
           FOR UPDATE OF c""",
        (seguranca.hash_token(token),),
    )
    if c is None:
        raise HTTPException(404, "convite_invalido")
    if c["usado_em"] or c["revogado_em"] or c["expira_em"] <= relogio.agora():
        raise HTTPException(410, "convite_expirado")
    return c


@rota.post("/convites/consultar")
def consultar(dados: Consulta, request: Request):
    limites.contar_ip(request.app.state.pool, seguranca.origem(request)["ip"], "convites")
    with db.transacao(request.app.state.pool) as conn:
        c = _convite(conn, dados.token)
    return {k: c[k] for k in ("usuario_id", "org_id", "org_nome", "email", "papel")}


@rota.post("/convites/aceitar", status_code=201)
def aceitar(dados: Aceite, request: Request):
    origem = seguranca.origem(request)
    limites.contar_ip(request.app.state.pool, origem["ip"], "convites")
    segredo = _segredo(request)
    chave_publica = seguranca.de_b64u(dados.chave_publica)
    # Argon2 antes de abrir a transação: a espera pela vez não segura conexão do pool.
    auth = seguranca.hash_auth(segredo, seguranca.de_b64u(dados.auth_hash))
    with db.transacao(request.app.state.pool) as conn:
        c = _convite(conn, dados.token)
        # Bootstrap (convite da CLI, sem criado_por): o owner inicial confere a própria chave.
        bootstrap = c["criado_por"] is None and c["papel"] == "owner"
        estado = "ativo" if bootstrap else "aceito"
        conn.execute(
            """UPDATE usuarios SET nome = %(nome)s, estado = %(estado)s, kdf = %(kdf)s,
                      kdf_sal = %(sal)s, auth_hash = %(auth)s,
                      chave_usuario_cif = %(cu)s, chave_usuario_recup_cif = %(cur)s,
                      recup_auth_hmac = %(recup)s, chave_publica = %(pub)s,
                      chave_privada_cif = %(cp)s, fingerprint_confirmado = %(fp)s,
                      confirmado_por = %(conf)s, atualizado_em = now()
               WHERE id = %(id)s AND estado = 'convidado'""",
            {
                "id": c["usuario_id"],
                "nome": dados.nome,
                "estado": estado,
                "kdf": Jsonb(dados.kdf),
                "sal": seguranca.de_b64u(dados.sal),
                "auth": auth,
                "cu": dados.chave_usuario_cif,
                "cur": dados.chave_usuario_recup_cif,
                "recup": seguranca.hmac_pepper(segredo, seguranca.de_b64u(dados.recup_auth)),
                "pub": chave_publica,
                "cp": dados.chave_privada_cif,
                "fp": seguranca.fingerprint(chave_publica) if bootstrap else None,
                "conf": c["usuario_id"] if bootstrap else None,
            },
        )
        conn.execute("UPDATE convites SET usado_em = %s WHERE id = %s", (relogio.agora(), c["id"]))
        auditoria.registrar(
            conn,
            org_id=c["org_id"],
            ator_id=c["usuario_id"],
            tipo="convite.aceito",
            alvo_tipo="convite",
            alvo_id=str(c["id"]),
            **origem,
        )
    return {"usuario_id": c["usuario_id"], "estado": estado}


def _email_curto(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()[:8]


@rota.post("/login")
def login(dados: Login, request: Request, response: Response):
    pool, origem, segredo = request.app.state.pool, seguranca.origem(request), _segredo(request)
    limites.contar_ip(pool, origem["ip"], "login")
    with db.transacao(pool) as conn:
        u = db.linha(
            conn,
            SQL_USUARIO
            + " WHERE u.email = %s AND u.auth_hash IS NOT NULL AND u.estado <> 'removido'",
            (dados.email,),
        )
    alvo = {"org_id": u and u["org_id"], "ator_id": u and u["id"], **origem}
    meta = {"email_sha256": _email_curto(dados.email)}
    # Conta a tentativa antes do Argon2, numa instrução atômica (paralelas não furam o limite).
    limites.tentar_conta(
        pool,
        dados.email,
        lambda conn: auditoria.registrar(conn, tipo="auth.bloqueio", meta=meta, **alvo),
    )
    # Sempre exatamente uma verificação Argon2, exista o e-mail ou não (RNF-01).
    guardado = u["auth_hash"] if u else seguranca.HASH_FALSO
    valido = seguranca.verificar_auth(guardado, segredo, seguranca.de_b64u(dados.auth_hash))

    if not (valido and u):
        with db.transacao(pool) as conn:
            auditoria.registrar(conn, tipo="auth.login", resultado="falha", meta=meta, **alvo)
        raise HTTPException(401, "credenciais_invalidas")
    if u["estado"] == "suspenso":
        raise HTTPException(403, "conta_suspensa")
    # Fator ausente/errado não zera a contagem: a tentativa já contou contra a conta.
    mfa.exigir_segundo_fator(pool, segredo, u, dados.totp, dados.codigo_recuperacao, origem)

    limites.limpar_conta(pool, dados.email)
    token, token_hash = seguranca.novo_token()
    agora = relogio.agora()
    with db.transacao(pool) as conn:
        (sessao_id,) = conn.execute(
            """INSERT INTO sessoes (usuario_id, token_hash, criada_em, ultimo_uso, expira_em,
                                    ip, user_agent)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (
                u["id"],
                token_hash,
                agora,
                agora,
                agora + seguranca.ABSOLUTA,
                origem["ip"],
                origem["user_agent"],
            ),
        ).fetchone()
        auditoria.registrar(
            conn,
            org_id=u["org_id"],
            ator_id=u["id"],
            tipo="auth.login",
            alvo_tipo="sessao",
            alvo_id=str(sessao_id),
            **origem,
        )
    response.set_cookie(
        seguranca.COOKIE,
        token,
        httponly=True,
        secure=request.app.state.config.cookie_secure,
        samesite="strict",
        path="/api",
    )
    return _perfil(u)


@rota.post("/logout", status_code=204)
def logout(request: Request, sessao: seguranca.SessaoAtual):
    with db.transacao(request.app.state.pool) as conn:
        conn.execute(
            "UPDATE sessoes SET revogada_em = %s WHERE id = %s", (relogio.agora(), sessao.id)
        )
        auditoria.registrar(
            conn,
            org_id=sessao.org_id,
            ator_id=sessao.usuario_id,
            tipo="auth.logout",
            alvo_tipo="sessao",
            alvo_id=str(sessao.id),
            **seguranca.origem(request),
        )
    resposta = Response(status_code=204)
    resposta.delete_cookie(
        seguranca.COOKIE,
        path="/api",
        secure=request.app.state.config.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return resposta


@rota.get("/eu")
def eu(request: Request, sessao: seguranca.SessaoAtual):
    with db.transacao(request.app.state.pool) as conn:
        u = db.linha(conn, SQL_USUARIO + " WHERE u.id = %s", (sessao.usuario_id,))
    return _perfil(u)


@rota.post("/eu/senha", status_code=204)
def trocar_senha(
    dados: TrocaSenha,
    request: Request,
    sessao: seguranca.SessaoAtual,
):
    pool, origem, segredo = request.app.state.pool, seguranca.origem(request), _segredo(request)
    with db.transacao(pool) as conn:
        u = db.linha(conn, SQL_USUARIO + " WHERE u.id = %s", (sessao.usuario_id,))
    evento = {
        "org_id": sessao.org_id,
        "ator_id": sessao.usuario_id,
        "tipo": "auth.senha_trocada",
        "alvo_tipo": "usuario",
        "alvo_id": str(sessao.usuario_id),
        **origem,
    }
    # Senha atual errada conta contra a conta, como no login: sessão roubada não vira oráculo.
    limites.tentar_conta(
        pool,
        sessao.email,
        lambda conn: auditoria.registrar(
            conn, tipo="auth.bloqueio", org_id=sessao.org_id, ator_id=sessao.usuario_id, **origem
        ),
    )
    atual = seguranca.de_b64u(dados.auth_hash_atual)
    if not seguranca.verificar_auth(u["auth_hash"], segredo, atual):
        with db.transacao(pool) as conn:
            auditoria.registrar(conn, **(evento | {"resultado": "falha"}))
        raise HTTPException(401, "credenciais_invalidas")
    mfa.exigir_segundo_fator(pool, segredo, u, dados.totp, None, origem)
    limites.limpar_conta(pool, sessao.email)
    novo_hash = seguranca.hash_auth(segredo, seguranca.de_b64u(dados.auth_hash))
    with db.transacao(pool) as conn:
        conn.execute(
            """UPDATE usuarios SET kdf = %s, kdf_sal = %s, auth_hash = %s,
                      chave_usuario_cif = %s, atualizado_em = now()
               WHERE id = %s""",
            (
                Jsonb(dados.kdf),
                seguranca.de_b64u(dados.sal),
                novo_hash,
                dados.chave_usuario_cif,
                sessao.usuario_id,
            ),
        )
        # A sessão em uso continua; todas as outras caem (RF-I10).
        conn.execute(
            """UPDATE sessoes SET revogada_em = %s
               WHERE usuario_id = %s AND id <> %s AND revogada_em IS NULL""",
            (relogio.agora(), sessao.usuario_id, sessao.id),
        )
        seguranca.invalidar_recuperacoes(conn, sessao.usuario_id)
        auditoria.registrar(conn, **evento)
    return Response(status_code=204)


# ---------- Recuperação por kit (RF-U06) ----------

RECUPERACAO_VALIDADE = timedelta(minutes=5)
_RECUP_FALSO = secrets.token_bytes(32)  # comparação de mesmo custo para e-mail inexistente


@rota.post("/recuperar/iniciar")
def recuperar_iniciar(dados: RecuperarIniciar, request: Request):
    """recup_auth + segundo fator válidos → token de 5 min e a userKey envelopada pelo kit."""
    pool, origem, segredo = request.app.state.pool, seguranca.origem(request), _segredo(request)
    limites.contar_ip(pool, origem["ip"], "recuperar")
    with db.transacao(pool) as conn:
        u = db.linha(
            conn,
            SQL_USUARIO + " WHERE u.email = %s AND u.estado IN ('aceito', 'ativo')"
            " AND u.recup_auth_hmac IS NOT NULL",
            (dados.email,),
        )
    alvo = {"org_id": u and u["org_id"], "ator_id": u and u["id"], **origem}
    meta = {"email_sha256": _email_curto(dados.email)}
    # Mesma conta de tentativas do login: kit e senha dividem o limite de 10 em 15 min.
    limites.tentar_conta(
        pool,
        dados.email,
        lambda conn: auditoria.registrar(conn, tipo="auth.bloqueio", meta=meta, **alvo),
    )
    recebido = seguranca.hmac_pepper(segredo, seguranca.de_b64u(dados.recup_auth))
    valido = hmac.compare_digest(recebido, bytes(u["recup_auth_hmac"]) if u else _RECUP_FALSO)
    if not (valido and u):
        with db.transacao(pool) as conn:
            auditoria.registrar(conn, tipo="auth.recuperacao", resultado="falha", meta=meta, **alvo)
        raise HTTPException(401, "credenciais_invalidas")
    mfa.exigir_segundo_fator(pool, segredo, u, dados.totp, dados.codigo_recuperacao, origem)
    limites.limpar_conta(pool, dados.email)

    token, token_hash = seguranca.novo_token()
    with db.transacao(pool) as conn:
        conn.execute(
            "INSERT INTO recuperacoes (token_hash, usuario_id, expira_em) VALUES (%s, %s, %s)",
            (token_hash, u["id"], relogio.agora() + RECUPERACAO_VALIDADE),
        )
        auditoria.registrar(
            conn,
            tipo="auth.recuperacao",
            alvo_tipo="usuario",
            alvo_id=str(u["id"]),
            meta={"etapa": "iniciada"},
            **alvo,
        )
    return {
        "token": token,
        "usuario_id": u["id"],
        "chave_usuario_recup_cif": u["chave_usuario_recup_cif"],
    }


def _recuperacao_valida(conn, token_hash: bytes, travar: bool = False):
    sql = (
        "SELECT usuario_id FROM recuperacoes"
        " WHERE token_hash = %s AND usado_em IS NULL AND expira_em > %s"
    )
    linha = conn.execute(sql + (" FOR UPDATE" if travar else ""), (token_hash, relogio.agora()))
    linha = linha.fetchone()
    if not linha:
        raise HTTPException(401, "token_invalido")
    return linha[0]


@rota.post("/recuperar/concluir", status_code=204)
def recuperar_concluir(dados: RecuperarConcluir, request: Request):
    """Nova senha (userKey re-envelopada) e novo kit; revoga todas as sessões."""
    pool, origem, segredo = request.app.state.pool, seguranca.origem(request), _segredo(request)
    limites.contar_ip(pool, origem["ip"], "recuperar")
    token_hash = seguranca.hash_token(dados.token)
    with db.transacao(pool) as conn:  # token inválido não gasta Argon2
        _recuperacao_valida(conn, token_hash)
    # Argon2 fora da transação: a espera pela vez não segura conexão do pool.
    novo_hash = seguranca.hash_auth(segredo, seguranca.de_b64u(dados.auth_hash))
    with db.transacao(pool) as conn:
        usuario_id = _recuperacao_valida(conn, token_hash, travar=True)
        agora = relogio.agora()
        # Este token e qualquer outro pendente do usuário deixam de valer.
        seguranca.invalidar_recuperacoes(conn, usuario_id)
        alterado = conn.execute(
            """UPDATE usuarios SET kdf = %s, kdf_sal = %s, auth_hash = %s,
                      chave_usuario_cif = %s, chave_usuario_recup_cif = %s,
                      recup_auth_hmac = %s, atualizado_em = now()
               WHERE id = %s AND estado IN ('aceito', 'ativo') RETURNING org_id""",
            (
                Jsonb(dados.kdf),
                seguranca.de_b64u(dados.sal),
                novo_hash,
                dados.chave_usuario_cif,
                dados.chave_usuario_recup_cif,
                seguranca.hmac_pepper(segredo, seguranca.de_b64u(dados.recup_auth)),
                usuario_id,
            ),
        ).fetchone()
        if not alterado:  # suspenso/removido depois do iniciar: rollback, nada muda
            raise HTTPException(401, "token_invalido")
        (org_id,) = alterado
        conn.execute(
            "UPDATE sessoes SET revogada_em = %s WHERE usuario_id = %s AND revogada_em IS NULL",
            (agora, usuario_id),
        )
        auditoria.registrar(
            conn,
            org_id=org_id,
            ator_id=usuario_id,
            tipo="auth.recuperacao",
            alvo_tipo="usuario",
            alvo_id=str(usuario_id),
            meta={"etapa": "concluida"},
            **origem,
        )
    return Response(status_code=204)
