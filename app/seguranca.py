"""Hash do authHash (D5/D19), tokens opacos e a dependência de sessão (D15)."""

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request

from app import db, relogio

HASHER = PasswordHasher()  # padrão do argon2-cffi: Argon2id t=3, m=65536, p=4
COOKIE = "sessao"
OCIOSA = timedelta(minutes=15)  # Fase 4 troca pela política da org (inatividade_min)
ABSOLUTA = timedelta(hours=12)
POLITICA = {"inatividade_min": 15}


def b64u(dados: bytes) -> str:
    return base64.urlsafe_b64encode(dados).rstrip(b"=").decode()


def de_b64u(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def subchave(segredo: bytes, rotulo: str) -> bytes:
    """D19: uma subchave por finalidade a partir de COFRE_SEGREDO."""
    return hmac.new(segredo, rotulo.encode(), hashlib.sha256).digest()


def hmac_pepper(segredo: bytes, dados: bytes) -> bytes:
    return hmac.new(subchave(segredo, "pepper"), dados, hashlib.sha256).digest()


# Cada hash/verificação Argon2 aloca 64 MiB (m=65536). Sem teto, N requisições paralelas
# somam N × 64 MiB e o container morre por OOM. Quem passa do teto espera a vez sem alocar;
# se a espera passar de ARGON2_ESPERA_S, 503. Memória da api: ver mem_limit no compose.
ARGON2_CONCORRENCIA = int(os.environ.get("COFRE_ARGON2_CONCORRENCIA", "2"))
ARGON2_ESPERA_S = 10.0
_argon2 = threading.BoundedSemaphore(ARGON2_CONCORRENCIA)


@contextmanager
def _vez_do_argon2():
    if not _argon2.acquire(timeout=ARGON2_ESPERA_S):
        raise HTTPException(503, "ocupado", headers={"Retry-After": "5"})
    try:
        yield
    finally:
        _argon2.release()


def hash_auth(segredo: bytes, auth_hash: bytes) -> str:
    with _vez_do_argon2():
        return HASHER.hash(hmac_pepper(segredo, auth_hash))


# Verificação falsa para e-mail inexistente: mesmo custo Argon2 que a verdadeira.
HASH_FALSO = HASHER.hash(secrets.token_bytes(32))


def verificar_auth(guardado: str, segredo: bytes, auth_hash: bytes) -> bool:
    with _vez_do_argon2():
        try:
            return HASHER.verify(guardado, hmac_pepper(segredo, auth_hash))
        except VerificationError, InvalidHashError:
            return False


def novo_token() -> tuple[str, bytes]:
    """Token opaco de 256 bits: o texto vai ao cliente, só o SHA-256 vai ao banco."""
    texto = b64u(secrets.token_bytes(32))
    return texto, hash_token(texto)


def hash_token(texto: str) -> bytes:
    return hashlib.sha256(texto.encode()).digest()


def fingerprint(chave_publica: bytes) -> str:
    h = hashlib.sha256(chave_publica).hexdigest()[:32].upper()
    return " ".join(h[i : i + 4] for i in range(0, 32, 4))


def origem(request: Request) -> dict:
    """ip/user_agent para eventos e sessões (ip já vem do X-Forwarded-For via uvicorn)."""
    host = request.client.host if request.client else None
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        ip = None
    return {"ip": ip, "user_agent": (request.headers.get("user-agent") or "")[:300] or None}


@dataclass(frozen=True)
class Sessao:
    id: UUID
    usuario_id: UUID
    org_id: UUID
    papel: str
    estado: str


def sessao_atual(request: Request) -> Sessao:
    """Cookie válido (não revogado, dentro da ociosa e da absoluta) e X-Cofre em não-GET."""
    if request.method not in ("GET", "HEAD") and request.headers.get("x-cofre") != "1":
        raise HTTPException(403, "csrf")
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "nao_autenticado")
    agora = relogio.agora()
    with db.transacao(request.app.state.pool) as conn:
        linha = conn.execute(
            """UPDATE sessoes s SET ultimo_uso = %(agora)s
               FROM usuarios u
               WHERE s.token_hash = %(hash)s AND u.id = s.usuario_id
                 AND s.revogada_em IS NULL
                 AND s.expira_em > %(agora)s
                 AND s.ultimo_uso > %(agora)s - %(ociosa)s
                 AND u.estado IN ('aceito', 'ativo')
               RETURNING s.id, u.id, u.org_id, u.papel, u.estado""",
            {"agora": agora, "hash": hash_token(token), "ociosa": OCIOSA},
        ).fetchone()
    if not linha:
        raise HTTPException(401, "nao_autenticado")
    return Sessao(*linha)


SessaoAtual = Annotated[Sessao, Depends(sessao_atual)]


def exigir_papel(*papeis: str):
    def dependencia(sessao: SessaoAtual) -> Sessao:
        if sessao.estado != "ativo" or sessao.papel not in papeis:
            raise HTTPException(403, "sem_permissao")
        return sessao

    return dependencia


Gestor = Annotated[Sessao, Depends(exigir_papel("owner", "admin"))]
