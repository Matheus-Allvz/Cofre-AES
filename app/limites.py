"""RNF-01: 20 req/min por IP nas rotas públicas; 10 falhas por conta → bloqueio de 15 min.

Cada função usa a própria transação: o contador precisa ficar gravado mesmo quando a
requisição termina em 401/429.
"""

import hashlib
import math
from datetime import timedelta

from fastapi import HTTPException

from app import db, relogio

IP_MAX = 20
IP_JANELA = timedelta(minutes=1)
CONTA_MAX = 10
CONTA_BLOQUEIO = timedelta(minutes=15)

_SOMAR = """INSERT INTO limites (chave, falhas, janela_inicio) VALUES (%(chave)s, 1, %(agora)s)
            ON CONFLICT (chave) DO UPDATE SET
              falhas = CASE WHEN limites.janela_inicio <= %(corte)s
                            THEN 1 ELSE limites.falhas + 1 END,
              janela_inicio = CASE WHEN limites.janela_inicio <= %(corte)s
                                   THEN %(agora)s ELSE limites.janela_inicio END
            RETURNING falhas, janela_inicio"""


def _bloqueado(restante: timedelta):
    segundos = max(1, math.ceil(restante.total_seconds()))
    raise HTTPException(429, "bloqueado", headers={"Retry-After": str(segundos)})


def chave_conta(email: str) -> str:
    # Nunca o e-mail em claro: só o SHA-256 do normalizado.
    return "conta:" + hashlib.sha256(email.encode()).hexdigest()


def contar_ip(pool, ip: str | None, rota: str) -> None:
    agora = relogio.agora()
    params = {"chave": f"ip:{ip}:{rota}", "agora": agora, "corte": agora - IP_JANELA}
    with db.transacao(pool) as conn:
        total, inicio = conn.execute(_SOMAR, params).fetchone()
    if total > IP_MAX:
        _bloqueado(inicio + IP_JANELA - agora)


def checar_conta(pool, email: str) -> None:
    agora = relogio.agora()
    with db.transacao(pool) as conn:
        linha = conn.execute(
            "SELECT bloqueado_ate FROM limites WHERE chave = %s", (chave_conta(email),)
        ).fetchone()
    if linha and linha[0] and linha[0] > agora:
        _bloqueado(linha[0] - agora)


def falha_conta(pool, email: str) -> bool:
    """Soma uma falha; devolve True quando esta falha bloqueou a conta."""
    agora = relogio.agora()
    params = {"chave": chave_conta(email), "agora": agora, "corte": agora - CONTA_BLOQUEIO}
    with db.transacao(pool) as conn:
        falhas, _ = conn.execute(_SOMAR, params).fetchone()
        if falhas < CONTA_MAX:
            return False
        conn.execute(
            """UPDATE limites SET falhas = 0, janela_inicio = %(agora)s,
                                  bloqueado_ate = %(agora)s + %(bloqueio)s
               WHERE chave = %(chave)s""",
            {**params, "bloqueio": CONTA_BLOQUEIO},
        )
    return True


def limpar_conta(pool, email: str) -> None:
    with db.transacao(pool) as conn:
        conn.execute("DELETE FROM limites WHERE chave = %s", (chave_conta(email),))
