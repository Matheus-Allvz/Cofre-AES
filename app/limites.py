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


# Uma instrução atômica por tentativa (a linha fica travada pelo ON CONFLICT): requisições
# paralelas não passam do limite. A tentativa conta ANTES da verificação Argon2; o login
# certo zera a contagem (limpar_conta). Bloqueada: não soma nem estende o bloqueio.
_TENTAR = """
INSERT INTO limites (chave, falhas, janela_inicio) VALUES (%(chave)s, 1, %(agora)s)
ON CONFLICT (chave) DO UPDATE SET
  falhas = CASE WHEN limites.bloqueado_ate > %(agora)s THEN limites.falhas
                WHEN limites.bloqueado_ate <= %(agora)s OR limites.janela_inicio <= %(corte)s
                THEN 1 ELSE limites.falhas + 1 END,
  janela_inicio = CASE WHEN limites.bloqueado_ate > %(agora)s THEN limites.janela_inicio
                       WHEN limites.bloqueado_ate <= %(agora)s OR limites.janela_inicio <= %(corte)s
                       THEN %(agora)s ELSE limites.janela_inicio END,
  bloqueado_ate = CASE WHEN limites.bloqueado_ate > %(agora)s THEN limites.bloqueado_ate
                       WHEN limites.bloqueado_ate <= %(agora)s OR limites.janela_inicio <= %(corte)s
                       THEN NULL
                       WHEN limites.falhas + 1 > %(max)s THEN %(fim)s
                       ELSE NULL END
RETURNING bloqueado_ate"""


def tentar_conta(pool, email: str, ao_bloquear=None) -> None:
    """Conta uma tentativa; a 11ª dentro da janela bloqueia por 15 min (429 + Retry-After).

    `ao_bloquear(conn)` roda na mesma transação só quando ESTA tentativa criou o bloqueio.
    """
    agora = relogio.agora()
    fim = agora + CONTA_BLOQUEIO
    params = {
        "chave": chave_conta(email),
        "agora": agora,
        "corte": agora - CONTA_BLOQUEIO,
        "max": CONTA_MAX,
        "fim": fim,
    }
    with db.transacao(pool) as conn:
        (bloqueado_ate,) = conn.execute(_TENTAR, params).fetchone()
        if bloqueado_ate == fim and ao_bloquear:
            ao_bloquear(conn)
    if bloqueado_ate and bloqueado_ate > agora:
        _bloqueado(bloqueado_ate - agora)


def limpar_conta(pool, email: str) -> None:
    """Zera a conta após credencial válida e purga o que já não vale nada (sem job externo).

    Linha sem bloqueio vigente e com janela iniciada há mais de 15 min (a maior janela, a da
    conta) é recriada do zero na próxima tentativa: apagar não muda nenhuma regra.
    """
    agora = relogio.agora()
    with db.transacao(pool) as conn:
        conn.execute(
            """DELETE FROM limites WHERE chave = %s
                  OR (janela_inicio <= %s AND (bloqueado_ate IS NULL OR bloqueado_ate <= %s))""",
            (chave_conta(email), agora - CONTA_BLOQUEIO, agora),
        )
