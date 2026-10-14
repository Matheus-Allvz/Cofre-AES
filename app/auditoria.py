import psycopg
from psycopg.types.json import Jsonb


def registrar(
    conn: psycopg.Connection,
    *,
    org_id: str | None,
    tipo: str,
    resultado: str = "ok",
    ator_id: str | None = None,
    alvo_tipo: str | None = None,
    alvo_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    meta: dict | None = None,
) -> int:
    """Grava um evento na conexão/transação recebida: se a operação cair, o evento cai junto."""
    linha = conn.execute(
        """INSERT INTO eventos
             (org_id, ator_id, tipo, alvo_tipo, alvo_id, resultado, ip, user_agent, meta)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING id""",
        (org_id, ator_id, tipo, alvo_tipo, alvo_id, resultado, ip, user_agent, Jsonb(meta or {})),
    ).fetchone()
    return linha[0]
