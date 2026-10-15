from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


def criar_pool(url: str) -> ConnectionPool:
    pool = ConnectionPool(
        url,
        min_size=1,
        max_size=10,
        timeout=5,
        open=False,
        check=ConnectionPool.check_connection,
        kwargs={"connect_timeout": 3},
    )
    pool.open(wait=False)
    return pool


@contextmanager
def transacao(pool: ConnectionPool) -> Iterator[psycopg.Connection]:
    """Uma conexão do pool numa transação: commit no fim, rollback em exceção."""
    with pool.connection() as conn, conn.transaction():
        yield conn


def linha(conn: psycopg.Connection, sql, params=None) -> dict | None:
    """Uma linha como dict (ou None)."""
    return conn.cursor(row_factory=dict_row).execute(sql, params).fetchone()
