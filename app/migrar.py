"""Runner de migrations forward-only (D4). Uso: python -m app.migrar (com DATABASE_URL_DONO)."""

import hashlib
import logging
import sys
from pathlib import Path

import psycopg

from app import config, logs

PASTA = Path(__file__).resolve().parent.parent / "migracoes"
TRAVA = 7_301_221_001  # chave do pg_advisory_lock: um runner por vez

log = logging.getLogger("cofre.migrar")


class ChecksumDivergente(Exception):
    pass


def migrar(url: str, pasta: Path | None = None) -> list[str]:
    """Aplica em ordem as migrations pendentes; devolve as versões aplicadas nesta execução."""
    arquivos = sorted((pasta or PASTA).glob("[0-9][0-9][0-9][0-9]_*.sql"))
    novas = []
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (TRAVA,))
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS schema_migracoes (
                     versao text PRIMARY KEY,
                     sha256 text NOT NULL,
                     aplicada_em timestamptz NOT NULL DEFAULT now())"""
            )
            aplicadas = dict(conn.execute("SELECT versao, sha256 FROM schema_migracoes"))
            pendentes = []
            for arquivo in arquivos:
                conteudo = arquivo.read_bytes()
                soma = hashlib.sha256(conteudo).hexdigest()
                if arquivo.stem not in aplicadas:
                    pendentes.append((arquivo.stem, conteudo.decode("utf-8"), soma))
                elif aplicadas[arquivo.stem] != soma:
                    raise ChecksumDivergente(arquivo.stem)
            for versao, sql, soma in pendentes:
                with conn.transaction():
                    conn.execute(sql)
                    conn.execute(
                        "INSERT INTO schema_migracoes (versao, sha256) VALUES (%s, %s)",
                        (versao, soma),
                    )
                log.info(f"migration aplicada: {versao}", extra={"versao": versao})
                novas.append(versao)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (TRAVA,))
    return novas


def main() -> int:
    logs.configurar()
    try:
        novas = migrar(config.database_url_dono())
    except ChecksumDivergente as e:
        log.error("checksum_divergente", extra={"erro": "checksum_divergente", "versao": str(e)})
        return 1
    if not novas:
        log.info("nada a aplicar")
    return 0


if __name__ == "__main__":
    sys.exit(main())
