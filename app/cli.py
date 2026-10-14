"""CLI de administração. Uso: python -m app.cli criar-org --nome N --email E (com DATABASE_URL)."""

import argparse
import json
import os
import sys

import psycopg

from app import auditoria
from app.rotas.convites import criar_convite

TRAVA = 7_301_221_002  # pg_advisory_xact_lock: duas CLIs simultâneas não criam duas orgs


class OrgJaExiste(Exception):
    pass


def criar_org(url: str, nome: str, email: str) -> dict:
    """Uma org por instalação: org + owner `convidado` + convite de bootstrap (72 h)."""
    email = email.strip().lower()
    with psycopg.connect(url) as conn:  # uma transação: commit no fim, rollback em exceção
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (TRAVA,))
        if conn.execute("SELECT 1 FROM organizacoes").fetchone():
            raise OrgJaExiste
        (org_id,) = conn.execute(
            "INSERT INTO organizacoes (nome) VALUES (%s) RETURNING id", (nome,)
        ).fetchone()
        auditoria.registrar(
            conn, org_id=org_id, tipo="org.criada", alvo_tipo="org", alvo_id=str(org_id)
        )
        (usuario_id,) = conn.execute(
            "INSERT INTO usuarios (org_id, email, papel) VALUES (%s, %s, 'owner') RETURNING id",
            (org_id, email),
        ).fetchone()
        _, token = criar_convite(
            conn, org_id=org_id, usuario_id=usuario_id, papel="owner", criado_por=None
        )
    return {"org_id": str(org_id), "usuario_id": str(usuario_id), "token": token}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="comando", required=True)
    org = sub.add_parser("criar-org", help="cria a organização e o convite do owner inicial")
    org.add_argument("--nome", required=True)
    org.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    try:
        saida = criar_org(os.environ["DATABASE_URL"], args.nome, args.email)
    except OrgJaExiste:
        print(json.dumps({"erro": "org_ja_existe"}), file=sys.stderr)
        return 1
    print(json.dumps(saida))
    return 0


if __name__ == "__main__":
    sys.exit(main())
