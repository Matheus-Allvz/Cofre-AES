"""CLI de administração (com DATABASE_URL).

python -m app.cli criar-org --nome N --email E
python -m app.cli reemitir-convite --email E   (owner do bootstrap que ainda não aceitou)
"""

import argparse
import json
import os
import sys

import psycopg

from app import auditoria, relogio
from app.rotas.convites import criar_convite

TRAVA = 7_301_221_002  # pg_advisory_xact_lock: duas CLIs simultâneas não criam duas orgs


class ErroCli(Exception):
    """Erro esperado: vira {"erro": <código>} no stderr e exit 1."""


def criar_org(url: str, nome: str, email: str) -> dict:
    """Uma org por instalação: org + política (MFA opcional) + owner convidado + convite 72 h."""
    email = email.strip().lower()
    with psycopg.connect(url) as conn:  # uma transação: commit no fim, rollback em exceção
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (TRAVA,))
        if conn.execute("SELECT 1 FROM organizacoes").fetchone():
            raise ErroCli("org_ja_existe")
        (org_id,) = conn.execute(
            "INSERT INTO organizacoes (nome) VALUES (%s) RETURNING id", (nome,)
        ).fetchone()
        conn.execute(
            "INSERT INTO politicas (org_id, mfa_obrigatorio) VALUES (%s, false)", (org_id,)
        )
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


def reemitir_convite(url: str, email: str) -> dict:
    """Novo convite de bootstrap para o owner ainda `convidado`; o anterior deixa de valer."""
    email = email.strip().lower()
    with psycopg.connect(url) as conn:
        linha = conn.execute(
            """SELECT u.id, u.org_id FROM usuarios u
               WHERE u.email = %s AND u.estado = 'convidado' AND u.papel = 'owner'
                 AND EXISTS (SELECT 1 FROM convites c
                             WHERE c.usuario_id = u.id AND c.criado_por IS NULL)
               FOR UPDATE""",
            (email,),
        ).fetchone()
        if not linha:
            raise ErroCli("owner_convidado_nao_encontrado")
        usuario_id, org_id = linha
        revogados = conn.execute(
            """UPDATE convites SET revogado_em = %s
               WHERE usuario_id = %s AND usado_em IS NULL AND revogado_em IS NULL
               RETURNING id""",
            (relogio.agora(), usuario_id),
        ).fetchall()
        for (convite_id,) in revogados:
            auditoria.registrar(
                conn,
                org_id=org_id,
                tipo="convite.revogado",
                alvo_tipo="convite",
                alvo_id=str(convite_id),
                meta={"motivo": "reemissao"},
            )
        _, token = criar_convite(
            conn, org_id=org_id, usuario_id=usuario_id, papel="owner", criado_por=None
        )
    return {"usuario_id": str(usuario_id), "token": token}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="comando", required=True)
    org = sub.add_parser("criar-org", help="cria a organização e o convite do owner inicial")
    org.add_argument("--nome", required=True)
    org.add_argument("--email", required=True)
    reemitir = sub.add_parser("reemitir-convite", help="novo convite para o owner inicial")
    reemitir.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    url = os.environ["DATABASE_URL"]
    try:
        if args.comando == "criar-org":
            saida = criar_org(url, args.nome, args.email)
        else:
            saida = reemitir_convite(url, args.email)
    except ErroCli as e:
        print(json.dumps({"erro": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps(saida))
    return 0


if __name__ == "__main__":
    sys.exit(main())
