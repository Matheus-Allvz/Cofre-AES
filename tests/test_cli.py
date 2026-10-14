import json

import psycopg
import pytest

from app import cli


def test_criar_org_imprime_json_e_cria_owner_convidado(banco, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", banco["app"])
    assert cli.main(["criar-org", "--nome", "Acme", "--email", " Dono@Acme.Invalid "]) == 0
    saida = json.loads(capsys.readouterr().out)
    assert set(saida) == {"org_id", "usuario_id", "token"}
    with psycopg.connect(banco["dono"]) as conn:
        u = conn.execute(
            "SELECT org_id::text, email, papel, estado FROM usuarios WHERE id = %s",
            (saida["usuario_id"],),
        ).fetchone()
        tipos = [t for (t,) in conn.execute("SELECT tipo FROM eventos ORDER BY id")]
        hash_guardado = conn.execute("SELECT token_hash FROM convites").fetchone()[0]
    assert u == (saida["org_id"], "dono@acme.invalid", "owner", "convidado")
    assert tipos == ["org.criada", "convite.criado"]
    assert saida["token"].encode() not in hash_guardado  # só o SHA-256 vai ao banco


def test_segunda_org_recusada(banco, monkeypatch, capsys):
    """RF-I01: CLI recusa segunda org (exit != 0)."""
    monkeypatch.setenv("DATABASE_URL", banco["app"])
    assert cli.main(["criar-org", "--nome", "A", "--email", "a@a.invalid"]) == 0
    capsys.readouterr()
    assert cli.main(["criar-org", "--nome", "B", "--email", "b@b.invalid"]) == 1
    assert json.loads(capsys.readouterr().err) == {"erro": "org_ja_existe"}


def test_cli_exige_subcomando():
    with pytest.raises(SystemExit):
        cli.main([])
