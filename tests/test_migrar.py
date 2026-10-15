import logging
import shutil

import psycopg
import pytest

from app import migrar as runner


def test_aplicada_e_idempotente(banco):
    with psycopg.connect(banco["dono"]) as conn:
        versoes = [v for (v,) in conn.execute("SELECT versao FROM schema_migracoes")]
    assert versoes == ["0001_base", "0002_contas"]
    assert runner.migrar(banco["dono"]) == []


def test_main_nada_a_aplicar(banco, monkeypatch, caplog):
    monkeypatch.setenv("DATABASE_URL_DONO", banco["dono"])
    with caplog.at_level(logging.INFO):
        assert runner.main() == 0
    assert "nada a aplicar" in caplog.text


def test_checksum_divergente(banco, monkeypatch, tmp_path, caplog):
    pasta = tmp_path / "migracoes"
    shutil.copytree(runner.PASTA, pasta)
    with (pasta / "0001_base.sql").open("a") as f:
        f.write("\n-- alterada depois de aplicada\n")

    with pytest.raises(runner.ChecksumDivergente):
        runner.migrar(banco["dono"], pasta)

    monkeypatch.setattr(runner, "PASTA", pasta)
    monkeypatch.setenv("DATABASE_URL_DONO", banco["dono"])
    assert runner.main() == 1
    assert "checksum_divergente" in caplog.text


def test_nova_migration_aplicada_uma_vez(banco, tmp_path):
    pasta = tmp_path / "migracoes"
    shutil.copytree(runner.PASTA, pasta)
    (pasta / "9999_teste.sql").write_text("CREATE TABLE teste_9999 (org_id uuid NOT NULL);")
    try:
        assert runner.migrar(banco["dono"], pasta) == ["9999_teste"]
        assert runner.migrar(banco["dono"], pasta) == []
    finally:
        with psycopg.connect(banco["dono"]) as conn:
            conn.execute("DROP TABLE teste_9999")
            conn.execute("DELETE FROM schema_migracoes WHERE versao = '9999_teste'")


# Fora da regra, cada uma com motivo. Toda tabela nova cai no teste até ser classificada.
SEM_ORG = {
    "schema_migracoes": "controle do runner",
    "organizacoes": "é a própria organização",
    "limites": "rate limit por IP/sha256(email), antes de existir usuário",
    "eventos": "org_id nullable documentado (login falho de e-mail inexistente)",
}


def test_toda_tabela_de_negocio_tem_org_id(banco):
    """RF-O01: org_id NOT NULL direto, ou FK NOT NULL para tabela com org_id NOT NULL."""
    with psycopg.connect(banco["dono"]) as conn:
        tabelas = {
            t
            for (t,) in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        }
        not_null = set(
            conn.execute(
                """SELECT table_name, column_name FROM information_schema.columns
                   WHERE table_schema = 'public' AND is_nullable = 'NO'"""
            ).fetchall()
        )
        fks = conn.execute(
            """SELECT c.conrelid::regclass::text, a.attname, c.confrelid::regclass::text
               FROM pg_constraint c
               JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
               WHERE c.contype = 'f' AND cardinality(c.conkey) = 1"""
        ).fetchall()
        org_eventos = conn.execute(
            """SELECT is_nullable FROM information_schema.columns
               WHERE table_name = 'eventos' AND column_name = 'org_id'"""
        ).fetchone()
    com_org = {t for t in tabelas if (t, "org_id") in not_null}
    via_fk = {t for t, col, alvo in fks if (t, col) in not_null and alvo in com_org}
    assert tabelas - com_org - via_fk - set(SEM_ORG) == set()
    assert {"usuarios", "convites"} <= com_org and "sessoes" in via_fk
    assert org_eventos == ("YES",)


def test_conftest_so_aceita_postgres_local():
    from conftest import host_local

    assert host_local("postgresql://u:p@127.0.0.1:5432/x")
    assert host_local("postgresql://u:p@localhost/x")
    assert not host_local("postgresql://u:p@db.exemplo.com:5432/x")
    assert not host_local("host=10.0.0.5 user=postgres")


def test_privilegios_da_app(banco):
    with psycopg.connect(banco["dono"]) as conn:
        privs = dict(
            conn.execute(
                """SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type)
                   FROM information_schema.role_table_grants
                   WHERE grantee = 'cofre_app' GROUP BY table_name"""
            )
        )
    crud = "DELETE,INSERT,SELECT,UPDATE"
    assert privs == {
        "eventos": "INSERT,SELECT",
        **{t: crud for t in ("organizacoes", "usuarios", "convites", "sessoes", "limites")},
    }
