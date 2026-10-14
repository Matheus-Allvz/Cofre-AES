import logging
import shutil

import psycopg
import pytest

from app import migrar as runner


def test_aplicada_e_idempotente(banco):
    with psycopg.connect(banco["dono"]) as conn:
        versoes = [v for (v,) in conn.execute("SELECT versao FROM schema_migracoes")]
    assert versoes == ["0001_base"]
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


def test_toda_tabela_de_negocio_tem_org_id(banco):
    """RF-O01: org_id direto (FKs indiretas entram nas fases 3 e 6)."""
    with psycopg.connect(banco["dono"]) as conn:
        sem_org = conn.execute(
            """SELECT t.tablename FROM pg_tables t
               WHERE t.schemaname = 'public'
                 AND t.tablename NOT IN ('schema_migracoes', 'organizacoes')
                 AND NOT EXISTS (SELECT 1 FROM information_schema.columns c
                                 WHERE c.table_schema = 'public'
                                   AND c.table_name = t.tablename
                                   AND c.column_name = 'org_id')"""
        ).fetchall()
    assert sem_org == []


def test_privilegios_da_app(banco):
    with psycopg.connect(banco["dono"]) as conn:
        privs = dict(
            conn.execute(
                """SELECT table_name, string_agg(privilege_type, ',' ORDER BY privilege_type)
                   FROM information_schema.role_table_grants
                   WHERE grantee = 'cofre_app' GROUP BY table_name"""
            )
        )
    assert privs == {"eventos": "INSERT,SELECT", "organizacoes": "DELETE,INSERT,SELECT,UPDATE"}
