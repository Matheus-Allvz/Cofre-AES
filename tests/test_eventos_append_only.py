import psycopg
import pytest

from app import auditoria

COMANDOS = [
    "UPDATE eventos SET tipo = 'adulterado'",
    "DELETE FROM eventos",
    "TRUNCATE eventos",
]


@pytest.fixture
def evento(banco):
    with psycopg.connect(banco["app"]) as conn:
        (org_id,) = conn.execute(
            "INSERT INTO organizacoes (nome) VALUES ('Org') RETURNING id"
        ).fetchone()
        auditoria.registrar(
            conn,
            org_id=org_id,
            tipo="org.criada",
            alvo_tipo="org",
            alvo_id=str(org_id),
            ip="127.0.0.1",
            user_agent="pytest",
            meta={"nome": "Org"},
        )
    return org_id


def test_registrar_grava_evento(banco, evento):
    with psycopg.connect(banco["app"]) as conn:
        linha = conn.execute(
            "SELECT org_id, tipo, resultado, host(ip), meta FROM eventos"
        ).fetchone()
    assert linha == (evento, "org.criada", "ok", "127.0.0.1", {"nome": "Org"})


def test_evento_cai_com_a_transacao(banco, evento):
    with pytest.raises(RuntimeError), psycopg.connect(banco["app"]) as conn:
        auditoria.registrar(conn, org_id=evento, tipo="item.revelado")
        raise RuntimeError  # rollback
    with psycopg.connect(banco["app"]) as conn:
        assert conn.execute("SELECT count(*) FROM eventos").fetchone() == (1,)


@pytest.mark.parametrize("comando", COMANDOS)
def test_app_sem_privilegio(banco, evento, comando):
    with psycopg.connect(banco["app"]) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(comando)


@pytest.mark.parametrize("comando", COMANDOS)
def test_dono_barrado_pelo_trigger(banco, evento, comando):
    with psycopg.connect(banco["dono"]) as conn, pytest.raises(psycopg.errors.RaiseException) as e:
        conn.execute(comando)
    assert "append-only" in str(e.value)
    with psycopg.connect(banco["dono"]) as conn:
        assert conn.execute("SELECT count(*), min(tipo) FROM eventos").fetchone() == (
            1,
            "org.criada",
        )
