import base64
import os
import secrets
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from app import cli, seguranca, totp
from app import relogio as app_relogio
from app.migrar import migrar

URL_DONO = os.environ.get(
    "TEST_DATABASE_URL_DONO", "postgresql://postgres:postgres@127.0.0.1:55432/postgres"
)
SENHA_APP = "senha-de-teste-app"
HOSTS_LOCAIS = {"127.0.0.1", "localhost", "::1"}


def host_local(url: str) -> bool:
    """O conftest troca a senha de cofre_app e cria/derruba bancos: só em Postgres local."""
    return conninfo_to_dict(url).get("host") in HOSTS_LOCAIS


@pytest.fixture(scope="session")
def banco():
    """Banco temporário por sessão: migrations como dono, app como cofre_app."""
    if not host_local(URL_DONO):
        pytest.exit("TEST_DATABASE_URL_DONO deve apontar para 127.0.0.1/localhost", returncode=2)
    nome = f"cofre_teste_{secrets.token_hex(4)}"
    with psycopg.connect(URL_DONO, autocommit=True) as conn:
        # Service container do CI não roda db/init: o papel nasce aqui.
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'cofre_app'").fetchone():
            conn.execute("CREATE ROLE cofre_app LOGIN")
        conn.execute(sql.SQL("ALTER ROLE cofre_app PASSWORD {}").format(sql.Literal(SENHA_APP)))
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(nome)))
    urls = {
        "dono": make_conninfo(URL_DONO, dbname=nome),
        "app": make_conninfo(URL_DONO, dbname=nome, user="cofre_app", password=SENHA_APP),
    }
    migrar(urls["dono"])
    yield urls
    with psycopg.connect(URL_DONO, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(nome)))


@pytest.fixture(autouse=True)
def limpar(request):
    yield
    if "banco" not in request.fixturenames:
        return
    urls = request.getfixturevalue("banco")
    with psycopg.connect(urls["dono"]) as conn:
        tabelas = [
            t
            for (t,) in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                " AND tablename <> 'schema_migracoes'"
            )
        ]
        # O trigger de eventos barra TRUNCATE até do dono: desliga só aqui, na transação.
        conn.execute("ALTER TABLE eventos DISABLE TRIGGER USER")
        conn.execute(
            sql.SQL("TRUNCATE {} RESTART IDENTITY CASCADE").format(
                sql.SQL(", ").join(map(sql.Identifier, tabelas))
            )
        )
        conn.execute("ALTER TABLE eventos ENABLE TRIGGER USER")


def _ambiente(monkeypatch, database_url):
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("COFRE_SEGREDO", base64.b64encode(secrets.token_bytes(32)).decode())


@pytest.fixture
def cliente(banco, monkeypatch):
    _ambiente(monkeypatch, banco["app"])
    from app.main import app

    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def cliente_sem_banco(monkeypatch):
    # Porta fechada: simula banco parado.
    _ambiente(monkeypatch, "postgresql://cofre_app:x@127.0.0.1:1/cofre")
    from app.main import app

    with TestClient(app, base_url="https://testserver") as c:
        yield c


# ---------- Fase 3: contas ----------

H = {"X-Cofre": "1"}  # header exigido em não-GET autenticado
EMAIL_OWNER = "owner@teste.invalid"
KDF = {"tipo": "argon2id", "m": 65536, "t": 3, "p": 1}


def b64u(n: int) -> str:
    return seguranca.b64u(secrets.token_bytes(n))


def env_v1() -> str:
    return f"v1.{b64u(12)}.{b64u(48)}"


def payload_aceite(token: str, auth_hash: str | None = None, **extra) -> dict:
    """Aceite bem formado com material aleatório (o servidor não decifra nada)."""
    return {
        "token": token,
        "nome": "Pessoa Teste",
        "kdf": dict(KDF),
        "sal": b64u(16),
        "auth_hash": auth_hash or b64u(32),
        "chave_usuario_cif": env_v1(),
        "chave_usuario_recup_cif": env_v1(),
        "recup_auth": b64u(32),
        "chave_publica": b64u(32),
        "chave_privada_cif": env_v1(),
        **extra,
    }


class Relogio:
    def __init__(self):
        self.agora = datetime.now(UTC)

    def avancar(self, **delta):
        self.agora += timedelta(**delta)


@pytest.fixture
def relogio(monkeypatch):
    r = Relogio()
    monkeypatch.setattr(app_relogio, "agora", lambda: r.agora)
    return r


@pytest.fixture
def org(banco):
    return cli.criar_org(banco["app"], "Org Teste", EMAIL_OWNER)


@pytest.fixture
def novo_cliente(cliente):
    """Outro "navegador" (cookies próprios) contra a mesma app já iniciada."""
    from app.main import app

    return lambda: TestClient(app, base_url="https://testserver")


def aceitar_e_logar(c: TestClient, token: str, email: str) -> str:
    auth = b64u(32)
    assert c.post("/api/v1/convites/aceitar", json=payload_aceite(token, auth)).status_code == 201
    assert c.post("/api/v1/login", json={"email": email, "auth_hash": auth}).status_code == 200
    return auth


def convidar(c, email, papel="member"):
    r = c.post("/api/v1/convites", json={"email": email, "papel": papel}, headers=H)
    assert r.status_code == 201, r.text
    return r.json() | {"token": r.json()["link"].removeprefix("/#/convite/")}


def ativar(gestor: TestClient, novo_cliente, email: str, papel: str = "member") -> dict:
    """Fluxo real da Fase 5: convite → aceite → login → o gestor confere o fingerprint da chave
    pública que o membro enviou. Devolve {cliente, auth_hash, id, chave_publica}."""
    convite = convidar(gestor, email, papel)
    c, auth, pub = novo_cliente(), b64u(32), b64u(32)
    aceite = payload_aceite(convite["token"], auth, chave_publica=pub)
    assert c.post("/api/v1/convites/aceitar", json=aceite).status_code == 201
    assert c.post("/api/v1/login", json={"email": email, "auth_hash": auth}).status_code == 200
    fp = seguranca.fingerprint(seguranca.de_b64u(pub))
    url = f"/api/v1/membros/{convite['usuario_id']}/confirmar"
    r = gestor.post(url, json={"fingerprint": fp}, headers=H)
    assert r.status_code == 200, r.text
    return {"cliente": c, "auth_hash": auth, "id": convite["usuario_id"], "chave_publica": pub}


def politica(banco, **campos):
    """Altera a política da org direto no banco (como dono)."""
    with psycopg.connect(banco["dono"]) as conn:
        for campo, valor in campos.items():
            conn.execute(
                sql.SQL("UPDATE politicas SET {} = %s").format(sql.Identifier(campo)), (valor,)
            )


def codigo_totp(segredo: bytes, passos_adiante: int = 0) -> str:
    """Código do passo atual do relógio da app (real ou o simulado da fixture `relogio`)."""
    return totp.codigo(segredo, totp.passo_de(app_relogio.agora().timestamp()) + passos_adiante)


def ativar_mfa(c: TestClient) -> tuple[bytes, list[str]]:
    """iniciar + confirmar com o código do passo atual; devolve (segredo, códigos)."""
    r = c.post("/api/v1/eu/mfa/iniciar", headers=H)
    assert r.status_code == 200, r.text
    b32 = r.json()["segredo_base32"]
    segredo = base64.b32decode(b32 + "=" * (-len(b32) % 8))
    r = c.post("/api/v1/eu/mfa/confirmar", json={"codigo": codigo_totp(segredo)}, headers=H)
    assert r.status_code == 200, r.text
    return segredo, r.json()["codigos_recuperacao"]


@pytest.fixture
def owner(cliente, org, banco):
    """Owner do bootstrap aceito e logado em `cliente`. Os testes da Fase 3 rodam sem MFA
    obrigatório; a política padrão (MFA obrigatório) é coberta nos testes da Fase 4."""
    politica(banco, mfa_obrigatorio=False)
    return {
        **org,
        "email": EMAIL_OWNER,
        "auth_hash": aceitar_e_logar(cliente, org["token"], EMAIL_OWNER),
    }


@pytest.fixture
def owner_mfa(cliente, org, relogio):
    """Owner do bootstrap com a política padrão (MFA obrigatório) e TOTP ativado em `cliente`."""
    auth = aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    segredo, codigos = ativar_mfa(cliente)
    relogio.avancar(seconds=30)  # o passo usado na confirmação não vale de novo
    return {**org, "email": EMAIL_OWNER, "auth_hash": auth, "segredo": segredo, "codigos": codigos}


def login(c: TestClient, auth: str, email: str = EMAIL_OWNER, **extra):
    return c.post("/api/v1/login", json={"email": email, "auth_hash": auth, **extra})


def ler(banco, consulta: str, params=()):
    with psycopg.connect(banco["dono"]) as conn:
        return conn.execute(consulta, params).fetchall()
