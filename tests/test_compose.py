from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((RAIZ / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICOS = COMPOSE["services"]


def test_db_sem_porta_publicada():
    assert "ports" not in SERVICOS["db"]
    assert SERVICOS["db"]["image"] == "postgres:16-alpine"


def test_portas_so_em_localhost():
    portas = [p for s in SERVICOS.values() for p in s.get("ports", [])]
    assert portas == ["127.0.0.1:8098:8000"]
    assert all(str(p).startswith("127.0.0.1:") for p in portas)


def test_limites_de_memoria():
    assert all("mem_limit" in s for s in SERVICOS.values())


def test_credencial_de_dono_so_no_migrar():
    assert "DATABASE_URL_DONO" in SERVICOS["migrar"]["environment"]
    assert "DATABASE_URL_DONO" not in SERVICOS["api"]["environment"]
    assert "cofre_dono" not in str(SERVICOS["api"])


def test_api_espera_migrar():
    dep = SERVICOS["api"]["depends_on"]["migrar"]
    assert dep["condition"] == "service_completed_successfully"


def test_dockerfile_nao_root_e_healthcheck():
    linhas = (RAIZ / "Dockerfile").read_text(encoding="utf-8").splitlines()
    usuarios = [linha.split()[1] for linha in linhas if linha.startswith("USER ")]
    assert usuarios and usuarios[-1] not in ("root", "0")
    assert any(linha.startswith("HEALTHCHECK") for linha in linhas)
    assert "/api/saude" in "\n".join(linhas)
