"""Fase 9 — deploy-empresarial.sh como forced command: só aceita "empresarial" ou um SHA hex
(7–40) da história de origin/empresarial, vindo de $1 ou de $SSH_ORIGINAL_COMMAND; qualquer outra
coisa sai 2 sem rodar git/docker. git, docker e curl simulados no PATH."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not shutil.which("bash"), reason="precisa de bash (CI)"
)

STUB = '#!/usr/bin/env bash\necho "$(basename "$0") $*" >> "$STUB_LOG"\n{corpo}\n'
CORPOS = {
    # merge-base --is-ancestor: só STUB_HISTORIA (e origin/empresarial) está na história.
    "git": 'case $1 in merge-base) [[ " $STUB_HISTORIA origin/empresarial " == *" $3 "* ]] ;; '
    "rev-parse) echo abc1234 ;; log) echo msg ;; esac",
    "docker": "true",
    "curl": "true",
}


@pytest.fixture
def proj(tmp_path):
    shutil.copy(RAIZ / "deploy-empresarial.sh", tmp_path / "deploy-empresarial.sh")
    (tmp_path / "bin").mkdir()
    for nome, corpo in CORPOS.items():
        (tmp_path / "bin" / nome).write_text(STUB.replace("{corpo}", corpo))
        (tmp_path / "bin" / nome).chmod(0o755)
    return tmp_path


def rodar(proj: Path, *args: str, original: str | None = None):
    env = {
        "PATH": f"{proj / 'bin'}:/usr/bin:/bin",
        "STUB_LOG": str(proj / "chamadas.log"),
        "STUB_HISTORIA": "0123abc 0123456789abcdef0123456789abcdef01234567",
    }
    if original is not None:
        env["SSH_ORIGINAL_COMMAND"] = original
    r = subprocess.run(
        ["bash", str(proj / "deploy-empresarial.sh"), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    log = proj / "chamadas.log"
    return r, (log.read_text().splitlines() if log.exists() else [])


@pytest.mark.parametrize(
    "original",
    [
        "",
        "true",
        "main",
        "origin/empresarial",
        "empresarial; id",
        "0123abc\nid",
        "0123ABC",
        "012345",
        "0123abc ",
        "$(id)",
        "-h",
    ],
)
def test_forced_command_recusa_ref_invalido_sem_efeito(proj, original):
    r, chamadas = rodar(proj, original=original)
    assert r.returncode == 2
    assert "recusado: ref inválido" in r.stderr
    assert chamadas == []


def test_sem_ref_nenhum_recusa(proj):
    r, chamadas = rodar(proj)
    assert r.returncode == 2 and chamadas == []


def test_sha_fora_da_historia_de_empresarial_recusa_sem_checkout(proj):
    r, chamadas = rodar(proj, original="fedcba9")
    assert r.returncode == 2
    assert "não está na história" in r.stderr
    assert [c.split()[:2] for c in chamadas] == [["git", "fetch"], ["git", "merge-base"]]


@pytest.mark.parametrize(
    ("args", "original", "alvo"),
    [
        (
            (),
            "0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef01234567",
        ),
        ((), "empresarial", "origin/empresarial"),
        (("0123abc",), "lixo ignorado", "0123abc"),  # operador: $1 vale sobre o original
    ],
)
def test_ref_valido_implanta(proj, args, original, alvo):
    r, chamadas = rodar(proj, *args, original=original)
    assert r.returncode == 0, r.stderr
    assert f"git checkout -q -f -B empresarial {alvo}" in chamadas
    assert "docker compose up -d --wait" in chamadas
    assert any(c.startswith("curl ") and "/api/pronto" in c for c in chamadas)
