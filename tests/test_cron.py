"""Fase 9 — cron do backup: scripts/cron-backup.sh (log rotacionado, ultimo_falhou em saída
≠ 0) e scripts/instalar-cron.sh (idempotente), com backup.sh e crontab simulados."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not shutil.which("bash"), reason="precisa de bash (CI)"
)


@pytest.fixture
def projeto(tmp_path):
    (tmp_path / "scripts").mkdir()
    for nome in ("cron-backup.sh", "instalar-cron.sh"):
        shutil.copy(RAIZ / "scripts" / nome, tmp_path / "scripts" / nome)
    # backup.sh simulado: sai com STUB_RC e mostra que recebeu a variável do .env.
    falso = tmp_path / "scripts" / "backup.sh"
    falso.write_text(
        '#!/usr/bin/env bash\necho "backup falso rc=$STUB_RC r=${#BACKUP_AGE_RECIPIENT}"\n'
        'exit "$STUB_RC"\n'
    )
    falso.chmod(0o755)
    (tmp_path / ".env").write_text("BACKUP_AGE_RECIPIENT=age1abc\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    crontab = bin_ / "crontab"
    crontab.write_text(
        '#!/usr/bin/env bash\nf="$CRONTAB_ARQ"\n'
        'if [[ $1 == -l ]]; then [[ -f $f ]] && cat "$f" || exit 1; else cat > "$f"; fi\n'
    )
    crontab.chmod(0o755)
    return tmp_path


def rodar(proj: Path, script: str, **env) -> subprocess.CompletedProcess:
    base = {"PATH": f"{proj / 'bin'}:/usr/bin:/bin", "CRONTAB_ARQ": str(proj / "crontab.txt")}
    return subprocess.run(
        ["bash", str(proj / "scripts" / script)],
        env=base | env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_falha_grava_ultimo_falhou_e_sucesso_remove(projeto):
    backups = projeto / "backups"
    r = rodar(projeto, "cron-backup.sh", STUB_RC="4")
    assert r.returncode == 4
    assert "exit=4" in (backups / "ultimo_falhou").read_text()
    r = rodar(projeto, "cron-backup.sh", STUB_RC="0")
    assert r.returncode == 0
    assert not (backups / "ultimo_falhou").exists()
    log = (backups / "backup.log").read_text().splitlines()
    assert log == ["backup falso rc=4 r=7", "backup falso rc=0 r=7"]  # anexado, .env carregado


def test_sem_env_falha(projeto):
    (projeto / ".env").unlink()
    r = rodar(projeto, "cron-backup.sh", STUB_RC="0")
    assert r.returncode == 2
    assert (projeto / "backups" / "ultimo_falhou").exists()


def test_log_rotaciona_acima_de_1_mib(projeto):
    backups = projeto / "backups"
    backups.mkdir()
    (backups / "backup.log").write_text("x" * (1024 * 1024 + 1))
    rodar(projeto, "cron-backup.sh", STUB_RC="0")
    assert (backups / "backup.log.1").stat().st_size == 1024 * 1024 + 1
    assert (backups / "backup.log").read_text() == "backup falso rc=0 r=7\n"


def test_instalar_cron_idempotente_e_preserva_outras_linhas(projeto):
    (projeto / "crontab.txt").write_text(
        f"0 */2 * * * outro\n0 1 * * * {projeto}/scripts/cron-backup.sh\n"
    )
    for _ in range(2):
        r = rodar(projeto, "instalar-cron.sh")
        assert r.returncode == 0, r.stderr
    assert (projeto / "crontab.txt").read_text().splitlines() == [
        "0 */2 * * * outro",
        f"30 3 * * * {projeto}/scripts/cron-backup.sh",
    ]


def test_instalar_cron_com_crontab_vazio(projeto):
    assert rodar(projeto, "instalar-cron.sh").returncode == 0
    assert (projeto / "crontab.txt").read_text() == f"30 3 * * * {projeto}/scripts/cron-backup.sh\n"
