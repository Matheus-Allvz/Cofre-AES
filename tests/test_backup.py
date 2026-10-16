"""Fase 8 — scripts/backup.sh com docker, age e rclone simulados por stubs no PATH (RNF-05):
retenção 7+4+3 com datas falsas, guarda de cota do R2 (9 GB), prefixos, nunca apagar no R2 e
backup local sem destino externo. A restauração real (age + Postgres) roda no job de CI
`backup` e na evidência da DoD 5."""

import shutil
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
SCRIPT = RAIZ / "scripts" / "backup.sh"
RECIPIENT = "age1stubstubstubstubstubstubstubstubstubstubstubstubstubstubst"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not shutil.which("bash"), reason="precisa de bash/GNU date (CI)"
)

STUBS = {
    # docker compose ... exec -T db psql|pg_dump ...: manifesto JSON ou um "dump" com sentinela.
    "docker": """#!/usr/bin/env bash
case " $* " in
  *" psql "*) echo '{"eventos" : 5, "organizacoes" : 1, "usuarios" : 2}' ;;
  *" pg_dump "*) printf 'PGDMP-falso SENT-dump-em-claro\\n' ;;
  *) echo "docker stub: $*" >&2; exit 9 ;;
esac
""",
    # age -r <recipient>: "cifra" (base64) — o teste confere só o fluxo, não a cripto.
    "age": """#!/usr/bin/env bash
[[ $1 == -r && -n $2 ]] || { echo "age stub: só -r" >&2; exit 9; }
echo "$*" >> "$STUB_LOG.age"
printf 'age-stub\\n'; base64 -w0; echo
""",
    # rclone: anota cada chamada; size devolve RCLONE_USO; copyto copia para STUB_R2.
    "rclone": """#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case $1 in
  listremotes) echo "r2:" ;;
  size) echo "{\\"count\\":3,\\"bytes\\":${RCLONE_USO:-0},\\"sizeless\\":0}" ;;
  copyto) destino=$STUB_R2/${@: -1}; mkdir -p "$(dirname "$destino")"; cp "${@: -2:1}" "$destino" ;;
  *) echo "rclone stub: $1 não simulado" >&2; exit 9 ;;
esac
""",
}


@pytest.fixture
def ambiente(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nome, corpo in STUBS.items():
        (bin_ / nome).write_text(corpo)
        (bin_ / nome).chmod(0o755)
    return tmp_path


def rodar(amb: Path, agora="20261014T030000Z", sem=(), **env):
    bin_ = amb / "bin"
    for nome in sem:
        (bin_ / nome).unlink(missing_ok=True)
    base = {
        "PATH": f"{bin_}:/usr/bin:/bin",
        "HOME": str(amb),
        "BACKUP_DIR": str(amb / "backups"),
        "BACKUP_AGE_RECIPIENT": RECIPIENT,
        "BACKUP_AGORA": agora,
        "STUB_LOG": str(amb / "rclone.log"),
        "STUB_R2": str(amb / "r2"),
    }
    return subprocess.run(
        ["bash", str(SCRIPT)], env=base | env, capture_output=True, text=True, timeout=60
    )


def chamadas(amb: Path) -> list[str]:
    log = amb / "rclone.log"
    return log.read_text().splitlines() if log.exists() else []


def status(amb: Path) -> str:
    return (amb / "backups" / "status").read_text()


# ---------- retenção ----------


def nome(d: date, hora="030000") -> str:
    return f"cofre-{d:%Y%m%d}T{hora}Z.dump.age"


def retencao(nomes) -> set:
    r = subprocess.run(
        ["bash", str(SCRIPT), "--retencao"],
        input="\n".join(nomes) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return set(r.stdout.split())


def oraculo(dias: list[date]) -> set:
    """O mesmo critério em Python: 7 dias mais recentes, 4 domingos, 3 dias 1."""
    dias = sorted(set(dias), reverse=True)
    manter = set(dias[:7])
    manter |= set([d for d in dias if d.isoweekday() == 7][:4])
    manter |= set([d for d in dias if d.day == 1][:3])
    return {nome(d) for d in manter}


def test_retencao_mantem_exatamente_7_diarios_4_semanais_3_mensais():
    """Datas escolhidas sem sobreposição: 7 dias recentes (nem domingo nem dia 1), 4 domingos e
    3 dias 1 anteriores, e mais antigos de cada tipo que têm de sair."""
    hoje = date(2026, 10, 16)  # sexta
    recentes = [hoje - timedelta(days=i) for i in range(9) if (hoje - timedelta(days=i)).isoweekday() != 7]
    recentes = [d for d in recentes if d.day != 1][:7]
    domingos = [date(2026, 10, 4) - timedelta(weeks=i) for i in range(7)]  # 4 ficam, 3 saem
    primeiros = [date(2026, m, 1) for m in (9, 7, 4, 1)] + [date(2025, 12, 1)]  # não-domingos
    assert all(d.isoweekday() != 7 for d in primeiros)
    extras = [date(2026, 5, 13), date(2026, 5, 14)]  # nem recentes, nem domingo, nem dia 1
    nomes = [nome(d) for d in recentes + domingos + primeiros + extras]
    nomes += [nome(recentes[0], "010000"), "lixo.txt", "cofre-x.dump.age"]  # 2º do dia, intrusos
    mantidos = retencao(nomes)
    esperado = {nome(d) for d in recentes} | {nome(d) for d in domingos[:4]}
    esperado |= {nome(d) for d in primeiros[:3]}
    assert len(esperado) == 7 + 4 + 3
    assert mantidos == esperado
    assert nome(recentes[0], "010000") not in mantidos  # só o mais novo de cada dia


def test_retencao_backup_diario_de_um_ano_bate_com_o_oraculo():
    dias = [date(2026, 10, 16) - timedelta(days=i) for i in range(400)]
    mantidos = retencao(nome(d) for d in dias)
    assert mantidos == oraculo(dias)
    assert len(mantidos) <= 7 + 4 + 3


# ---------- backup.sh ----------


def test_sem_destino_externo_backup_local_com_aviso(ambiente):
    r = rodar(ambiente, BACKUP_RCLONE_DEST="")
    assert r.returncode == 0, r.stderr
    dump = ambiente / "backups" / "cofre-20261014T030000Z.dump.age"
    assert dump.read_text().startswith("age-stub") and "SENT-" not in dump.read_text()
    assert (ambiente / "backups" / "cofre-20261014T030000Z.manifesto.age").exists()
    assert "AVISO: cópia externa ignorado: BACKUP_RCLONE_DEST vazio" in r.stderr
    assert status(ambiente).startswith("em=20261014T030000Z resultado=ok motivo=ignorado")
    assert (ambiente / "backups" / "ultimo_ok").read_text().split() == [
        "20261014T030000Z",
        "cofre-20261014T030000Z.dump.age",
    ]
    assert chamadas(ambiente) == []


def test_sem_rclone_instalado_backup_local_com_aviso(ambiente):
    r = rodar(ambiente, sem=("rclone",))
    assert r.returncode == 0, r.stderr
    assert "rclone não instalado" in r.stderr


def test_envio_por_prefixo_e_nunca_apaga_no_r2(ambiente):
    # 2026-11-01 é domingo e dia 1: diario, semanal e mensal.
    r = rodar(ambiente, agora="20261101T030000Z", RCLONE_USO="1000")
    assert r.returncode == 0, r.stderr
    enviados = sorted(str(p.relative_to(ambiente / "r2")) for p in (ambiente / "r2").rglob("*.age"))
    arquivos = ["cofre-20261101T030000Z.dump.age", "cofre-20261101T030000Z.manifesto.age"]
    esperado = sorted(f"r2:secrets-backup/{p}/{a}" for p in ("diario", "semanal", "mensal") for a in arquivos)
    assert [e.replace("\\", "/") for e in enviados] == esperado
    for c in chamadas(ambiente):
        assert c.split()[0] in {"listremotes", "size", "copyto"}, c  # nada de delete/sync/move
        if c.split()[0] != "listremotes":
            assert "--s3-no-check-bucket" in c
    assert status(ambiente).startswith("em=20261101T030000Z resultado=ok motivo=ok: diario semanal mensal")


def test_dia_comum_vai_so_para_diario(ambiente):
    r = rodar(ambiente, agora="20261014T030000Z")  # quarta, dia 14
    assert r.returncode == 0, r.stderr
    prefixos = {p.parent.name for p in (ambiente / "r2").rglob("*.age")}
    assert prefixos == {"diario"}


@pytest.mark.parametrize(("agora", "prefixos"), [("20261014T030000Z", 1), ("20261101T030000Z", 3)])
def test_guarda_de_cota_nao_envia_acima_de_90_por_cento(ambiente, agora, prefixos):
    """Uso atual + arquivo novo × prefixos > BACKUP_LIMITE_BYTES (padrão 9e9) → nada enviado,
    saída 3, motivo no status e no log; o backup local fica."""
    r = rodar(ambiente, agora=agora, RCLONE_USO="0")
    assert r.returncode == 0
    novo = sum(p.stat().st_size for p in (ambiente / "backups").glob(f"cofre-{agora}.*.age"))
    for f in (ambiente / "r2").rglob("*"):
        f.unlink() if f.is_file() else None
    (ambiente / "rclone.log").unlink()
    # Exatamente no limite passa; um byte acima não.
    no_limite = str(9_000_000_000 - novo * prefixos)
    r = rodar(ambiente, agora=agora, RCLONE_USO=no_limite)
    assert r.returncode == 0, r.stderr
    (ambiente / "rclone.log").unlink()
    acima = str(9_000_000_000 - novo * prefixos + 1)
    r = rodar(ambiente, agora=agora, RCLONE_USO=acima)
    assert r.returncode == 3, r.stderr
    assert not any(c.startswith("copyto") for c in chamadas(ambiente))
    assert "passa do limite 9000000000; nada enviado" in r.stderr
    assert "resultado=falha motivo=cota:" in status(ambiente)
    assert (ambiente / "backups" / f"cofre-{agora}.dump.age").exists()


def test_limite_configuravel(ambiente):
    r = rodar(ambiente, RCLONE_USO="10", BACKUP_LIMITE_BYTES="100")
    assert r.returncode == 3
    r = rodar(ambiente, BACKUP_LIMITE_BYTES="9e9")
    assert r.returncode == 2 and "inteiro em bytes" in r.stderr


def test_recusa_chave_privada_sem_imprimir(ambiente):
    segredo = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    r = rodar(ambiente, BACKUP_AGE_RECIPIENT=segredo)
    assert r.returncode == 2
    assert segredo not in r.stdout + r.stderr + status(ambiente)
    assert not list((ambiente / "backups").glob("*.age"))


def test_sem_recipient_falha(ambiente):
    r = rodar(ambiente, BACKUP_AGE_RECIPIENT="")
    assert r.returncode == 2 and "BACKUP_AGE_RECIPIENT" in r.stderr


def test_retencao_local_apaga_antigos_e_seus_manifestos(ambiente):
    pasta = ambiente / "backups"
    pasta.mkdir()
    antigos = [date(2026, 10, 13) - timedelta(days=i) for i in range(30)]
    for d in antigos:
        (pasta / nome(d)).write_text("x")
        (pasta / nome(d).replace(".dump.", ".manifesto.")).write_text("x")
    r = rodar(ambiente, BACKUP_RCLONE_DEST="")
    assert r.returncode == 0, r.stderr
    restantes = {p.name for p in pasta.glob("cofre-*.dump.age")}
    assert restantes == oraculo([*antigos, date(2026, 10, 14)])
    manifestos = {p.name.replace(".manifesto.", ".dump.") for p in pasta.glob("*.manifesto.age")}
    assert manifestos == restantes


def test_backup_nao_le_chave_privada():
    """Checklist: o backup.sh só usa o recipient público (age -r), nunca -d/-i/AGE_IDENTITY."""
    fonte = SCRIPT.read_text()
    assert "age -r" in fonte
    for proibido in ("age -d", " -i ", "AGE_IDENTITY", "--decrypt", "--identity"):
        assert proibido not in fonte, proibido


def test_status_json_do_rclone_size_aceita_espacos(ambiente):
    stub = ambiente / "bin" / "rclone"
    stub.write_text(stub.read_text().replace('\\"bytes\\":${RCLONE_USO:-0}', '\\"bytes\\": 42'))
    r = rodar(ambiente)
    assert r.returncode == 0, r.stderr
    novo = sum(p.stat().st_size for p in (ambiente / "backups").glob("cofre-*.age"))
    assert f"uso projetado {42 + novo} de" in status(ambiente)
