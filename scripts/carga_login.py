"""N logins paralelos contra a API do compose: ela não pode reiniciar nem morrer por OOM.

Uso: python scripts/carga_login.py --projeto cofre-e2e [--n 40] [--api http://127.0.0.1:8098]

Cada requisição usa um e-mail e um X-Forwarded-For próprios (pior caso: atacante com muitos
IPs; acessando direto a porta, o XFF é aceito), então todas chegam ao Argon2 do servidor.
Sai com 0 se RestartCount não mudou, OOMKilled=false e toda resposta foi 401/429/503.
"""

import argparse
import base64
import json
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def login(api: str, i: int):
    auth = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    req = urllib.request.Request(
        f"{api}/api/v1/login",
        json.dumps({"email": f"carga{i}@carga.invalid", "auth_hash": auth}).encode(),
        {"Content-Type": "application/json", "X-Forwarded-For": f"198.18.{i // 256}.{i % 256}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError as e:
        return f"erro:{type(e).__name__}"


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True).stdout


def container_api(projeto: str) -> str:
    filtros = ["--filter", f"label=com.docker.compose.project={projeto}"]
    filtros += ["--filter", "label=com.docker.compose.service=api"]
    return docker("ps", "-aq", *filtros).split()[0]


def estado(cid: str) -> dict:
    restart, oom, status = docker(
        "inspect", "-f", "{{.RestartCount}} {{.State.OOMKilled}} {{.State.Status}}", cid
    ).split()
    return {"restart": int(restart), "oom": oom == "true", "status": status}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--projeto", required=True)
    p.add_argument("--n", type=int, default=40)
    p.add_argument("--api", default="http://127.0.0.1:8098")
    args = p.parse_args()

    cid = container_api(args.projeto)
    antes = estado(cid)
    pico, parar = [], threading.Event()

    def medir():  # pico de memória visto pelo docker stats durante a carga
        while not parar.is_set():
            pico.append(docker("stats", "--no-stream", "--format", "{{.MemUsage}}", cid).strip())

    medidor = threading.Thread(target=medir)
    medidor.start()
    t0 = time.perf_counter()
    with ThreadPoolExecutor(args.n) as ex:
        respostas = list(ex.map(lambda i: login(args.api, i), range(args.n)))
    duracao = time.perf_counter() - t0
    time.sleep(2)  # um OOM no fim da rajada ainda aparece no estado
    parar.set()
    medidor.join()
    depois = estado(cid)

    contagem = Counter(respostas)
    ok = (
        depois["restart"] == antes["restart"]
        and not depois["oom"]
        and depois["status"] == "running"
        and set(contagem) <= {401, 429, 503}
    )
    print(
        json.dumps(
            {
                "n": args.n,
                "respostas": {str(k): v for k, v in contagem.items()},
                "duracao_s": round(duracao, 1),
                "antes": antes,
                "depois": depois,
                "memoria_amostras": pico,
                "resultado": "OK" if ok else "FALHA",
            },
            ensure_ascii=False,
            indent=1,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
