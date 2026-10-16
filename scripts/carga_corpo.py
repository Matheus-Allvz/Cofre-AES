"""N POSTs de corpo enorme em paralelo, sem cookie, contra a API do compose: 413 e nada de OOM.

Uso: python scripts/carga_corpo.py --projeto cofre-e2e [--n 6] [--mb 150] [--api 127.0.0.1:8098]

Metade das requisições manda Content-Length (o servidor recusa só pelo header), metade manda
Transfer-Encoding: chunked (o servidor conta os bytes do stream). Rotas: /prelogin, /login e
/colecoes/<id>/rotacionar (a de limite maior). O cliente envia em pedaços de 64 KiB e para assim
que a resposta chega. Sai com 0 se toda resposta foi 401/413, RestartCount não mudou,
OOMKilled=false e o pico de memória ficou abaixo de --teto-mib.
"""

import argparse
import json
import select
import socket
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from carga_login import container_api, docker, estado

ROTAS = [
    "/api/v1/prelogin",
    "/api/v1/login",
    "/api/v1/colecoes/00000000-0000-0000-0000-000000000000/rotacionar",
]
PEDACO = b"a" * 65536


def enviar(host: str, porta: int, rota: str, mb: int, chunked: bool):
    total = mb << 20
    cab = f"POST {rota} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
    cab += "Transfer-Encoding: chunked\r\n" if chunked else f"Content-Length: {total}\r\n"
    s = socket.create_connection((host, porta), timeout=120)
    enviado = 0
    try:
        s.sendall((cab + "\r\n").encode())
        while enviado < total:
            if select.select([s], [], [], 0)[0]:
                break  # resposta antes do fim do corpo
            s.sendall(b"10000\r\n" + PEDACO + b"\r\n" if chunked else PEDACO)
            enviado += len(PEDACO)
        resposta = s.recv(4096).decode(errors="replace")
        status = int(resposta.split()[1]) if resposta.startswith("HTTP/") else "sem_resposta"
    except OSError as e:
        status = f"erro:{type(e).__name__}"
    finally:
        s.close()
    return status, round(enviado / (1 << 20), 1)


def mib(uso: str) -> float:
    valor = uso.split("/")[0].strip()
    for sufixo, fator in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024)):
        if valor.endswith(sufixo):
            return float(valor[: -len(sufixo)]) * fator
    return 0.0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--projeto", required=True)
    p.add_argument("--n", type=int, default=6)
    p.add_argument("--mb", type=int, default=150)
    p.add_argument("--api", default="127.0.0.1:8098")
    p.add_argument("--teto-mib", type=float, default=200)
    args = p.parse_args()
    host, porta = args.api.split(":")

    cid = container_api(args.projeto)
    antes = estado(cid)
    amostras, parar = [], threading.Event()

    def medir():
        while not parar.is_set():
            uso = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", cid)
            amostras.append(uso.strip())

    medidor = threading.Thread(target=medir)
    medidor.start()
    casos = [(ROTAS[i % len(ROTAS)], i % 2 == 1) for i in range(args.n)]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(args.n) as ex:
        resultados = list(
            ex.map(lambda c: (c[0], c[1], *enviar(host, int(porta), c[0], args.mb, c[1])), casos)
        )
    duracao = time.perf_counter() - t0
    time.sleep(3)
    parar.set()
    medidor.join()
    depois = estado(cid)
    pico = max(map(mib, amostras), default=0.0)
    contagem = Counter(r[2] for r in resultados)
    ok = (
        depois["restart"] == antes["restart"]
        and not depois["oom"]
        and depois["status"] == "running"
        and set(contagem) <= {401, 413}
        and pico < args.teto_mib
    )
    print(
        json.dumps(
            {
                "n": args.n,
                "mb_por_requisicao": args.mb,
                "resultados": [
                    {"rota": r, "chunked": c, "status": s, "mib_enviados": e}
                    for r, c, s, e in resultados
                ],
                "respostas": {str(k): v for k, v in contagem.items()},
                "duracao_s": round(duracao, 1),
                "antes": antes,
                "depois": depois,
                "pico_mib": pico,
                "memoria_amostras": amostras,
                "resultado": "OK" if ok else "FALHA",
            },
            ensure_ascii=False,
            indent=1,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
