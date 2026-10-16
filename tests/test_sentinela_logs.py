"""Fase 8 — RNF-07 completo: percorre TODAS as rotas de /api/v1 (a matriz de autorização inteira,
com cada ator) com valor sentinela em todo campo sensível (authHash, recup_auth, sal, chaves e
envelopes cifrados, blobs, chave pública) e confere que nenhum sentinela, token de convite nem
e-mail de login falho aparece nos logs (caplog + stdout/stderr) nem em `eventos.meta`.
TOTP, códigos de recuperação e token de recuperação: test_logs.py::test_segredos_de_mfa_*."""

import itertools
import logging

import conftest
import test_cofre
import test_matriz_autorizacao as matriz
from conftest import ler

from app import seguranca
from app.logs import FormatoJson

SENTINELA = "SENT-"


def test_sentinelas_de_todas_as_rotas_fora_dos_logs_e_do_meta(
    cliente, owner, novo_cliente, banco, monkeypatch, caplog, capsys
):
    n = itertools.count()

    def b64u_sentinela(tamanho: int) -> str:
        # Mesmo comprimento do base64url de `tamanho` bytes; decodifica normalmente.
        alvo = len(seguranca.b64u(bytes(tamanho)))
        return (f"{SENTINELA}{next(n):05d}-" + "A" * alvo)[:alvo]

    # env_v1/x1/payload_aceite/env/criar_item/editar/corpo_rotacao/envelopes_owner geram tudo
    # a partir destes dois b64u: todo campo sensível da matriz passa a carregar um sentinela.
    for modulo in (conftest, test_cofre, matriz):
        monkeypatch.setattr(modulo, "b64u", b64u_sentinela)
    tokens = []
    convidar = matriz.convidar

    def convidar_anotando(c, email, papel="member"):
        r = convidar(c, email, papel)
        tokens.append(r["token"])
        return r

    monkeypatch.setattr(matriz, "convidar", convidar_anotando)
    assert conftest.env_v1().startswith(f"v1.{SENTINELA}")
    assert test_cofre.x1().startswith(f"x1.{SENTINELA}")

    with caplog.at_level(logging.DEBUG):
        matriz.test_matriz_de_autorizacao(cliente, owner, novo_cliente, banco, monkeypatch)

    assert next(n) > 300  # sentinelas de fato enviados
    assert len(tokens) > 10
    emails_falhos = [f"login-{a}@matriz.invalid" for a in matriz.ATORES]
    texto = caplog.text + "".join(FormatoJson().format(r) for r in caplog.records)
    saida = capsys.readouterr()
    texto += saida.out + saida.err
    assert "/api/v1/colecoes" in texto  # os logs de requisição existem
    for proibido in [SENTINELA, *tokens, *emails_falhos]:
        assert proibido not in texto, proibido
    meta = "".join(m for (m,) in ler(banco, "SELECT meta::text FROM eventos"))
    for proibido in [SENTINELA, *tokens, *emails_falhos]:
        assert proibido not in meta, proibido
    # Os sentinelas chegaram ao banco nos campos cifrados (o servidor guarda blobs opacos).
    assert ler(banco, "SELECT count(*) FROM itens WHERE meta_cif LIKE %s", (f"v1.{SENTINELA}%",))[
        0
    ][0]
