import json
import logging

from app.logs import FormatoJson

SENTINELA = "SENTINELA-F1"


def test_log_de_requisicao_json_sem_corpo(cliente, caplog, capsys):
    with caplog.at_level(logging.INFO):
        cliente.post("/api/saude", json={"auth_hash": SENTINELA, "blob": SENTINELA})

    registros = [r for r in caplog.records if r.getMessage() == "requisicao"]
    assert len(registros) == 1
    linha = json.loads(FormatoJson().format(registros[0]))
    assert linha["nivel"] == "INFO"
    assert linha["msg"] == "requisicao"
    assert linha["rota"] == "/api/saude"
    assert linha["status"] == 405
    assert isinstance(linha["duracao_ms"], float)

    assert SENTINELA not in caplog.text
    assert all(SENTINELA not in FormatoJson().format(r) for r in caplog.records)
    saida = capsys.readouterr()
    assert SENTINELA not in saida.out + saida.err


def test_formato_com_excecao():
    try:
        raise ValueError("falhou")
    except ValueError:
        registro = logging.getLogger("t").makeRecord(
            "t", logging.ERROR, __file__, 1, "erro %s", ("x",), exc_info=True
        )
        import sys

        registro.exc_info = sys.exc_info()
    linha = json.loads(FormatoJson().format(registro))
    assert linha["msg"] == "erro x"
    assert "ValueError: falhou" in linha["exc"]


def test_segredos_de_mfa_e_recuperacao_fora_dos_logs(cliente, org, relogio, caplog, capsys):
    """Fase 4: base32, códigos TOTP, códigos de recuperação, recup_auth e token de recuperação
    não aparecem em log nem no stdout/stderr capturados."""
    from conftest import EMAIL_OWNER, H, ativar_mfa, codigo_totp, login, payload_aceite

    with caplog.at_level(logging.DEBUG):
        dados = payload_aceite(org["token"])
        cliente.post("/api/v1/convites/aceitar", json=dados)
        login(cliente, dados["auth_hash"])
        segredo, codigos = ativar_mfa(cliente)
        relogio.avancar(seconds=30)
        codigo = codigo_totp(segredo)
        login(cliente, dados["auth_hash"], totp=codigo)
        login(cliente, dados["auth_hash"], codigo_recuperacao=codigos[0])
        r = cliente.post(
            "/api/v1/recuperar/iniciar",
            json={"email": EMAIL_OWNER, "recup_auth": dados["recup_auth"], "totp": "123456"},
        )
        relogio.avancar(seconds=30)
        r = cliente.post(
            "/api/v1/recuperar/iniciar",
            json={
                "email": EMAIL_OWNER,
                "recup_auth": dados["recup_auth"],
                "totp": codigo_totp(segredo),
            },
        )
        token = r.json()["token"]
        cliente.post("/api/v1/eu/senha", json={"auth_hash_atual": "x"}, headers=H)
    from app import totp

    texto = caplog.text + "".join(capsys.readouterr())
    texto += "".join(FormatoJson().format(r) for r in caplog.records)
    assert "/api/v1/recuperar/iniciar" in texto  # o log de requisição existe
    for sentinela in [totp.base32(segredo), codigo, *codigos, dados["recup_auth"], token]:
        assert sentinela not in texto
