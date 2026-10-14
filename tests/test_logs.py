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
