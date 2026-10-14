import json
import logging
import sys
from datetime import UTC, datetime

_PADRAO = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName"}


class FormatoJson(logging.Formatter):
    """Uma linha JSON por registro: em, nivel, logger, msg e os campos de `extra`."""

    def format(self, record: logging.LogRecord) -> str:
        dados = {
            "em": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "nivel": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        dados.update({k: v for k, v in vars(record).items() if k not in _PADRAO})
        if record.exc_info:
            dados["exc"] = self.formatException(record.exc_info)
        return json.dumps(dados, ensure_ascii=False, default=str)


def configurar(nivel: int = logging.INFO) -> None:
    raiz = logging.getLogger()
    if not any(isinstance(h.formatter, FormatoJson) for h in raiz.handlers):
        saida = logging.StreamHandler(sys.stdout)
        saida.setFormatter(FormatoJson())
        raiz.addHandler(saida)
    raiz.setLevel(nivel)
    # O uvicorn instala handlers em texto; passam a herdar o JSON da raiz. O access log
    # (que traria query string) fica desligado: o middleware da API registra as requisições.
    for nome in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(nome)
        logger.handlers.clear()
        logger.propagate = True
