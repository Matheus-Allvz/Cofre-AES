import base64
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    database_url: str
    cofre_segredo: bytes
    cookie_secure: bool


def carregar() -> Config:
    """Configuração da API. A credencial de dono do banco fica só no migrador."""
    try:
        segredo = base64.b64decode(os.environ["COFRE_SEGREDO"], validate=True)
    except (KeyError, ValueError) as e:  # binascii.Error é ValueError
        raise RuntimeError("COFRE_SEGREDO ausente ou não é base64") from e
    if len(segredo) != 32:
        raise RuntimeError("COFRE_SEGREDO deve ter 32 bytes")
    return Config(
        database_url=os.environ["DATABASE_URL"],
        cofre_segredo=segredo,
        cookie_secure=os.environ.get("COOKIE_SECURE", "true").strip().lower() != "false",
    )


def database_url_dono() -> str:
    return os.environ["DATABASE_URL_DONO"]
