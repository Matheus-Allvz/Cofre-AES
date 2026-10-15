import base64
import logging
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
    cookie_secure = os.environ.get("COOKIE_SECURE", "true").strip().lower() != "false"
    # 32 bytes aleatórios têm ~30 valores distintos; < 16 = zeros, padrão repetido ou
    # o valor fictício do .env.exemplo. Só aceito em dev local (COOKIE_SECURE=false).
    if len(set(segredo)) < 16:
        if cookie_secure:
            raise RuntimeError(
                "COFRE_SEGREDO fraco ou de exemplo: gere com openssl rand -base64 32"
            )
        logging.getLogger("cofre.config").warning(
            "COFRE_SEGREDO fraco ou de exemplo aceito só porque COOKIE_SECURE=false;"
            " nunca use assim fora do desenvolvimento local (gere com openssl rand -base64 32)"
        )
    return Config(
        database_url=os.environ["DATABASE_URL"],
        cofre_segredo=segredo,
        cookie_secure=cookie_secure,
    )


def database_url_dono() -> str:
    return os.environ["DATABASE_URL_DONO"]
