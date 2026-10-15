"""TOTP RFC 6238 (D17): HMAC-SHA1, 6 dígitos, passo de 30 s, janela ±1. Só stdlib."""

import base64
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

PASSO_S = 30
DIGITOS = 6
EMISSOR = "Cofre AES"


def codigo(segredo: bytes, passo: int, digitos: int = DIGITOS) -> str:
    """HOTP (RFC 4226 §5.3) do contador `passo`."""
    h = hmac.new(segredo, struct.pack(">Q", passo), "sha1").digest()
    deslocamento = h[-1] & 0x0F
    (valor,) = struct.unpack(">I", h[deslocamento : deslocamento + 4])
    return str((valor & 0x7FFFFFFF) % 10**digitos).zfill(digitos)


def passo_de(instante: float) -> int:
    return int(instante) // PASSO_S


def verificar(
    segredo: bytes, digitado: str | None, instante: float, ultimo: int | None
) -> int | None:
    """Passo que casa com o código (janela ±1) e é posterior a `ultimo` (anti-replay), ou None."""
    if not digitado or len(digitado) != DIGITOS or not digitado.isdigit():
        return None
    atual = passo_de(instante)
    for passo in (atual - 1, atual, atual + 1):
        if (ultimo is None or passo > ultimo) and hmac.compare_digest(
            codigo(segredo, passo), digitado
        ):
            return passo
    return None


def novo_segredo() -> bytes:
    return secrets.token_bytes(20)  # 160 bits, tamanho recomendado para SHA-1 (RFC 4226 §4)


def base32(segredo: bytes) -> str:
    return base64.b32encode(segredo).decode().rstrip("=")


def uri(segredo: bytes, conta: str) -> str:
    rotulo = quote(f"{EMISSOR}:{conta}")
    params = urlencode(
        {
            "secret": base32(segredo),
            "issuer": EMISSOR,
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{rotulo}?{params}"
