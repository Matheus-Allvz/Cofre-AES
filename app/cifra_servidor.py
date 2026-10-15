"""Cifra com chave do servidor (D17): segredo TOTP em envelope v1 (§3.1) sob a subchave `totp`."""

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.seguranca import b64u, de_b64u, subchave


def _aad(usuario_id) -> bytes:
    return f"cofre-emp/v1|totp|{usuario_id}".encode()


def cifrar(segredo_servidor: bytes, usuario_id, dados: bytes) -> str:
    iv = secrets.token_bytes(12)
    ct = AESGCM(subchave(segredo_servidor, "totp")).encrypt(iv, dados, _aad(usuario_id))
    return f"v1.{b64u(iv)}.{b64u(ct)}"


def decifrar(segredo_servidor: bytes, usuario_id, envelope: str) -> bytes:
    _, iv, ct = envelope.split(".")
    return AESGCM(subchave(segredo_servidor, "totp")).decrypt(
        de_b64u(iv), de_b64u(ct), _aad(usuario_id)
    )
