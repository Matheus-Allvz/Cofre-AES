"""D17 / RF-I03: TOTP RFC 6238 com stdlib e cifra do segredo com chave do servidor."""

import base64

import pytest
from cryptography.exceptions import InvalidTag

from app import cifra_servidor, totp

RFC_SEGREDO = b"12345678901234567890"  # chave SHA-1 do Apêndice B do RFC 6238

# Apêndice B (SHA-1, 8 dígitos): T → código. Truncado a 6 = os 6 dígitos finais.
RFC_VETORES = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("instante", "esperado"), RFC_VETORES)
def test_vetores_rfc6238_apendice_b(instante, esperado):
    passo = totp.passo_de(instante)
    assert totp.codigo(RFC_SEGREDO, passo, digitos=8) == esperado
    assert totp.codigo(RFC_SEGREDO, passo) == esperado[-6:]
    assert totp.verificar(RFC_SEGREDO, esperado[-6:], instante, None) == passo


def test_janela_mais_menos_um_passo():
    instante = 1_700_000_000
    p = totp.passo_de(instante)
    for delta in (-1, 0, 1):
        assert totp.verificar(RFC_SEGREDO, totp.codigo(RFC_SEGREDO, p + delta), instante, None) == (
            p + delta
        )
    for delta in (-2, 2):
        assert (
            totp.verificar(RFC_SEGREDO, totp.codigo(RFC_SEGREDO, p + delta), instante, None) is None
        )


def test_anti_replay_exige_passo_posterior():
    instante = 1_700_000_000
    p = totp.passo_de(instante)
    atual = totp.codigo(RFC_SEGREDO, p)
    assert totp.verificar(RFC_SEGREDO, atual, instante, p) is None  # mesmo passo
    assert totp.verificar(RFC_SEGREDO, totp.codigo(RFC_SEGREDO, p - 1), instante, p) is None
    assert totp.verificar(RFC_SEGREDO, totp.codigo(RFC_SEGREDO, p + 1), instante, p) == p + 1


@pytest.mark.parametrize("digitado", [None, "", "12345", "1234567", "abcdef", "12 345"])
def test_formato_invalido(digitado):
    assert totp.verificar(RFC_SEGREDO, digitado, 59, None) is None


def test_base32_e_uri():
    segredo = totp.novo_segredo()
    assert len(segredo) == 20
    b32 = totp.base32(segredo)
    assert "=" not in b32 and base64.b32decode(b32 + "=" * (-len(b32) % 8)) == segredo
    uri = totp.uri(segredo, "ana@x.invalid")
    assert uri.startswith("otpauth://totp/Cofre%20AES%3Aana%40x.invalid?secret=" + b32)
    assert "issuer=Cofre%20AES" in uri and "digits=6" in uri and "period=30" in uri


def test_cifra_servidor_v1_com_aad_do_usuario():
    servidor = bytes(range(32))
    env = cifra_servidor.cifrar(servidor, "u1", b"segredo")
    assert env.startswith("v1.")
    assert cifra_servidor.decifrar(servidor, "u1", env) == b"segredo"
    with pytest.raises(InvalidTag):
        cifra_servidor.decifrar(servidor, "u2", env)  # envelope de outro usuário não abre
    with pytest.raises(InvalidTag):
        cifra_servidor.decifrar(bytes(32), "u1", env)
