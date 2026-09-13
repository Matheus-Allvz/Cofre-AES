
import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

ITERACOES_PADRAO = 210_000
TAMANHO_CHAVE = 32   # bytes, AES-256
TAMANHO_SAL = 16     # bytes
TAMANHO_NONCE = 12   # bytes, valor recomendado para o GCM


def para_b64(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def de_b64(texto: str) -> bytes:
    return base64.b64decode(texto)


def derivar_chave(senha_mestra: str, sal: bytes, iteracoes: int) -> bytes:
    return PBKDF2(
        senha_mestra,
        sal,
        dkLen=TAMANHO_CHAVE,
        count=iteracoes,
        hmac_hash_module=SHA256,
    )


def gerar_sal() -> bytes:
    return get_random_bytes(TAMANHO_SAL)


def cifrar(chave: bytes, texto_claro: str, aad: bytes) -> tuple[str, str, str]:
    """Cifra e devolve (nonce, criptograma, etiqueta) em Base64."""
    nonce = get_random_bytes(TAMANHO_NONCE)
    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)
    criptograma, etiqueta = cifra.encrypt_and_digest(texto_claro.encode("utf-8"))
    return para_b64(nonce), para_b64(criptograma), para_b64(etiqueta)


def decifrar(
    chave: bytes,
    nonce_b64: str,
    cripto_b64: str,
    etiqueta_b64: str,
    aad: bytes,
) -> str:
    nonce = de_b64(nonce_b64)
    criptograma = de_b64(cripto_b64)
    etiqueta = de_b64(etiqueta_b64)
    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)
    texto_claro = cifra.decrypt_and_verify(criptograma, etiqueta)
    return texto_claro.decode("utf-8")


FRASE_VERIFICADORA = "cofre-ok"


def criar_verificador(chave: bytes, cofre_id: str) -> tuple[str, str, str]:
    return cifrar(chave, FRASE_VERIFICADORA, aad=cofre_id.encode())


def senha_mestra_correta(chave, nonce, cripto, etiqueta, cofre_id) -> bool:
    try:
        texto = decifrar(chave, nonce, cripto, etiqueta, aad=cofre_id.encode())
    except ValueError:
        return False
    return texto == FRASE_VERIFICADORA


def montar_aad_segredo(cofre_id: str, segredo_id: str) -> bytes:
    return f"{cofre_id}|{segredo_id}".encode()
