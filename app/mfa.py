"""Segundo fator (TOTP ou código de recuperação de MFA) e geração dos códigos (RF-I03)."""

import base64
import secrets

from cryptography.exceptions import InvalidTag
from fastapi import HTTPException

from app import auditoria, cifra_servidor, db, relogio, seguranca, totp

N_CODIGOS = 10


def _normalizar(codigo: str) -> bytes:
    return "".join(codigo.split()).replace("-", "").upper().encode()


def hmac_codigo(segredo: bytes, codigo: str) -> bytes:
    return seguranca.hmac_pepper(segredo, _normalizar(codigo))


def gravar_codigos(conn, segredo: bytes, usuario_id) -> list[str]:
    """Troca os códigos por 10 novos (40 bits cada, `secrets`); só o HMAC vai ao banco."""
    codigos = []
    for _ in range(N_CODIGOS):
        c = base64.b32encode(secrets.token_bytes(5)).decode()
        codigos.append(f"{c[:4]}-{c[4:]}")
    conn.execute("DELETE FROM codigos_mfa WHERE usuario_id = %s", (usuario_id,))
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO codigos_mfa (usuario_id, codigo_hmac) VALUES (%s, %s)",
            [(usuario_id, hmac_codigo(segredo, c)) for c in codigos],
        )
    return codigos


def chave_totp(segredo: bytes, usuario_id, envelope: str) -> bytes | None:
    """Segredo TOTP decifrado, ou None se o envelope foi adulterado/trocado (falha fechada)."""
    try:
        return cifra_servidor.decifrar(segredo, usuario_id, envelope)
    except (InvalidTag, ValueError):
        return None


def exigir_segundo_fator(pool, segredo: bytes, u: dict, totp_digitado, codigo, origem) -> None:
    """`u`: id, org_id, totp_segredo_cif, totp_ultimo_passo. Sem MFA ativo: nada.

    Com MFA: 401 mfa_requerido sem fator, 401 mfa_invalido se errado ou já usado. O evento
    auth.mfa (ok/falha) fica gravado mesmo quando a resposta é 401."""
    if u["totp_ultimo_passo"] is None:
        return
    if not totp_digitado and not codigo:
        raise HTTPException(401, "mfa_requerido")
    evento = {
        "org_id": u["org_id"],
        "ator_id": u["id"],
        "alvo_tipo": "usuario",
        "alvo_id": str(u["id"]),
        **origem,
    }
    with db.transacao(pool) as conn:
        if totp_digitado:
            chave = chave_totp(segredo, u["id"], u["totp_segredo_cif"])
            passo = chave and totp.verificar(
                chave, totp_digitado, relogio.agora().timestamp(), u["totp_ultimo_passo"]
            )
            # Anti-replay atômico: um passo vale uma vez, mesmo com requisições paralelas.
            ok = passo is not None and bool(
                conn.execute(
                    """UPDATE usuarios SET totp_ultimo_passo = %s
                       WHERE id = %s AND totp_ultimo_passo < %s RETURNING 1""",
                    (passo, u["id"], passo),
                ).fetchone()
            )
            metodo = "totp" if chave else "totp_segredo_invalido"
        else:
            ok = bool(
                conn.execute(
                    """UPDATE codigos_mfa SET usado_em = %s
                       WHERE usuario_id = %s AND codigo_hmac = %s AND usado_em IS NULL
                       RETURNING 1""",
                    (relogio.agora(), u["id"], hmac_codigo(segredo, codigo)),
                ).fetchone()
            )
            metodo = "codigo_recuperacao"
            if ok:
                auditoria.registrar(conn, tipo="mfa.codigo_recuperacao_usado", **evento)
        auditoria.registrar(
            conn,
            tipo="auth.mfa",
            resultado="ok" if ok else "falha",
            meta={"metodo": metodo},
            **evento,
        )
    if not ok:
        raise HTTPException(401, "mfa_invalido")
