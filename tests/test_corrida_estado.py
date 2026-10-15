"""Correção pós-validação (Fase 5): suspender/remover no meio de uma verificação lenta.

Login, recuperar/iniciar, troca de senha e desativação de MFA verificam (Argon2/segundo fator)
fora da transação que cria a sessão ou a credencial. O monkeypatch força a ordem ruim: a
suspensão/remoção é commitada pela rota real depois da verificação e antes da gravação.
Sem a releitura `FOR SHARE` do estado, a sessão/token nasceria e "reviveria" ao reativar.
"""

import pytest
from conftest import KDF, H, ativar, ativar_mfa, b64u, codigo_totp, env_v1, ler, login

from app import mfa, seguranca

M = "/api/v1/membros"


def _durante(monkeypatch, modulo, nome, acao):
    """Faz `modulo.nome` rodar normalmente e, logo depois, executar `acao` (uma vez)."""
    original = getattr(modulo, nome)
    feito = []

    def no_meio(*args, **kwargs):
        resultado = original(*args, **kwargs)
        if not feito:
            feito.append(acao())
        return resultado

    monkeypatch.setattr(modulo, nome, no_meio)
    return feito


def _vivas(banco, uid):
    sql = "SELECT count(*) FROM sessoes WHERE usuario_id = %s AND revogada_em IS NULL"
    return ler(banco, sql, (uid,))[0][0]


@pytest.mark.parametrize(
    "acao,esperado",
    [("suspender", (403, {"erro": "conta_suspensa"})), ("remover", None)],
)
def test_login_durante_suspensao_nao_cria_sessao(
    cliente, owner, novo_cliente, banco, monkeypatch, acao, esperado
):
    m = ativar(cliente, novo_cliente, "corre@t.invalid")
    m["cliente"].post("/api/v1/logout", headers=H)
    url = f"{M}/{m['id']}" + ("/suspender" if acao == "suspender" else "")
    metodo = cliente.post if acao == "suspender" else cliente.delete
    feito = _durante(
        monkeypatch, seguranca, "verificar_auth", lambda: metodo(url, headers=H).status_code
    )
    c = novo_cliente()
    r = login(c, m["auth_hash"], "corre@t.invalid")
    assert feito == [200]
    assert (r.status_code, r.json()) == (esperado or (401, {"erro": "credenciais_invalidas"}))
    assert "sessao" not in c.cookies
    assert _vivas(banco, m["id"]) == 0
    if acao == "suspender":  # nada revive ao reativar
        assert cliente.post(f"{url[: -len('/suspender')]}/reativar", headers=H).status_code == 200
        assert _vivas(banco, m["id"]) == 0


def test_recuperar_iniciar_durante_suspensao_nao_cria_token(
    cliente, owner, novo_cliente, banco, monkeypatch
):
    recup = b64u(32)
    m = ativar(cliente, novo_cliente, "kit@t.invalid", recup_auth=recup)
    feito = _durante(
        monkeypatch,
        mfa,
        "exigir_segundo_fator",
        lambda: cliente.post(f"{M}/{m['id']}/suspender", headers=H).status_code,
    )
    r = novo_cliente().post(
        "/api/v1/recuperar/iniciar", json={"email": "kit@t.invalid", "recup_auth": recup}
    )
    assert feito == [200]
    assert (r.status_code, r.json()) == (401, {"erro": "credenciais_invalidas"})
    assert ler(banco, "SELECT count(*) FROM recuperacoes WHERE usuario_id = %s", (m["id"],)) == [
        (0,)
    ]
    assert cliente.post(f"{M}/{m['id']}/reativar", headers=H).status_code == 200
    assert ler(banco, "SELECT count(*) FROM recuperacoes WHERE usuario_id = %s", (m["id"],)) == [
        (0,)
    ]


def test_troca_de_senha_durante_suspensao_nao_grava(
    cliente, owner, novo_cliente, banco, monkeypatch
):
    m = ativar(cliente, novo_cliente, "senha@t.invalid")
    antes = ler(banco, "SELECT auth_hash FROM usuarios WHERE id = %s", (m["id"],))
    feito = _durante(
        monkeypatch,
        seguranca,
        "verificar_auth",
        lambda: cliente.post(f"{M}/{m['id']}/suspender", headers=H).status_code,
    )
    troca = {
        "auth_hash_atual": m["auth_hash"],
        "kdf": dict(KDF),
        "sal": b64u(16),
        "auth_hash": b64u(32),
        "chave_usuario_cif": env_v1(),
    }
    r = m["cliente"].post("/api/v1/eu/senha", json=troca, headers=H)
    assert feito == [200]
    assert (r.status_code, r.json()) == (401, {"erro": "nao_autenticado"})
    assert ler(banco, "SELECT auth_hash FROM usuarios WHERE id = %s", (m["id"],)) == antes


def test_desativar_mfa_durante_suspensao_nao_grava(
    cliente, owner, novo_cliente, banco, monkeypatch, relogio
):
    m = ativar(cliente, novo_cliente, "mfa@t.invalid")
    segredo, _ = ativar_mfa(m["cliente"])
    relogio.avancar(seconds=30)
    feito = _durante(
        monkeypatch,
        seguranca,
        "verificar_auth",
        lambda: cliente.post(f"{M}/{m['id']}/suspender", headers=H).status_code,
    )
    corpo = {"auth_hash": m["auth_hash"], "codigo": codigo_totp(segredo)}
    r = m["cliente"].request("DELETE", "/api/v1/eu/mfa", json=corpo, headers=H)
    assert feito == [200]
    assert (r.status_code, r.json()) == (401, {"erro": "nao_autenticado"})
    sql = "SELECT totp_ultimo_passo IS NOT NULL FROM usuarios WHERE id = %s"
    assert ler(banco, sql, (m["id"],)) == [(True,)]
