"""Fase 8 — RF-A01 completo: cada tipo de evento de §5.6 (lido de ARQUITETURA-ALVO.md) é gerado
por uma ação real, exatamente uma vez, com org, ator, ip, user_agent e resultado. Falha se §5.6
ou o código ganharem um tipo sem ação aqui."""

import re
from pathlib import Path

import pytest
from conftest import (
    EMAIL_OWNER,
    H,
    aceitar_e_logar,
    ativar,
    ativar_mfa,
    codigo_totp,
    convidar,
    env_v1,
    ler,
    login,
    payload_aceite,
)
from fastapi.testclient import TestClient
from test_cofre import _item, _ok, criar_colecao, editar, env, x1
from test_compartilhar import corpo_rotacao

from app import main

RAIZ = Path(__file__).resolve().parent.parent
V = "/api/v1"
IP, UA = "198.51.100.7", "teste-eventos/1.0"


def tipos_da_arquitetura() -> set:
    texto = (RAIZ / "docs/plano/ARQUITETURA-ALVO.md").read_text(encoding="utf-8")
    secao = texto.split("### 5.6", 1)[1].split("\n`meta`", 1)[0]
    return set(re.findall(r"`([a-z_]+\.[a-z_]+)`", secao))


def tipos_do_codigo() -> set:
    prefixos = "|".join(sorted({t.split(".")[0] for t in tipos_da_arquitetura()}))
    achados = set()
    for arq in (RAIZ / "app").rglob("*.py"):
        achados |= set(re.findall(rf'"((?:{prefixos})\.[a-z_]+)"', arq.read_text(encoding="utf-8")))
    return achados


@pytest.fixture
def navegador(cliente):
    """Cliente com IP e User-Agent conhecidos (o padrão do TestClient não é IP válido)."""
    return lambda: TestClient(
        main.app, base_url="https://testserver", client=(IP, 50000), headers={"user-agent": UA}
    )


@pytest.fixture
def ctx(org, banco, navegador):
    from conftest import politica

    politica(banco, mfa_obrigatorio=False)
    dono = navegador()
    auth = aceitar_e_logar(dono, org["token"], EMAIL_OWNER)
    eu = org["usuario_id"]
    col = _ok(criar_colecao(dono, [env(eu)])[0], 201).json()["id"]
    item = _item(dono, col)
    return {"dono": dono, "auth": auth, "eu": eu, "col": col, "item": item, "nav": navegador}


def _m(c, email="alvo@ev.invalid", papel="member"):
    return ativar(c["dono"], c["nav"], email, papel)


def _bloqueio(c):
    for _ in range(11):
        r = login(c["nav"](), "A" * 43)
    assert r.status_code == 429


def _mfa_login(c, ok: bool, recuperacao=False):
    segredo, codigos = ativar_mfa(c["dono"])
    if recuperacao:
        return _ok(login(c["nav"](), c["auth"], codigo_recuperacao=codigos[0]))
    codigo = codigo_totp(segredo, 1) if ok else "000000"
    if not ok and codigo_totp(segredo) == codigo:
        codigo = "111111"
    return login(c["nav"](), c["auth"], totp=codigo)


def _senha(c):
    corpo = {
        "auth_hash_atual": c["auth"],
        "kdf": payload_aceite("x")["kdf"],
        "sal": payload_aceite("x")["sal"],
        "auth_hash": payload_aceite("x")["auth_hash"],
        "chave_usuario_cif": env_v1(),
    }
    return _ok(c["dono"].post(f"{V}/eu/senha", json=corpo, headers=H), 204)


def _recuperacao(c):
    dados = payload_aceite(convidar(c["dono"], "rec@ev.invalid")["token"])
    assert c["nav"]().post(f"{V}/convites/aceitar", json=dados).status_code == 201
    corpo = {"email": "rec@ev.invalid", "recup_auth": dados["recup_auth"]}
    return _ok(c["nav"]().post(f"{V}/recuperar/iniciar", json=corpo))


def _sessao_revogada(c):
    outra = c["nav"]()
    _ok(login(outra, c["auth"]))
    sessoes = _ok(c["dono"].get(f"{V}/eu/sessoes")).json()
    alvo = next(s["id"] for s in sessoes if not s["atual"])
    return _ok(c["dono"].delete(f"{V}/eu/sessoes/{alvo}", headers=H), 204)


def _mfa_desativado(c):
    segredo, _ = ativar_mfa(c["dono"])
    corpo = {"auth_hash": c["auth"], "codigo": codigo_totp(segredo, 1)}
    return _ok(c["dono"].request("DELETE", f"{V}/eu/mfa", json=corpo, headers=H), 204)


def _aceito(c):
    conv = convidar(c["dono"], "aceita@ev.invalid")
    return _ok(c["nav"]().post(f"{V}/convites/aceitar", json=payload_aceite(conv["token"])), 201)


def _confirmado(c):
    return _m(c)  # ativar = convite → aceite → login → confirmar fingerprint


def _membro(c, acao):
    m = _m(c)
    url = f"{V}/membros/{m['id']}"
    if acao == "reativar":
        _ok(c["dono"].post(f"{url}/suspender", headers=H))
    if acao == "papel":
        return _ok(c["dono"].put(f"{url}/papel", json={"papel": "admin"}, headers=H))
    if acao == "remover":
        return _ok(c["dono"].delete(url, headers=H))
    return _ok(c["dono"].post(f"{url}/{acao}", headers=H))


def _col_membro(c, acao):
    m = _m(c)
    base = f"{V}/colecoes/{c['col']}/membros"
    novo = {"usuario_id": m["id"], "permissao": "ver", "chave_ver": 1, "chave_colecao_cif": x1()}
    if acao != "adicionar":
        _ok(c["dono"].post(base, json=novo, headers=H), 201)
    if acao == "adicionar":
        return _ok(c["dono"].post(base, json=novo, headers=H), 201)
    if acao == "permissao":
        return _ok(c["dono"].put(f"{base}/{m['id']}", json={"permissao": "editar"}, headers=H))
    return _ok(c["dono"].delete(f"{base}/{m['id']}", headers=H), 204)


def _lixo(c, acao):
    d, i = c["dono"], c["item"]
    _ok(d.delete(f"{V}/itens/{i}", headers=H), 204) if acao != "excluir" else None
    if acao == "excluir":
        return _ok(d.delete(f"{V}/itens/{i}", headers=H), 204)
    if acao == "restaurar":
        return _ok(d.post(f"{V}/itens/{i}/restaurar", headers=H), 204)
    return _ok(d.delete(f"{V}/itens/{i}/definitivo", headers=H), 204)


def _recusada(c, monkeypatch):
    monkeypatch.setattr(main, "_grandes", 1)
    url = f"{V}/colecoes/{c['col']}/rotacionar"
    corpo = b"{}" + b" " * (300 << 10)
    r = c["dono"].post(url, content=corpo, headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 503


ACOES = {
    "auth.login": lambda c: _ok(login(c["nav"](), c["auth"])),
    "auth.logout": lambda c: _ok(c["dono"].post(f"{V}/logout", headers=H), 204),
    "auth.bloqueio": _bloqueio,
    "auth.mfa": lambda c: _mfa_login(c, ok=True),
    "auth.senha_trocada": _senha,
    "auth.recuperacao": _recuperacao,
    "auth.sessao_revogada": _sessao_revogada,
    "mfa.ativado": lambda c: ativar_mfa(c["dono"]),
    "mfa.desativado": _mfa_desativado,
    "mfa.codigo_recuperacao_usado": lambda c: _mfa_login(c, ok=True, recuperacao=True),
    "convite.criado": lambda c: convidar(c["dono"], "novo@ev.invalid"),
    "convite.revogado": lambda c: _ok(
        c["dono"].delete(f"{V}/convites/{convidar(c['dono'], 'r@ev.invalid')['convite_id']}", headers=H),
        204,
    ),
    "convite.aceito": _aceito,
    "membro.confirmado": _confirmado,
    "membro.suspenso": lambda c: _membro(c, "suspender"),
    "membro.reativado": lambda c: _membro(c, "reativar"),
    "membro.removido": lambda c: _membro(c, "remover"),
    "membro.papel_alterado": lambda c: _membro(c, "papel"),
    "politica.alterada": lambda c: _ok(
        c["dono"].put(f"{V}/org/politica", json={"mfa_obrigatorio": False, "inatividade_min": 30}, headers=H)
    ),
    "colecao.criada": lambda c: _ok(criar_colecao(c["dono"], [env(c["eu"])])[0], 201),
    "colecao.renomeada": lambda c: _ok(
        c["dono"].put(f"{V}/colecoes/{c['col']}", json={"chave_ver": 1, "nome_cif": env_v1()}, headers=H), 204
    ),
    "colecao.excluida": lambda c: _ok(
        c["dono"].delete(f"{V}/colecoes/{criar_colecao(c['dono'], [env(c['eu'])])[1]}", headers=H), 204
    ),
    "colecao.membro_adicionado": lambda c: _col_membro(c, "adicionar"),
    "colecao.permissao_alterada": lambda c: _col_membro(c, "permissao"),
    "colecao.membro_removido": lambda c: _col_membro(c, "remover"),
    "colecao.rotacao_iniciada": lambda c: _ok(c["dono"].get(f"{V}/colecoes/{c['col']}/rotacao")),
    "colecao.rotacionada": None,  # precisa do banco: ver o teste
    "item.criado": lambda c: _item(c["dono"], c["col"]),
    "item.editado": lambda c: _ok(editar(c["dono"], c["item"], 1)),
    "item.revelado": lambda c: _ok(c["dono"].get(f"{V}/itens/{c['item']}/segredo")),
    "item.versao_revelada": None,  # precisa de uma edição antes: ver o teste
    "item.copiado": lambda c: _ok(c["dono"].post(f"{V}/itens/{c['item']}/copiado", headers=H), 204),
    "item.excluido": lambda c: _lixo(c, "excluir"),
    "item.restaurado": lambda c: _lixo(c, "restaurar"),
    "item.purgado": lambda c: _lixo(c, "definitivo"),
    "org.criada": None,  # a CLI de bootstrap (fixture `org`) é a ação
    "requisicao.recusada": None,  # limite de corpo: ver o teste
}  # fmt: skip
# Eventos de bootstrap/CLI não têm requisição HTTP: sem ip/user_agent.
SEM_ORIGEM = {"org.criada"}


def test_todo_tipo_da_arquitetura_e_do_codigo_tem_acao():
    doc, codigo = tipos_da_arquitetura(), tipos_do_codigo()
    assert len(doc) >= 37
    assert doc - set(ACOES) == set(), "tipo de §5.6 sem ação neste teste"
    assert set(ACOES) - doc == set(), "ação para tipo fora de §5.6"
    assert codigo - doc == set(), "o código grava tipo que não está em §5.6"
    assert doc - codigo == set(), "tipo de §5.6 que o código nunca grava"


@pytest.mark.parametrize("tipo", sorted(ACOES))
def test_acao_gera_exatamente_um_evento_completo(tipo, ctx, banco, monkeypatch):
    antes = ler(banco, "SELECT coalesce(max(id), 0) FROM eventos")[0][0]
    if tipo == "colecao.rotacionada":
        _ok(
            ctx["dono"].post(
                f"{V}/colecoes/{ctx['col']}/rotacionar",
                json=corpo_rotacao(banco, ctx["col"]),
                headers=H,
            )
        )
    elif tipo == "item.versao_revelada":
        _ok(editar(ctx["dono"], ctx["item"], 1))
        antes = ler(banco, "SELECT max(id) FROM eventos")[0][0]
        _ok(ctx["dono"].get(f"{V}/itens/{ctx['item']}/versoes/1"))
    elif tipo == "org.criada":
        antes = 0  # gerado pela CLI (cli.criar_org) no fixture `org`
    elif tipo == "requisicao.recusada":
        _recusada(ctx, monkeypatch)
    else:
        ACOES[tipo](ctx)
    novos = ler(
        banco,
        """SELECT org_id, ator_id, host(ip), user_agent, resultado, alvo_tipo, alvo_id
           FROM eventos WHERE id > %s AND tipo = %s""",
        (antes, tipo),
    )
    assert len(novos) == 1, f"{tipo}: {len(novos)} eventos"
    org_id, ator, ip, ua, resultado, alvo_tipo, alvo_id = novos[0]
    assert org_id is not None and resultado in ("ok", "falha"), tipo
    if tipo not in SEM_ORIGEM:
        assert (ator is not None, ip, ua) == (True, IP, UA), tipo
