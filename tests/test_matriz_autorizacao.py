"""Fase 8 — matriz de autorização completa (RF-O02/O03/O04, RF-A06): TODA rota de /api/v1 ×
ator → status esperado, e um teste de completude que falha se o app ganhar rota fora da tabela.

Atores: anônimo; `aceito` (aceitou o convite, fingerprint ainda não conferido); `member` sem
envelope na coleção; members com cada permissão da coleção (`vsr` = ver_sem_revelar, `ver`,
`editar`, `gerenciar`); `admin` (sem envelope); `owner` (gerencia tudo, D13).

Cada linha faz a requisição real: quem pode recebe o sucesso (com alvo novo quando a rota muda
estado), quem não pode recebe 401/403/404 com o código do erro.
"""

import itertools

import pytest
from conftest import H, aceitar_e_logar, ativar, b64u, convidar, env_v1, payload_aceite
from fastapi.openapi.utils import get_openapi
from test_cofre import criar_colecao, criar_item, editar, env, x1
from test_compartilhar import corpo_rotacao, envelopes_owner

from app import limites, seguranca

V = "/api/v1"
ATORES = ("anon", "aceito", "member", "vsr", "ver", "editar", "gerenciar", "admin", "owner")
NIVEIS = ["ver_sem_revelar", "ver", "editar", "gerenciar"]
# Permissão do ator nas coleções do mundo (None = sem envelope).
PERMISSAO = {"vsr": "ver_sem_revelar", "ver": "ver", "editar": "editar", "gerenciar": "gerenciar"}
PERMISSAO["owner"] = "gerenciar"

NAO_AUTENTICADO = (401, "nao_autenticado")
SEM_PERMISSAO = (403, "sem_permissao")
NAO_ENCONTRADO = (404, "nao_encontrado")


def esperado(regra, ator: str, ok: tuple) -> tuple:
    """Status/código esperado do `ator` numa rota com a `regra` de acesso."""
    if regra == "publica":
        return ok
    if ator == "anon":
        return NAO_AUTENTICADO
    if regra == "sessao":  # qualquer sessão, inclusive conta ainda não ativa
        return ok
    if ator == "aceito":
        return SEM_PERMISSAO
    if regra == "ativo":
        return ok
    if regra == "gestor":
        return ok if ator in ("admin", "owner") else SEM_PERMISSAO
    if regra == "owner":
        return ok if ator == "owner" else SEM_PERMISSAO
    _, minimo = regra  # ("colecao", permissão mínima)
    nivel = PERMISSAO.get(ator)
    if nivel is None:
        return NAO_ENCONTRADO  # sem envelope: nem a existência vaza
    return ok if NIVEIS.index(nivel) >= NIVEIS.index(minimo) else SEM_PERMISSAO


class Mundo:
    """Org com um usuário por ator, coleções C (geral), R (rotação) e fábricas de alvos novos.
    Tudo criado pelos fluxos reais da API, pelo `owner`."""

    def __init__(self, cliente, owner, novo_cliente, banco):
        self.dono, self.novo_cliente, self.banco = cliente, novo_cliente, banco
        self._n = itertools.count()
        self.ids = {"owner": owner["usuario_id"]}
        self.clientes = {"owner": cliente, "anon": novo_cliente()}
        for ator, papel in (("admin", "admin"), *((a, "member") for a in ATORES[2:7])):
            m = ativar(cliente, novo_cliente, f"{ator}@matriz.invalid", papel)
            self.ids[ator], self.clientes[ator] = m["id"], m["cliente"]
        conv = convidar(cliente, "aceito@matriz.invalid")
        self.clientes["aceito"] = novo_cliente()
        aceitar_e_logar(self.clientes["aceito"], conv["token"], "aceito@matriz.invalid")
        self.ids["aceito"] = conv["usuario_id"]
        self.C, self.R = self.colecao(), self.colecao()
        self.item_fixo = self.item(editado=True)
        self.alvo_col = self.ativo()  # membro de C cuja permissão a matriz troca
        self._post(f"/colecoes/{self.C}/membros", self._env_membro(self.alvo_col["id"]))
        self.convite_fixo = self.convite()
        self.compartilhado = self.ativo()  # alvo de quem NÃO pode (nada deve mudar nele)

    def email(self) -> str:
        return f"p{next(self._n)}@matriz.invalid"

    def _post(self, caminho, corpo=None, status=(200, 201, 204)):
        r = self.dono.post(V + caminho, json=corpo, headers=H)
        assert r.status_code in status, r.text
        return r

    def colecao(self) -> str:
        """Coleção do owner com cada member em sua permissão."""
        envs = [env(self.ids["owner"])]
        envs += [env(self.ids[a], p) for a, p in PERMISSAO.items() if a != "owner"]
        r, cid = criar_colecao(self.dono, envs)
        assert r.status_code == 201, r.text
        return cid

    def item(self, lixeira=False, editado=False) -> str:
        r, item = criar_item(self.dono, self.C)
        assert r.status_code == 201, r.text
        if editado:
            assert editar(self.dono, item["id"], 1).status_code == 200
        if lixeira:
            assert self.dono.delete(f"{V}/itens/{item['id']}", headers=H).status_code == 204
        return item["id"]

    def ativo(self, papel="member") -> dict:
        return ativar(self.dono, self.novo_cliente, self.email(), papel)

    def aceito(self) -> dict:
        conv, pub = convidar(self.dono, self.email()), b64u(32)
        aceite = payload_aceite(conv["token"], chave_publica=pub)
        assert self.novo_cliente().post(f"{V}/convites/aceitar", json=aceite).status_code == 201
        fp = seguranca.fingerprint(seguranca.de_b64u(pub))
        return {"id": conv["usuario_id"], "fingerprint": fp}

    def convite(self) -> dict:
        return convidar(self.dono, self.email())

    def suspenso(self) -> dict:
        m = self.ativo()
        self._post(f"/membros/{m['id']}/suspender")
        return m

    def _env_membro(self, uid, permissao="ver") -> dict:
        return {
            "usuario_id": uid,
            "permissao": permissao,
            "chave_ver": 1,
            "chave_colecao_cif": x1(),
        }

    def membro_de_c(self) -> str:
        m = self.ativo()
        self._post(f"/colecoes/{self.C}/membros", self._env_membro(m["id"]))
        return m["id"]


def _criar_colecao(c, w, ator):
    eu = w.ids.get(ator, w.ids["owner"])  # anônimo: corpo válido qualquer
    envs = [env(eu)] + ([env(w.ids["owner"])] if eu != w.ids["owner"] else [])
    return criar_colecao(c, envs)[0]


def _senha(c):
    corpo = {
        "auth_hash_atual": b64u(32),
        "kdf": payload_aceite("x")["kdf"],
        "sal": b64u(16),
        "auth_hash": b64u(32),
        "chave_usuario_cif": env_v1(),
    }
    return c.post(f"{V}/eu/senha", json=corpo, headers=H)


def _concluir(c):
    p = payload_aceite(b64u(32))
    campos = ("token", "kdf", "sal", "auth_hash", "chave_usuario_cif", "chave_usuario_recup_cif")
    corpo = {k: p[k] for k in (*campos, "recup_auth")}
    return c.post(f"{V}/recuperar/concluir", json=corpo, headers=H)


def _aceitar(c, w):
    return c.post(f"{V}/convites/aceitar", json=payload_aceite(w.convite()["token"]), headers=H)


def _promover(c, w, ator, pode):
    alvo = w.ativo() if pode else w.compartilhado
    corpo = {"papel": "owner", "envelopes": envelopes_owner(w.banco)}
    return c.put(f"{V}/membros/{alvo['id']}/papel", json=corpo, headers=H)


def _alvo(w, pode, fabrica, chave="id"):
    """Alvo novo para quem pode (a ação muda estado); o compartilhado para quem não pode."""
    return fabrica()[chave] if pode else w.compartilhado[chave]


# (método, caminho, regra, sucesso (status, código|None), chamada(cliente, mundo, ator, pode))
# A ordem importa no fim: promover a owner (um owner a mais exige envelope dele nas coleções
# criadas depois) e logout (derruba a sessão de cada ator) são as últimas.
TABELA = [
    # ---- públicas (§5.1): mesmo resultado com ou sem sessão ----
    ("POST", "/prelogin", "publica", (200, None),
     lambda c, w, a, p: c.post(f"{V}/prelogin", json={"email": "x@matriz.invalid"})),
    ("POST", "/convites/consultar", "publica", (200, None),
     lambda c, w, a, p: c.post(f"{V}/convites/consultar", json={"token": w.convite_fixo["token"]})),
    ("POST", "/convites/aceitar", "publica", (201, None), lambda c, w, a, p: _aceitar(c, w)),
    ("POST", "/login", "publica", (401, "credenciais_invalidas"),
     lambda c, w, a, p: c.post(f"{V}/login", json={"email": f"login-{a}@matriz.invalid", "auth_hash": b64u(32)})),
    ("POST", "/recuperar/iniciar", "publica", (401, "credenciais_invalidas"),
     lambda c, w, a, p: c.post(
         f"{V}/recuperar/iniciar", json={"email": f"rec-{a}@matriz.invalid", "recup_auth": b64u(32)})),
    ("POST", "/recuperar/concluir", "publica", (401, "token_invalido"), lambda c, w, a, p: _concluir(c)),
    # ---- própria conta (§5.2): qualquer sessão ----
    ("GET", "/eu", "sessao", (200, None), lambda c, w, a, p: c.get(f"{V}/eu")),
    ("GET", "/eu/sessoes", "sessao", (200, None), lambda c, w, a, p: c.get(f"{V}/eu/sessoes")),
    # Sessão de outro usuário (ou inexistente) = 404; o 401 do anônimo vem antes.
    ("DELETE", "/eu/sessoes/{sessao_id}", "sessao", NAO_ENCONTRADO,
     lambda c, w, a, p: c.delete(f"{V}/eu/sessoes/00000000-0000-0000-0000-000000000000", headers=H)),
    ("GET", "/eu/eventos", "sessao", (200, None), lambda c, w, a, p: c.get(f"{V}/eu/eventos")),
    ("POST", "/eu/senha", "sessao", (401, "credenciais_invalidas"), lambda c, w, a, p: _senha(c)),
    ("POST", "/eu/mfa/iniciar", "sessao", (200, None),
     lambda c, w, a, p: c.post(f"{V}/eu/mfa/iniciar", headers=H)),
    ("POST", "/eu/mfa/confirmar", "sessao", (401, "mfa_invalido"),
     lambda c, w, a, p: c.post(f"{V}/eu/mfa/confirmar", json={"codigo": "x"}, headers=H)),
    ("DELETE", "/eu/mfa", "sessao", (409, "mfa_inativo"),
     lambda c, w, a, p: c.request(
         "DELETE", f"{V}/eu/mfa", json={"auth_hash": b64u(32), "codigo": "x"}, headers=H)),
    # ---- organização (§5.3) ----
    ("GET", "/org", "ativo", (200, None), lambda c, w, a, p: c.get(f"{V}/org")),
    ("GET", "/membros", "ativo", (200, None), lambda c, w, a, p: c.get(f"{V}/membros")),
    ("PUT", "/org/politica", "gestor", (200, None),
     lambda c, w, a, p: c.put(
         f"{V}/org/politica", json={"mfa_obrigatorio": False, "inatividade_min": 15}, headers=H)),
    ("POST", "/convites", "gestor", (201, None),
     lambda c, w, a, p: c.post(f"{V}/convites", json={"email": w.email(), "papel": "member"}, headers=H)),
    ("DELETE", "/convites/{convite_id}", "gestor", (204, None),
     lambda c, w, a, p: c.delete(
         f"{V}/convites/{w.convite()['convite_id'] if p else w.convite_fixo['convite_id']}", headers=H)),
    ("POST", "/membros/{alvo_id}/confirmar", "gestor", (200, None),
     lambda c, w, a, p: (lambda t: c.post(
         f"{V}/membros/{t['id']}/confirmar", json={"fingerprint": t["fingerprint"]}, headers=H))(
         w.aceito() if p else {"id": w.compartilhado["id"], "fingerprint": "0"})),
    ("POST", "/membros/{alvo_id}/suspender", "gestor", (200, None),
     lambda c, w, a, p: c.post(f"{V}/membros/{_alvo(w, p, w.ativo)}/suspender", headers=H)),
    ("POST", "/membros/{alvo_id}/reativar", "gestor", (200, None),
     lambda c, w, a, p: c.post(f"{V}/membros/{_alvo(w, p, w.suspenso)}/reativar", headers=H)),
    ("PUT", "/membros/{alvo_id}/papel", "gestor", (200, None),
     lambda c, w, a, p: c.put(f"{V}/membros/{_alvo(w, p, w.ativo)}/papel", json={"papel": "admin"}, headers=H)),
    ("DELETE", "/membros/{alvo_id}", "gestor", (200, None),
     lambda c, w, a, p: c.delete(f"{V}/membros/{_alvo(w, p, w.ativo)}", headers=H)),
    # ---- auditoria (§5.5) ----
    ("GET", "/auditoria", "gestor", (200, None), lambda c, w, a, p: c.get(f"{V}/auditoria")),
    # ---- coleções e itens (§5.4) ----
    ("GET", "/sync", "ativo", (200, None), lambda c, w, a, p: c.get(f"{V}/sync")),
    ("POST", "/colecoes", "ativo", (201, None), lambda c, w, a, p: _criar_colecao(c, w, a)),
    ("PUT", "/colecoes/{colecao_id}", ("colecao", "gerenciar"), (204, None),
     lambda c, w, a, p: c.put(f"{V}/colecoes/{w.C}", json={"chave_ver": 1, "nome_cif": env_v1()}, headers=H)),
    ("DELETE", "/colecoes/{colecao_id}", ("colecao", "gerenciar"), (204, None),
     lambda c, w, a, p: c.delete(f"{V}/colecoes/{w.colecao() if p else w.R}", headers=H)),
    ("GET", "/colecoes/{colecao_id}/membros", ("colecao", "gerenciar"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/colecoes/{w.C}/membros")),
    ("POST", "/colecoes/{colecao_id}/membros", ("colecao", "gerenciar"), (201, None),
     lambda c, w, a, p: c.post(
         f"{V}/colecoes/{w.C}/membros", json=w._env_membro(_alvo(w, p, w.ativo)), headers=H)),
    ("PUT", "/colecoes/{colecao_id}/membros/{usuario_id}", ("colecao", "gerenciar"), (200, None),
     lambda c, w, a, p: c.put(
         f"{V}/colecoes/{w.C}/membros/{w.alvo_col['id']}", json={"permissao": "editar"}, headers=H)),
    ("DELETE", "/colecoes/{colecao_id}/membros/{usuario_id}", ("colecao", "gerenciar"), (204, None),
     lambda c, w, a, p: c.delete(
         f"{V}/colecoes/{w.C}/membros/{w.membro_de_c() if p else w.alvo_col['id']}", headers=H)),
    ("GET", "/colecoes/{colecao_id}/rotacao", ("colecao", "gerenciar"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/colecoes/{w.R}/rotacao")),
    ("POST", "/colecoes/{colecao_id}/rotacionar", ("colecao", "gerenciar"), (200, None),
     lambda c, w, a, p: c.post(f"{V}/colecoes/{w.R}/rotacionar", json=corpo_rotacao(w.banco, w.R), headers=H)),
    ("POST", "/colecoes/{colecao_id}/itens", ("colecao", "editar"), (201, None),
     lambda c, w, a, p: criar_item(c, w.C)[0]),
    ("GET", "/colecoes/{colecao_id}/lixeira", ("colecao", "editar"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/colecoes/{w.C}/lixeira")),
    ("PUT", "/itens/{item_id}", ("colecao", "editar"), (200, None),
     lambda c, w, a, p: editar(c, w.item() if p else w.item_fixo, 1 if p else 2)),
    ("DELETE", "/itens/{item_id}", ("colecao", "editar"), (204, None),
     lambda c, w, a, p: c.delete(f"{V}/itens/{w.item() if p else w.item_fixo}", headers=H)),
    ("POST", "/itens/{item_id}/restaurar", ("colecao", "editar"), (204, None),
     lambda c, w, a, p: c.post(f"{V}/itens/{w.item(lixeira=True)}/restaurar", headers=H)),
    ("DELETE", "/itens/{item_id}/definitivo", ("colecao", "gerenciar"), (204, None),
     lambda c, w, a, p: c.delete(f"{V}/itens/{w.item(lixeira=True)}/definitivo", headers=H)),
    ("GET", "/itens/{item_id}/segredo", ("colecao", "ver"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/itens/{w.item_fixo}/segredo")),
    ("POST", "/itens/{item_id}/copiado", ("colecao", "ver"), (204, None),
     lambda c, w, a, p: c.post(f"{V}/itens/{w.item_fixo}/copiado", headers=H)),
    ("GET", "/itens/{item_id}/versoes", ("colecao", "ver"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/itens/{w.item_fixo}/versoes")),
    ("GET", "/itens/{item_id}/versoes/{versao}", ("colecao", "ver"), (200, None),
     lambda c, w, a, p: c.get(f"{V}/itens/{w.item_fixo}/versoes/1")),
    # ---- por último ----
    # Promover a owner: só owner (admin e member recebem 403 antes de olhar os envelopes).
    ("PUT", "/membros/{alvo_id}/papel", "owner", (200, None), _promover),
    ("POST", "/logout", "sessao", (204, None), lambda c, w, a, p: c.post(f"{V}/logout", headers=H)),
]  # fmt: skip


def _rotas_do_app() -> set:
    from app.main import app

    caminhos = get_openapi(title="cofre", version="v1", routes=app.routes)["paths"]
    return {
        (metodo.upper(), caminho.removeprefix(V))
        for caminho, ops in caminhos.items()
        if caminho.startswith(V + "/")
        for metodo in ops
    }


def test_tabela_cobre_todas_as_rotas_do_app(cliente):
    """Completude: rota nova em /api/v1 sem linha na matriz faz este teste falhar."""
    tabela = {(m, c) for m, c, *_ in TABELA}
    rotas = _rotas_do_app()
    assert rotas - tabela == set(), "rota do app sem linha na matriz de autorização"
    assert tabela - rotas == set(), "linha da matriz para rota que não existe"
    assert len(rotas) >= 46


def test_matriz_de_autorizacao(cliente, owner, novo_cliente, banco, monkeypatch):
    # Centenas de requisições de um "IP" só: o limite por IP é testado em test_limites.py.
    monkeypatch.setattr(limites, "IP_MAX", 10**6)
    w = Mundo(cliente, owner, novo_cliente, banco)
    falhas, total = [], 0
    for metodo, caminho, regra, ok, chamar in TABELA:
        for ator in ATORES:
            alvo = esperado(regra, ator, ok)
            r = chamar(w.clientes[ator], w, ator, alvo == ok)
            erro = r.json().get("erro") if alvo[1] is not None and r.content else None
            obtido = (r.status_code, erro)
            total += 1
            if obtido != alvo:
                falhas.append(
                    f"{metodo} {caminho} [{ator}]: esperado {alvo}, veio {obtido} {r.text[:120]}"
                )
    assert falhas == [], "\n".join(falhas)
    assert total == len(TABELA) * len(ATORES)


@pytest.mark.parametrize(
    ("regra", "ator", "esperado_"),
    [
        (("colecao", "ver"), "vsr", SEM_PERMISSAO),
        (("colecao", "ver"), "admin", NAO_ENCONTRADO),
        ("gestor", "aceito", SEM_PERMISSAO),
        ("owner", "admin", SEM_PERMISSAO),
        ("publica", "anon", (200, None)),
    ],
)
def test_regra_de_esperado(regra, ator, esperado_):
    assert esperado(regra, ator, (200, None)) == esperado_
