"""RF-I08 (listar/encerrar as próprias sessões) e GET /eu/eventos."""

from conftest import H, aceitar_e_logar, b64u, ler, login
from test_convites import convidar


def test_listar_e_encerrar_outra_sessao(cliente, owner, novo_cliente, banco):
    outra = novo_cliente()
    assert login(outra, owner["auth_hash"]).status_code == 200
    sessoes = cliente.get("/api/v1/eu/sessoes").json()
    assert len(sessoes) == 2
    assert {"id", "criada_em", "ultimo_uso", "ip", "user_agent", "atual"} == set(sessoes[0])
    atual = [s for s in sessoes if s["atual"]]
    alvo = [s for s in sessoes if not s["atual"]]
    assert len(atual) == len(alvo) == 1

    assert cliente.delete(f"/api/v1/eu/sessoes/{alvo[0]['id']}", headers=H).status_code == 204
    assert outra.get("/api/v1/eu").status_code == 401  # a outra caiu
    assert cliente.get("/api/v1/eu").status_code == 200
    r = cliente.delete(f"/api/v1/eu/sessoes/{alvo[0]['id']}", headers=H)
    assert (r.status_code, r.json()) == (404, {"erro": "nao_encontrado"})
    assert [s["id"] for s in cliente.get("/api/v1/eu/sessoes").json()] == [atual[0]["id"]]
    assert ler(banco, "SELECT count(*) FROM eventos WHERE tipo = 'auth.sessao_revogada'") == [(1,)]


def test_nao_encerra_sessao_de_outro_usuario(cliente, owner, novo_cliente):
    convite = convidar(cliente, "m@t.invalid")
    member = novo_cliente()
    aceitar_e_logar(member, convite["token"], "m@t.invalid")
    (dele,) = member.get("/api/v1/eu/sessoes").json()
    assert cliente.delete(f"/api/v1/eu/sessoes/{dele['id']}", headers=H).status_code == 404
    assert member.get("/api/v1/eu").status_code == 200


def test_eventos_proprios_auth_paginados(cliente, owner, novo_cliente):
    login(novo_cliente(), b64u(32))  # falha na própria conta
    convidar(cliente, "m@t.invalid")  # convite.criado: não é auth.*
    eventos = cliente.get("/api/v1/eu/eventos").json()
    tipos = [e["tipo"] for e in eventos]
    assert tipos == ["auth.login", "auth.login"]  # mais novo primeiro
    assert [e["resultado"] for e in eventos] == ["falha", "ok"]
    assert set(eventos[0]) == {"id", "em", "tipo", "resultado", "ip", "user_agent"}
    pagina = cliente.get("/api/v1/eu/eventos", params={"limite": 1}).json()
    assert [e["id"] for e in pagina] == [eventos[0]["id"]]
    resto = cliente.get(
        "/api/v1/eu/eventos", params={"limite": 1, "antes_de_id": pagina[-1]["id"]}
    ).json()
    assert [e["id"] for e in resto] == [eventos[1]["id"]]
    assert cliente.get("/api/v1/eu/eventos", params={"limite": 201}).status_code == 422


def test_rotas_de_conta_exigem_sessao(cliente):
    assert cliente.get("/api/v1/eu/sessoes").status_code == 401
    assert cliente.get("/api/v1/eu/eventos").status_code == 401
