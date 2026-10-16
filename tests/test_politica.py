"""RF-P03 (inatividade_min na sessão do servidor) e RF-P07 (política por owner/admin, auditada)."""

import pytest
from conftest import EMAIL_OWNER, H, aceitar_e_logar, ativar, convidar, ler, politica

POLITICA = "/api/v1/org/politica"


def _membro_ativo(cliente, novo_cliente, email, papel):
    m = ativar(cliente, novo_cliente, email, papel)
    return m["cliente"], m["auth_hash"]


def test_get_org(cliente, owner):
    r = cliente.get("/api/v1/org")
    assert r.status_code == 200
    assert r.json() == {
        "id": owner["org_id"],
        "nome": "Org Teste",
        "politica": {"mfa_obrigatorio": False, "inatividade_min": 15},
    }


@pytest.mark.parametrize(
    "corpo",
    [
        {"mfa_obrigatorio": True, "inatividade_min": 4},
        {"mfa_obrigatorio": True, "inatividade_min": 61},
        {"mfa_obrigatorio": "true", "inatividade_min": 15},
        {"mfa_obrigatorio": True, "inatividade_min": 15.0},
        {"mfa_obrigatorio": True},
        {"mfa_obrigatorio": True, "inatividade_min": 15, "extra": 1},
    ],
    ids=["4", "61", "bool_texto", "float", "faltando", "extra"],
)
def test_politica_fora_de_faixa_422(cliente, owner, corpo):
    """DoD 5: inatividade_min 4 e 61 → 422."""
    assert cliente.put(POLITICA, json=corpo, headers=H).status_code == 422


def test_politica_member_403_admin_200_com_evento(cliente, owner, novo_cliente, banco):
    """DoD 5 / RF-P07: member → 403; admin → 200 e politica.alterada com antes/depois."""
    member, _ = _membro_ativo(cliente, novo_cliente, "m@t.invalid", "member")
    nova = {"mfa_obrigatorio": True, "inatividade_min": 30}
    r = member.put(POLITICA, json=nova, headers=H)
    assert (r.status_code, r.json()) == (403, {"erro": "sem_permissao"})
    assert member.get("/api/v1/org").status_code == 200  # member ativo lê

    admin, _ = _membro_ativo(cliente, novo_cliente, "a@t.invalid", "admin")
    r = admin.put(POLITICA, json=nova, headers=H)
    assert (r.status_code, r.json()) == (200, nova)
    ((meta, ator),) = ler(
        banco, "SELECT meta, ator_id::text FROM eventos WHERE tipo = 'politica.alterada'"
    )
    assert meta == {"antes": {"mfa_obrigatorio": False, "inatividade_min": 15}, "depois": nova}
    assert ler(banco, "SELECT id::text FROM usuarios WHERE email = 'a@t.invalid'") == [(ator,)]
    assert cliente.put(POLITICA, json=nova, headers={"X-Cofre": "0"}).status_code == 403


def test_aceito_nao_le_org(cliente, owner, novo_cliente):
    convite = convidar(cliente, "n@t.invalid")
    c = novo_cliente()
    aceitar_e_logar(c, convite["token"], "n@t.invalid")
    assert c.get("/api/v1/org").json() == {"erro": "sem_permissao"}


def test_ociosa_segue_inatividade_min(cliente, owner, relogio):
    """DoD 6 / RF-P03: sessão ociosa por inatividade_min + 1 min → 401."""
    nova = {"mfa_obrigatorio": False, "inatividade_min": 5}
    assert cliente.put(POLITICA, json=nova, headers=H).status_code == 200
    relogio.avancar(minutes=4, seconds=59)
    assert cliente.get("/api/v1/eu").status_code == 200  # renova
    relogio.avancar(minutes=6)
    assert cliente.get("/api/v1/eu").status_code == 401


def test_ociosa_maior_que_padrao(cliente, org, banco, relogio):
    politica(banco, mfa_obrigatorio=False, inatividade_min=60)
    aceitar_e_logar(cliente, org["token"], EMAIL_OWNER)
    relogio.avancar(minutes=59)
    assert cliente.get("/api/v1/eu").status_code == 200
    relogio.avancar(minutes=61)
    assert cliente.get("/api/v1/eu").status_code == 401


def test_migration_cria_politica_padrao(banco, org):
    """Fase 7 (decisão do usuário): MFA opcional por padrão, na org da CLI e no DEFAULT."""
    assert ler(banco, "SELECT mfa_obrigatorio, inatividade_min FROM politicas") == [(False, 15)]
    padrao = ler(
        banco,
        """SELECT column_default FROM information_schema.columns
           WHERE table_name = 'politicas' AND column_name = 'mfa_obrigatorio'""",
    )
    assert padrao == [("false",)]
