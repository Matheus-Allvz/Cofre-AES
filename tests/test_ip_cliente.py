"""Fase 9 — IP do cliente: CF-Connecting-IP só vale vindo do proxy local (Caddy no host);
de qualquer outro peer o header é ignorado e vale o IP da conexão."""

import pytest
from starlette.requests import Request

from app import seguranca


def req(peer: str, **headers: str) -> Request:
    return Request(
        {
            "type": "http",
            "headers": [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()],
            "client": (peer, 50000),
        }
    )


@pytest.mark.parametrize("proxy", ["127.0.0.1", "::1"])
def test_cf_connecting_ip_do_proxy_local_vale(proxy):
    assert seguranca.origem(req(proxy, cf_connecting_ip="203.0.113.7"))["ip"] == "203.0.113.7"
    assert seguranca.origem(req(proxy, cf_connecting_ip="2001:db8::1"))["ip"] == "2001:db8::1"


def test_gateway_do_container_conta_como_proxy_local(monkeypatch):
    monkeypatch.setattr(seguranca, "PROXIES_LOCAIS", frozenset({"172.17.0.1"}))
    r = req("172.17.0.1", cf_connecting_ip="203.0.113.7")
    assert seguranca.origem(r)["ip"] == "203.0.113.7"


def test_header_forjado_de_peer_nao_local_e_ignorado():
    r = req("198.51.100.9", cf_connecting_ip="203.0.113.7", x_forwarded_for="203.0.113.8")
    assert seguranca.origem(r)["ip"] == "198.51.100.9"


@pytest.mark.parametrize("valor", ["", "lixo", "203.0.113.7, 10.0.0.1", "999.1.1.1"])
def test_header_invalido_do_proxy_cai_no_peer(valor):
    assert seguranca.origem(req("127.0.0.1", cf_connecting_ip=valor))["ip"] == "127.0.0.1"


def test_x_forwarded_for_nunca_e_usado():
    assert seguranca.origem(req("127.0.0.1", x_forwarded_for="203.0.113.8"))["ip"] == "127.0.0.1"


def test_gateway_padrao_le_proc_net_route(tmp_path):
    rota = tmp_path / "route"
    rota.write_text(
        "Iface\tDestination\tGateway\tFlags\n"
        "eth0\t000011AC\t00000000\t0001\n"
        "eth0\t00000000\t010011AC\t0003\n"
    )
    assert seguranca._gateway_padrao(str(rota)) == "172.17.0.1"
    assert seguranca._gateway_padrao(str(tmp_path / "nao-existe")) is None
