"""Testes property-based (Hypothesis) das INVARIANTES da defesa anti-SSRF.

O bug de classe aqui foi de normalização: `::ffff:100.64.0.1` é o MESMO host que
`100.64.0.1`, escrito de outro jeito, e passava batido — um bypass de SSRF. Os testes
por exemplo cobrem os endereços que alguém listou; estes geram milhares e afirmam as
propriedades que não podem falhar, para essa classe nunca reabrir em silêncio:

    1. todo endereço de faixa reservada/interna/CGNAT é bloqueado;
    2. `::ffff:X` bloqueia se e somente se `X` bloqueia (normalização — a classe do bypass).
"""

from __future__ import annotations

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from sentinela.core.http import _ip_blocked

# Faixas que JAMAIS podem ser alvo de uma requisição de varredura (SSRF).
_FAIXAS_PERIGOSAS = [
    ipaddress.ip_network(c)
    for c in (
        "127.0.0.0/8",  # loopback
        "10.0.0.0/8",  # privada
        "172.16.0.0/12",  # privada
        "192.168.0.0/16",  # privada
        "169.254.0.0/16",  # link-local (inclui 169.254.169.254 — metadados de nuvem)
        "100.64.0.0/10",  # CGNAT (inclui 100.100.100.100 — metadados Alibaba)
        "198.18.0.0/15",  # benchmarking
        "0.0.0.0/8",  # "this host"
    )
]


@st.composite
def _host_em_faixa_perigosa(draw: st.DrawFn) -> ipaddress.IPv4Address:
    rede = draw(st.sampled_from(_FAIXAS_PERIGOSAS))
    offset = draw(st.integers(min_value=0, max_value=rede.num_addresses - 1))
    return ipaddress.ip_address(int(rede.network_address) + offset)


@settings(max_examples=400)
@given(ip=_host_em_faixa_perigosa())
def test_faixa_reservada_sempre_bloqueada(ip: ipaddress.IPv4Address) -> None:
    """INVARIANTE 1: qualquer endereço de faixa interna/não-roteável é bloqueado."""
    assert _ip_blocked(ip) is True, f"faixa perigosa não bloqueada: {ip}"


@settings(max_examples=400)
@given(ip=st.ip_addresses(v=4))
def test_ipv4_mapeado_espelha_o_ipv4(ip: ipaddress.IPv4Address) -> None:
    """INVARIANTE 2 (a classe do bypass): `::ffff:X` decide igual a `X`."""
    mapeado = ipaddress.ip_address(f"::ffff:{ip}")
    assert _ip_blocked(mapeado) == _ip_blocked(ip), f"normalização divergiu para {ip}"
