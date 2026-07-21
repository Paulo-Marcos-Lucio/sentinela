"""Testes da normalização de alvo."""

from __future__ import annotations

import pytest

from sentinela.core.target import parse_target


def test_dominio_simples_assume_https() -> None:
    t = parse_target("exemplo.com.br")
    assert t.scheme == "https"
    assert t.host == "exemplo.com.br"
    assert t.port == 443
    assert t.is_https


def test_url_http_com_porta() -> None:
    t = parse_target("http://localhost:8080/app")
    assert t.scheme == "http"
    assert t.host == "localhost"
    assert t.port == 8080
    assert not t.is_https


def test_host_normalizado_para_minusculo() -> None:
    assert parse_target("HTTPS://Exemplo.COM").host == "exemplo.com"


def test_origin_omite_porta_padrao() -> None:
    assert parse_target("https://exemplo.com").origin == "https://exemplo.com"
    assert parse_target("https://exemplo.com:8443").origin == "https://exemplo.com:8443"


@pytest.mark.parametrize("valor", ["", "   ", "ftp://exemplo.com", "http://"])
def test_entradas_invalidas(valor: str) -> None:
    with pytest.raises(ValueError):
        parse_target(valor)
