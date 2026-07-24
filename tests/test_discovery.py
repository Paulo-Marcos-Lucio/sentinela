"""Testes dos parsers de Certificate Transparency (Cert Spotter e crt.sh)."""

from __future__ import annotations

import json

from sentinela.core.discovery import _parse_certspotter, _parse_crtsh


def test_crtsh_dedupe_e_filtra_dominio() -> None:
    raw = json.dumps(
        [
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "other.org"},
        ]
    )
    out = _parse_crtsh(raw, "example.com")
    assert out is not None
    assert "www.example.com" in out
    assert "api.example.com" in out
    assert "example.com" in out  # apex (a partir do curinga) é incluído
    assert "other.org" not in out
    assert all("*" not in n for n in out)  # curingas são removidos
    assert out == sorted(set(out))  # dedupe + ordenado


def test_certspotter_extrai_dns_names() -> None:
    raw = json.dumps(
        [
            {"dns_names": ["*.example.com", "app.example.com"]},
            {"dns_names": ["api.example.com", "unrelated.net"]},
        ]
    )
    out = _parse_certspotter(raw, "example.com")
    assert out is not None
    assert "app.example.com" in out
    assert "api.example.com" in out
    assert "example.com" in out
    assert "unrelated.net" not in out


def test_json_invalido_e_inconclusivo() -> None:
    assert _parse_crtsh("{truncado", "example.com") is None
    assert _parse_certspotter("{truncado", "example.com") is None


def test_json_nao_lista_e_inconclusivo() -> None:
    assert _parse_crtsh(json.dumps({"erro": "x"}), "example.com") is None
    assert _parse_certspotter(json.dumps({"erro": "x"}), "example.com") is None
