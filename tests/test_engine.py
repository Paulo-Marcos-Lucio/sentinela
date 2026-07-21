"""Testes de orquestração do motor (com cliente HTTP falso, sem rede)."""

from __future__ import annotations

import pytest

import sentinela.core.engine as engine
from conftest import make_probe
from sentinela.core.config import ScanConfig
from sentinela.core.target import parse_target


class FakeHttpClient:
    def __init__(self, primary=None, **_kw) -> None:  # type: ignore[no-untyped-def]
        self._primary = primary if primary is not None else make_probe(headers={})

    def __enter__(self) -> FakeHttpClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        return self._primary

    def request(self, method: str, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        return make_probe(status=404, final_url=url)

    def close(self) -> None:
        return None


def test_engine_orquestra_e_marca_conclusao(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "HttpClient", FakeHttpClient)
    target = parse_target("https://example.com/")
    result = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert result.finished_at is not None
    assert result.checks_run == ["security-headers"]
    assert result.tool_version
    # example.com sem cabeçalhos de segurança deve gerar ao menos um achado
    assert result.findings


def test_engine_registra_erro_de_transporte(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_factory(**_kw: object) -> FakeHttpClient:
        return FakeHttpClient(primary=make_probe(error="ConnectError", status=0))

    monkeypatch.setattr(engine, "HttpClient", fake_factory)
    target = parse_target("https://example.com/")
    result = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert any(e.check_id == "http" for e in result.errors)
