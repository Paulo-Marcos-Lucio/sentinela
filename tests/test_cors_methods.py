"""Testes de CORS e métodos HTTP (usando cliente falso)."""

from __future__ import annotations

from conftest import FakeClient, make_context, make_probe
from sentinela.checks.cors import CorsChecker
from sentinela.checks.http_methods import HttpMethodsChecker


def test_cors_reflexao_com_credenciais() -> None:
    def handler(method, url, headers):
        origin = (headers or {}).get("Origin", "")
        return make_probe(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        )

    client = FakeClient(handler=handler)
    ctx = make_context(client=client)
    ids = {f.id for f in CorsChecker().run(ctx)}
    assert "CORS_REFLEXAO_COM_CREDENCIAIS" in ids


def test_cors_curinga_com_credenciais() -> None:
    # 2º ramo do checker: `*` + credentials. Sem este teste, apagar o ramo inteiro
    # deixava a suíte verde e a varredura devolvia "nada encontrado".
    client = FakeClient(
        default=make_probe(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )
    ids = {f.id for f in CorsChecker().run(make_context(client=client))}
    assert "CORS_CURINGA_COM_CREDENCIAIS" in ids


def test_cors_reflexao_sem_credenciais() -> None:
    # 3º ramo: reflete a origem, sem credenciais → LOW.
    def handler(method, url, headers):
        return make_probe(headers={"Access-Control-Allow-Origin": (headers or {}).get("Origin", "")})

    ids = {f.id for f in CorsChecker().run(make_context(client=FakeClient(handler=handler)))}
    assert ids == {"CORS_REFLEXAO_ORIGEM"}


def test_cors_curinga_sem_credenciais_nao_gera_achado() -> None:
    client = FakeClient(default=make_probe(headers={"Access-Control-Allow-Origin": "*"}))
    ids = {f.id for f in CorsChecker().run(make_context(client=client))}
    assert ids == set()


def test_cors_sem_header_nao_gera_achado() -> None:
    client = FakeClient(default=make_probe(headers={}))
    assert list(CorsChecker().run(make_context(client=client))) == []


def test_trace_habilitado() -> None:
    client = FakeClient(default=make_probe(headers={"Allow": "GET, POST, TRACE, OPTIONS"}))
    ids = {f.id for f in HttpMethodsChecker().run(make_context(client=client))}
    assert "HTTP_TRACE_HABILITADO" in ids


def test_metodos_perigosos() -> None:
    client = FakeClient(default=make_probe(headers={"Allow": "GET, PUT, DELETE"}))
    ids = {f.id for f in HttpMethodsChecker().run(make_context(client=client))}
    assert "HTTP_METODOS_PERIGOSOS" in ids


def test_metodos_seguros_nao_geram_achado() -> None:
    client = FakeClient(default=make_probe(headers={"Allow": "GET, POST, HEAD, OPTIONS"}))
    assert list(HttpMethodsChecker().run(make_context(client=client))) == []
