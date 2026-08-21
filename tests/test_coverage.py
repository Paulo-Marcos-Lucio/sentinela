"""Testes do bloco `coverage` do JSON (item `EV-05`).

Antes deste item, três situações diferentes convergiam no mesmo silêncio no
relatório: uma checagem que rodou e não achou nada, uma checagem que nem fazia
sentido rodar (TLS num alvo que só fala texto aberto) e uma resposta HTTP lida pela
metade por um teto de corpo. As três terminavam do mesmo jeito — ausência em
`findings` — e um laudo que não distingue "não achei nada" de "não consegui olhar"
lê a segunda leitura como a primeira.

A classe do defeito, não o exemplo: o teste de ponta a ponta usa um alvo `http://`
real (o cenário citado no `criterio_aceite`), mas a invariante provada é geral —
`ScanResult.checks_skipped`/`.truncations` chegam ao JSON completos e nunca
somem, mesmo vazios (mesma regra que já vale para `by_severity`).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sentinela.core.config import ScanConfig
from sentinela.core.engine import run_scan
from sentinela.core.models import CheckSkip, ScanResult, Target, Truncation
from sentinela.core.target import parse_target
from sentinela.report.json_report import render_json

_TARGET = Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")


class _ServidorHttpPuro(BaseHTTPRequestHandler):
    """Um `http.server` comum — a mesma classe de alvo que o job de autoauditoria do
    CI já sobe. Não fala TLS em porta nenhuma: é exatamente o alvo que o
    `criterio_aceite` de EV-05 descreve ("scan de alvo http://, sem TLS")."""

    def do_GET(self) -> None:  # noqa: N802 - assinatura da stdlib
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        corpo = b"<html><body>servidor http simples, sem TLS em lugar nenhum</body></html>"
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture()
def servidor_http_puro() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _ServidorHttpPuro)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        thread.join(timeout=2)


# --------------------------------------------------------------------------- #
# Ponta a ponta: o cenário literal do critério de aceite.
# --------------------------------------------------------------------------- #
def test_scan_de_alvo_http_declara_tls_pulado_em_vez_de_silencio(servidor_http_puro: str) -> None:
    target = parse_target(servidor_http_puro)
    resultado = run_scan(target, ScanConfig(only=frozenset({"tls"})))

    assert resultado.checks_run == ["tls"]  # a checagem RODOU...
    assert resultado.findings == []  # ...não achou achado nenhum...
    # ...e a razão está declarada, não presumida por quem lê um `findings` vazio.
    assert len(resultado.checks_skipped) == 1
    skip = resultado.checks_skipped[0]
    assert skip.check == "tls"
    assert "TLS" in skip.reason or "tls" in skip.reason.lower()

    dados = json.loads(render_json(resultado))
    assert dados["coverage"]["checks_skipped"] == [{"check": "tls", "reason": skip.reason}]


def test_scan_completo_pula_so_tls_as_demais_checagens_seguem_normais(servidor_http_puro: str) -> None:
    # Controle: numa varredura completa (todas as checagens, não só `only={"tls"}"`),
    # o skip aparece exatamente para `tls` — as outras doze checagens não são afetadas
    # pelo mecanismo novo, e a varredura como um todo continua produzindo achados.
    target = parse_target(servidor_http_puro)
    resultado = run_scan(target, ScanConfig())
    assert [s.check for s in resultado.checks_skipped] == ["tls"]
    assert "security-headers" in resultado.checks_run
    assert resultado.findings  # HSTS/CSP ausentes etc. continuam sendo reportados


# --------------------------------------------------------------------------- #
# Contrato JSON: a chave `coverage` nunca some, mesmo vazia — mesma regra que já
# vale para `by_severity`.
# --------------------------------------------------------------------------- #
def test_coverage_presente_e_vazio_num_relatorio_limpo() -> None:
    resultado = ScanResult(target=_TARGET, tool_version="0.1.0")
    dados = json.loads(render_json(resultado))
    assert dados["coverage"] == {"checks_skipped": [], "truncations": []}


def test_coverage_serializa_skips_e_truncagens() -> None:
    resultado = ScanResult(target=_TARGET, tool_version="0.1.0")
    resultado.checks_skipped.append(CheckSkip(check="tls", reason="sem endpoint TLS"))
    resultado.truncations.append(Truncation(url="https://alvo.com/grande", limit_bytes=4096))
    dados = json.loads(render_json(resultado))
    assert dados["coverage"] == {
        "checks_skipped": [{"check": "tls", "reason": "sem endpoint TLS"}],
        "truncations": [{"url": "https://alvo.com/grande", "limit_bytes": 4096}],
    }


# --------------------------------------------------------------------------- #
# `ScanContext.skipped` é compartilhado por todas as checagens de UMA varredura —
# o motor só o lê depois que a pool de threads termina.
# --------------------------------------------------------------------------- #
def test_engine_copia_skips_e_truncagens_do_contexto_e_do_cliente(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentinela.core.engine as engine
    from conftest import make_probe

    registrados: list[Truncation] = [Truncation(url="https://x/", limit_bytes=99)]

    class _HttpClientFalso:
        def __init__(self, **_kw: object) -> None:
            self.truncations = registrados

        def __enter__(self) -> _HttpClientFalso:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def get(self, url: str, **_kw: object):  # type: ignore[no-untyped-def]
            return make_probe(headers={})

        def request(self, method: str, url: str, **_kw: object):  # type: ignore[no-untyped-def]
            return make_probe(status=404, final_url=url)

        def close(self) -> None:
            return None

    monkeypatch.setattr(engine, "HttpClient", _HttpClientFalso)
    target = parse_target("https://example.com/")
    resultado = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert resultado.truncations == registrados


def test_engine_tolera_cliente_sem_contabilidade_de_truncagem(monkeypatch: pytest.MonkeyPatch) -> None:
    """Um cliente falso mínimo (o padrão dos testes de motor existentes) não tem
    `.truncations` — o motor não pode quebrar por isso, só reportar vazio."""
    import sentinela.core.engine as engine
    from conftest import make_probe

    class _HttpClientMinimo:
        def __init__(self, **_kw: object) -> None:
            pass

        def __enter__(self) -> _HttpClientMinimo:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def get(self, url: str, **_kw: object):  # type: ignore[no-untyped-def]
            return make_probe(headers={})

        def request(self, method: str, url: str, **_kw: object):  # type: ignore[no-untyped-def]
            return make_probe(status=404, final_url=url)

        def close(self) -> None:
            return None

    monkeypatch.setattr(engine, "HttpClient", _HttpClientMinimo)
    target = parse_target("https://example.com/")
    resultado = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert resultado.truncations == []
