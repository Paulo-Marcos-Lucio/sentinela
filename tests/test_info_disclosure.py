"""Testes de exposição de informação (não-intrusiva)."""

from __future__ import annotations

from conftest import make_context, make_probe
from sentinela.checks.info_disclosure import InfoDisclosureChecker


def _run(headers=None, body=""):
    probe = make_probe(headers=headers or {}, body=body)
    return {f.id for f in InfoDisclosureChecker().run(make_context(primary=probe))}


def test_versao_servidor_exposta() -> None:
    assert "VERSAO_STACK_EXPOSTA" in _run(headers={"Server": "nginx/1.18.0"})


def test_x_powered_by_exposto() -> None:
    assert "VERSAO_STACK_EXPOSTA" in _run(headers={"X-Powered-By": "PHP/7.4.3"})


def test_server_generico_sem_versao_nao_gera_achado() -> None:
    assert _run(headers={"Server": "cloudflare"}) == set()


def test_listagem_diretorio() -> None:
    body = "<html><head><title>Index of /uploads</title></head><body>Index of /</body></html>"
    assert "LISTAGEM_DIRETORIO" in _run(body=body)
