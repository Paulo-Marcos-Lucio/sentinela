"""Testes de transporte (redirect) e exposição intrusiva de rotas."""

from __future__ import annotations

from conftest import FakeClient, make_context, make_probe
from sentinela.checks.exposure import ExposureChecker
from sentinela.checks.transport import TransportChecker


def test_http_sem_redirect_https_gera_achado() -> None:
    http_probe = make_probe(status=200, final_url="http://example.com/")
    ids = {f.id for f in TransportChecker().run(make_context(http_probe=http_probe))}
    assert "SEM_REDIRECT_HTTPS" in ids


def test_http_com_redirect_https_ok() -> None:
    http_probe = make_probe(status=301, headers={"Location": "https://example.com/"})
    ids = {f.id for f in TransportChecker().run(make_context(http_probe=http_probe))}
    assert "SEM_REDIRECT_HTTPS" not in ids


def test_transport_sem_http_probe_nao_gera_achado() -> None:
    assert list(TransportChecker().run(make_context(http_probe=None))) == []


def test_exposure_git_detectado() -> None:
    def handler(method, url, headers):
        if url.endswith("/.git/HEAD"):
            return make_probe(status=200, body="ref: refs/heads/main\n")
        return make_probe(status=404)

    ids = {f.id for f in ExposureChecker().run(make_context(client=FakeClient(handler=handler)))}
    assert "GIT_EXPOSTO" in ids


def test_exposure_dotenv_detectado() -> None:
    def handler(method, url, headers):
        if url.endswith("/.env"):
            return make_probe(status=200, body="APP_KEY=secreto\nDB_PASSWORD=123\n")
        return make_probe(status=404)

    ids = {f.id for f in ExposureChecker().run(make_context(client=FakeClient(handler=handler)))}
    assert "DOTENV_EXPOSTO" in ids


def test_exposure_200_generico_nao_gera_falso_positivo() -> None:
    # SPA que devolve 200 + HTML para qualquer rota: a assinatura evita falso-positivo.
    html = "<!doctype html><html><body>app</body></html>"
    client = FakeClient(default=make_probe(status=200, body=html))
    ids = {f.id for f in ExposureChecker().run(make_context(client=client))}
    assert "GIT_EXPOSTO" not in ids
    assert "DOTENV_EXPOSTO" not in ids


def test_exposure_security_txt_ausente() -> None:
    client = FakeClient(default=make_probe(status=404))
    ids = {f.id for f in ExposureChecker().run(make_context(client=client))}
    assert "SECURITY_TXT_AUSENTE" in ids
