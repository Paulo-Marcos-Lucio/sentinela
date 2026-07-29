"""Testes de transporte (redirect) e exposição intrusiva de rotas."""

from __future__ import annotations

from conftest import FakeClient, make_context, make_probe, make_target
from sentinela.checks.exposure import ExposureChecker
from sentinela.checks.transport import TransportChecker
from sentinela.core.engine import _probe_http
from sentinela.core.scoring import compute_score


# --------------------------------------------------------------------------- #
# Alvo servido em texto aberto. Um site 100% HTTP com cabeçalhos impecáveis tirava
# 92/100 conceito A — o pior veredito que a ferramenta pode entregar a um cliente.
# --------------------------------------------------------------------------- #
def _http(final_url: str = "http://example.com/", **kwargs: object):
    probe = make_probe(final_url=final_url, **kwargs)  # type: ignore[arg-type]
    ctx = make_context(primary=probe, http_probe=probe, target=make_target(final_url))
    return list(TransportChecker().run(ctx))


def test_alvo_em_texto_aberto_gera_achado_alto() -> None:
    achados = _http()
    assert [f.id for f in achados] == ["SEM_HTTPS"]
    assert compute_score(achados).grade == "D"  # conceito tetado pela severidade alta


def test_sem_https_nao_empilha_com_sem_redirect_https() -> None:
    # Uma causa raiz, uma penalidade: 20 pts, não 20 + 8.
    assert sum(f.severity.weight for f in _http()) == 20


def test_alvo_http_que_redireciona_para_https_nao_gera_sem_https() -> None:
    probe = make_probe(final_url="https://example.com/")
    ctx = make_context(primary=probe, target=make_target("http://example.com/"))
    assert "SEM_HTTPS" not in {f.id for f in TransportChecker().run(ctx)}


def test_alvo_https_nunca_recebe_sem_https() -> None:
    probe = make_probe(final_url="https://example.com/")
    ctx = make_context(primary=probe, target=make_target("https://example.com/"))
    assert "SEM_HTTPS" not in {f.id for f in TransportChecker().run(ctx)}


def test_sonda_http_usa_a_porta_do_alvo_e_nao_a_80() -> None:
    # Contaminação cruzada: com a sonda cravada na porta 80, o veredito de transporte
    # de um app em :8123 era decidido por um serviço DIFERENTE na porta 80 do host.
    urls: list[str] = []

    class _Cliente:
        def request(self, method: str, url: str, **kwargs: object):
            urls.append(url)
            return make_probe(status=200, final_url=url)

    _probe_http(_Cliente(), make_target("http://127.0.0.1:8123/app"))  # type: ignore[arg-type]
    assert urls == ["http://127.0.0.1:8123/"]


def test_sonda_de_alvo_https_continua_na_porta_80() -> None:
    # Deliberado: a pergunta é "a versão em texto aberto deste host faz upgrade?" —
    # e o texto aberto mora na 80, mesmo que o alvo esteja em :8443.
    urls: list[str] = []

    class _Cliente:
        def request(self, method: str, url: str, **kwargs: object):
            urls.append(url)
            return make_probe(status=200, final_url=url)

    _probe_http(_Cliente(), make_target("https://exemplo.com:8443/app"))  # type: ignore[arg-type]
    assert urls == ["http://exemplo.com/"]


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


def test_exposure_apache_status_e_phpinfo() -> None:
    # Dois IDs do catálogo que não tinham nenhum caso positivo: os ramos podiam ser
    # apagados num refactor e a varredura devolveria "nada encontrado".
    corpos = {
        "/server-status": "<h1>Apache Server Status for exemplo.com</h1>",
        "/phpinfo.php": "<title>phpinfo()</title><h1>PHP Version 8.2.0</h1>",
    }

    def handler(method, url, headers):
        for caminho, corpo in corpos.items():
            if url.endswith(caminho):
                return make_probe(status=200, body=corpo)
        return make_probe(status=404)

    ids = {f.id for f in ExposureChecker().run(make_context(client=FakeClient(handler=handler)))}
    assert {"APACHE_STATUS_EXPOSTO", "PHPINFO_EXPOSTO"} <= ids


def test_exposure_status_e_phpinfo_com_conteudo_generico_nao_flagam() -> None:
    html = "<!doctype html><html><body>página comum do site</body></html>"
    client = FakeClient(default=make_probe(status=200, body=html))
    ids = {f.id for f in ExposureChecker().run(make_context(client=client))}
    assert "APACHE_STATUS_EXPOSTO" not in ids
    assert "PHPINFO_EXPOSTO" not in ids


def test_exposure_security_txt_ausente() -> None:
    client = FakeClient(default=make_probe(status=404))
    ids = {f.id for f in ExposureChecker().run(make_context(client=client))}
    assert "SECURITY_TXT_AUSENTE" in ids
