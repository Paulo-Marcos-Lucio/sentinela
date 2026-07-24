"""Testes da leitura passiva de robots.txt."""

from __future__ import annotations

from conftest import FakeClient, make_context, make_probe, make_target
from sentinela.checks.well_known import WellKnownChecker


def _run(robots_body: str, status: int = 200) -> set[str]:
    def handler(method: str, url: str, headers: dict[str, str] | None):  # type: ignore[no-untyped-def]
        if url.endswith("/robots.txt"):
            return make_probe(body=robots_body, status=status, final_url=url)
        return None

    client = FakeClient(handler=handler)
    ctx = make_context(client=client, target=make_target("https://example.com/"))
    return {f.id for f in WellKnownChecker().run(ctx)}


def test_robots_sem_disallow_sensivel() -> None:
    body = "User-agent: *\nDisallow: /assets/\nDisallow: /cart\n"
    assert _run(body) == set()


def test_robots_com_caminho_sensivel() -> None:
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /public\n"
    assert "ROBOTS_CAMINHOS_SENSIVEIS" in _run(body)


def test_robots_ausente_nao_gera_achado() -> None:
    assert _run("Not found", status=404) == set()


def test_robots_html_e_ignorado() -> None:
    body = "<!doctype html><html><body>Disallow: /admin</body></html>"
    assert _run(body) == set()


def test_disallow_raiz_ignorado() -> None:
    assert _run("User-agent: *\nDisallow: /\n") == set()


def test_blog_nao_confunde_com_termo_sensivel() -> None:
    # 'log' não é termo sensível e a âncora de fronteira evita casar dentro de 'blog'
    assert _run("User-agent: *\nDisallow: /blog/\n") == set()
