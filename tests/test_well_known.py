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


def test_curinga_de_extensao_nao_e_caminho_sensivel() -> None:
    # `Disallow: /*.sql$` é uma regra genérica de extensão, não um caminho concreto.
    # Sem a guarda de padrão, '.sql' casaria com o termo sensível 'sql' por coincidência
    # textual, mesmo sem existir nenhum endereço navegável ali.
    assert _run("User-agent: *\nDisallow: /*.sql$\n") == set()


def test_curinga_no_meio_do_caminho_tambem_e_ignorado() -> None:
    assert _run("User-agent: *\nDisallow: /admin/*.bak\n") == set()


def test_sqlite_nao_confunde_com_termo_sensivel_sql() -> None:
    # 'sql' precisa estar ancorado também à direita — sem isso, 'sqlite' (prefixo
    # textual 'sql' + 'ite') dispara o mesmo achado que um dump de banco de verdade.
    assert _run("User-agent: *\nDisallow: /sqlite/\n") == set()


def test_caminho_concreto_com_sql_ainda_e_sensivel() -> None:
    # A âncora de token não pode apagar o achado real: '/db/base.sql' é 'sql' como
    # token completo (entre separadores), não um prefixo de outra palavra.
    assert "ROBOTS_CAMINHOS_SENSIVEIS" in _run("User-agent: *\nDisallow: /db/base.sql\n")


def test_convencoes_publicas_de_framework_nao_sao_achado() -> None:
    # mail_password_form (Plone/Zope), user/password, changelog e install são
    # boilerplate de pilha — aparecem no robots.txt padrão de várias stacks e casam
    # com termo sensível ('password') só por coincidência lexical.
    body = (
        "User-agent: *\n"
        "Disallow: /mail_password_form\n"
        "Disallow: /user/password\n"
        "Disallow: /changelog\n"
        "Disallow: /install\n"
    )
    assert _run(body) == set()
