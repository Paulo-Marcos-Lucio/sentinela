"""Exfiltração de dados em rotas sensíveis, e a sondagem do mapa que o alvo entrega.

O buraco que estes testes travam: o ``well-known`` lia o ``robots.txt`` para AVISAR
que ele lista área sensível, e o ``exposure`` sondava seis palpites fixos — os dois
lados nunca se falavam. O alvo publicava ``Disallow: /backup/`` e a ferramenta
arquivava o aviso sem nunca ir lá.

A invariante que sustenta a mudança inteira: **status não é achado, corpo é**. Sem
ela, sondar caminho revelado encheria o laudo de falso positivo (todo ``/admin/``
responde 200 com uma tela de login) e derrubaria a credibilidade do resto.
"""

from __future__ import annotations

from conftest import FakeClient, make_context, make_probe, make_target
from sentinela.checks.exposure import ExposureChecker
from sentinela.core import disclosure

ROBOTS = "robots.txt"
SITEMAP = "sitemap.xml"


def _servidor(rotas: dict[str, str], *, status: dict[str, int] | None = None):
    """Cliente falso servindo um mapa caminho→corpo. O que não estiver no mapa dá 404."""
    status = status or {}

    def handler(method: str, url: str, headers: dict[str, str] | None):
        caminho = url.split("example.com", 1)[-1] or "/"
        if caminho in rotas:
            return make_probe(status=status.get(caminho, 200), body=rotas[caminho], final_url=url)
        return make_probe(status=404, body="não encontrado", final_url=url)

    return FakeClient(handler=handler)


def _rodar(rotas: dict[str, str], **kw):
    cliente = _servidor(rotas, **kw)
    ctx = make_context(client=cliente, target=make_target("https://example.com/"))
    return list(ExposureChecker().run(ctx)), cliente


def _coletar(rotas: dict[str, str]):
    cliente = _servidor(rotas)
    ctx = make_context(client=cliente, target=make_target("https://example.com/"))
    return disclosure.coletar(ctx)


# --------------------------------------------------------------------------- #
# O mapa que o alvo entrega
# --------------------------------------------------------------------------- #
def test_robots_e_sitemap_viram_caminhos_revelados() -> None:
    d = _coletar(
        {
            "/robots.txt": "User-agent: *\nDisallow: /backup/\nDisallow: /admin/\n",
            "/sitemap.xml": "<urlset><url><loc>https://example.com/dump/base.sql</loc></url></urlset>",
        }
    )
    assert d.robots_lido and d.sitemap_lido
    assert "/backup/" in d.caminhos
    assert "/admin/" in d.caminhos
    assert "/dump/base.sql" in d.caminhos


def test_curinga_vira_o_prefixo_literal_e_nao_o_asterisco() -> None:
    # `Disallow: /admin/*.bak$` não é um endereço: requisitar o `*` literal só gera 404.
    d = _coletar({"/robots.txt": "Disallow: /admin/*.bak$\n"})
    assert d.caminhos == ("/admin/",)


def test_barra_sozinha_nao_vira_caminho_sondavel() -> None:
    # `Disallow: /` é o site inteiro — já é a resposta primária, não acrescenta superfície.
    d = _coletar({"/robots.txt": "Disallow: /\nDisallow: *\n"})
    assert d.caminhos == ()


def test_sitemap_de_outro_host_e_descartado_e_reportado() -> None:
    # O escopo da autorização é o ALVO. Sondar host de terceiro a partir do mapa dele
    # seria o erro mais caro que esta ferramenta pode cometer.
    d = _coletar(
        {
            "/robots.txt": "Disallow: /admin/\n",
            "/sitemap.xml": (
                "<urlset>"
                "<url><loc>https://cdn-de-terceiro.net/backup/base.sql</loc></url>"
                "<url><loc>https://example.com/config/app.json</loc></url>"
                "</urlset>"
            ),
        }
    )
    assert "/backup/base.sql" not in d.caminhos
    assert "/config/app.json" in d.caminhos
    assert "cdn-de-terceiro.net" in d.origens_externas


def test_caminho_repetido_aparece_uma_vez_so_e_na_ordem_revelada() -> None:
    d = _coletar({"/robots.txt": "Disallow: /admin/\nDisallow: /backup/\nDisallow: /admin/\n"})
    assert d.caminhos == ("/admin/", "/backup/")


def test_teto_de_revelados_declara_quanto_cortou() -> None:
    linhas = "".join(f"Disallow: /admin/{i}/\n" for i in range(60))
    d = _coletar({"/robots.txt": linhas})
    assert len(d.caminhos) == disclosure.TETO_REVELADOS
    assert d.truncado_em == 60 - disclosure.TETO_REVELADOS


def test_robots_em_html_nao_e_robots() -> None:
    # Catch-all de SPA devolve 200 + HTML para qualquer caminho.
    d = _coletar({"/robots.txt": "<!doctype html><html><body>página inicial</body></html>"})
    assert not d.robots_lido and d.caminhos == ()


def test_aviso_passivo_e_conservador_e_a_sondagem_e_ampla() -> None:
    # `/cliente/` é rota pública legítima em metade dos sites: não pode virar achado
    # passivo. Mas na sondagem autorizada ela é segura, porque lá quem decide é o corpo.
    d = _coletar({"/robots.txt": "Disallow: /cliente/\nDisallow: /admin/\n"})
    assert "/cliente/" not in d.sensiveis
    assert "/admin/" in d.sensiveis
    assert "/cliente/" in d.sondaveis
    assert set(d.sensiveis) <= set(d.sondaveis)


# --------------------------------------------------------------------------- #
# A invariante central: status não é achado, corpo é
# --------------------------------------------------------------------------- #
def test_rota_revelada_com_tela_de_login_nao_gera_achado() -> None:
    achados, _ = _rodar(
        {
            "/robots.txt": "Disallow: /admin/\n",
            "/admin/": "<!doctype html><html><body><form>Entrar</form></body></html>",
        }
    )
    assert [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"] == []


def test_rota_revelada_com_dump_sql_gera_achado_critico() -> None:
    achados, _ = _rodar(
        {
            "/robots.txt": "Disallow: /backup/base.sql\n",
            "/backup/base.sql": (
                "-- MySQL dump 10.13\nCREATE TABLE clientes (id INT, cpf VARCHAR(14));\n"
                "INSERT INTO clientes VALUES (1,'000.000.000-00');"
            ),
        }
    )
    exf = [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"]
    assert len(exf) == 1
    assert exf[0].severity.name == "CRITICAL"
    assert "dump de banco" in exf[0].title
    # O laudo precisa dizer que a pista veio do próprio alvo — é o que torna o achado
    # defensável numa conversa com o cliente.
    assert "revelado pelo próprio alvo" in exf[0].description


def test_heapdump_do_actuator_e_critico() -> None:
    achados, _ = _rodar({"/actuator/heapdump": "JAVA PROFILE 1.0.2\x00...binário..."})
    exf = [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"]
    assert len(exf) == 1 and exf[0].severity.name == "CRITICAL"
    assert "ANPD" in exf[0].impact or "ANPD" in exf[0].recommendation


def test_actuator_env_do_spring_e_alto() -> None:
    achados, _ = _rodar({"/actuator/env": '{"activeProfiles":["prod"],"propertySources":[]}'})
    exf = [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"]
    assert len(exf) == 1 and exf[0].severity.name == "HIGH"


def test_chave_privada_exposta_e_critica() -> None:
    achados, _ = _rodar({"/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"})
    assert [f.severity.name for f in achados if f.id == "EXFILTRACAO_DE_DADOS"] == ["CRITICAL"]


def test_json_de_configuracao_generico_nao_dispara_sozinho() -> None:
    # Um `/config.json` de front-end (tema, locale) NÃO é exfiltração. Sem esta guarda,
    # toda SPA do mundo viraria achado crítico.
    achados, _ = _rodar({"/config.json": '{"tema":"escuro","idioma":"pt-BR"}'})
    assert [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"] == []


def test_resposta_vazia_em_200_nao_e_achado() -> None:
    achados, _ = _rodar({"/backup.sql": "   "})
    assert [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"] == []


def test_status_404_nunca_vira_achado_mesmo_com_corpo_sensivel() -> None:
    achados, _ = _rodar(
        {"/backup.sql": "CREATE TABLE x (id INT);"},
        status={"/backup.sql": 404},
    )
    assert [f for f in achados if f.id == "EXFILTRACAO_DE_DADOS"] == []


# --------------------------------------------------------------------------- #
# Escopo e honestidade da cobertura
# --------------------------------------------------------------------------- #
def test_sondagem_nunca_sai_da_origem_do_alvo() -> None:
    _, cliente = _rodar(
        {
            "/robots.txt": "Disallow: /admin/\n",
            "/sitemap.xml": "<urlset><url><loc>https://outro-host.example.org/dump.sql</loc></url></urlset>",
        }
    )
    fora = [url for _m, url, _h in cliente.calls if not url.startswith("https://example.com/")]
    assert fora == [], f"a sondagem saiu do escopo autorizado: {fora}"


def test_truncamento_da_sondagem_e_declarado_nunca_silencioso() -> None:
    # Ausência de achado tem de ser distinguível de ausência de medição.
    linhas = "".join(f"Disallow: /admin/{i}/\n" for i in range(200))
    achados, _ = _rodar({"/robots.txt": linhas})
    truncados = [f for f in achados if f.id == "SONDAGEM_TRUNCADA"]
    assert len(truncados) == 1
    assert "SEM VEREDICTO" in truncados[0].impact


def test_sem_robots_nem_sitemap_a_checagem_segue_funcionando() -> None:
    # Regressão: a leitura do mapa não pode derrubar a sondagem da lista fixa.
    achados, _ = _rodar({"/.git/HEAD": "ref: refs/heads/main"})
    assert "GIT_EXPOSTO" in {f.id for f in achados}
