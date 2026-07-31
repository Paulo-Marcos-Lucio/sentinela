"""A regra que separa relatório confiável de relatório perigoso.

**Inconclusivo não é ausência.** Quando a varredura não consegue verificar alguma
coisa — corpo que veio pela metade, DNS que não respondeu, porta 80 inalcançável,
fonte de Certificate Transparency fora do ar, OpenSSL local que não fala TLS legado —
o relatório tem que DIZER isso. Antes, tudo virava silêncio, e silêncio num laudo lê
como aprovação.

O sintoma que motivou esta suíte: o mesmo alvo, no mesmo commit, saía com achados
diferentes conforme a rede, o resolvedor e o relógio da máquina que rodou a varredura.

Nenhum destes achados pesa na nota (severidade informativa): declarar um limite não
pode punir o alvo. Eles existem para o leitor saber o que NÃO foi verificado.
"""

from __future__ import annotations

import dns.exception
import pytest

from conftest import make_context, make_probe
from sentinela.checks import dns_email as dns_mod
from sentinela.checks.dns_email import DnsEmailChecker
from sentinela.checks.security_headers import SecurityHeadersChecker
from sentinela.checks.tls import TlsChecker
from sentinela.checks.transport import TransportChecker
from sentinela.core.http import Probe

HTML = "text/html; charset=utf-8"


# --------------------------------------------------------------------------- #
# Corpo truncado: a inversão de achado mais cara que existia
# --------------------------------------------------------------------------- #
_PAGINA_COM_CSP = (
    "<!doctype html><html><head>"
    + "<!-- enchimento -->" * 200
    + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">'
    + "</head><body></body></html>"
)

_SEM_POLITICA = {"Content-Type": HTML, "Strict-Transport-Security": "max-age=63072000; includeSubDomains"}


def _headers_ids(probe: Probe) -> set[str]:
    return {f.id for f in SecurityHeadersChecker().run(make_context(primary=probe))}


def test_corpo_completo_enxerga_a_csp_da_metatag() -> None:
    probe = make_probe(headers=_SEM_POLITICA, body=_PAGINA_COM_CSP)
    ids = _headers_ids(probe)
    assert "CSP_AUSENTE" not in ids
    assert "POLITICA_VIA_META" in ids


def test_corpo_truncado_nao_afirma_que_falta_csp() -> None:
    """Rede pior cortou o corpo antes da metatag. O achado NÃO pode virar
    "a resposta não define uma Content-Security-Policy" — isso seria falso."""
    cortado = _PAGINA_COM_CSP[:1000]
    probe = Probe(
        url="https://exemplo.com/",
        status_code=200,
        headers=_SEM_POLITICA,
        body_snippet=cortado,
        final_url="https://exemplo.com/",
        truncated=True,
        bytes_lidos=len(cortado),
    )
    ids = _headers_ids(probe)
    assert "CSP_AUSENTE" not in ids, "afirmou ausência a partir de leitura parcial"
    assert "CSP_NAO_AVALIADA" in ids


def test_corpo_truncado_mas_com_csp_visivel_conclui_normalmente() -> None:
    """Truncamento só bloqueia a conclusão quando ela dependia do que não chegou."""
    probe = Probe(
        url="https://exemplo.com/",
        status_code=200,
        headers=_SEM_POLITICA,
        body_snippet='<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'">',
        final_url="https://exemplo.com/",
        truncated=True,
        bytes_lidos=90,
    )
    ids = _headers_ids(probe)
    assert "CSP_NAO_AVALIADA" not in ids
    assert "POLITICA_VIA_META" in ids


def test_sem_csp_e_corpo_inteiro_continua_sendo_achado_de_verdade() -> None:
    probe = make_probe(headers=_SEM_POLITICA, body="<html><head></head><body></body></html>")
    assert "CSP_AUSENTE" in _headers_ids(probe)


# --------------------------------------------------------------------------- #
# DNS mudo
# --------------------------------------------------------------------------- #
class _ResolvedorMudo:
    nameservers = ["192.0.2.1"]

    def resolve(self, *_a: object, **_k: object) -> object:
        raise dns.exception.Timeout


def test_dns_sem_resposta_declara_que_nao_avaliou(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolvedor filtrado fazia SPF, DMARC, CAA, DNSSEC e MTA-STS evaporarem —
    com `errors` vazio. O laudo ficava idêntico ao de um domínio impecável."""
    monkeypatch.setattr(dns_mod, "_resolver", lambda *_a, **_k: _ResolvedorMudo())
    monkeypatch.setattr(dns_mod, "is_provider_hosted", lambda _h: False)
    achados = list(DnsEmailChecker().run(make_context()))
    assert [f.id for f in achados] == ["DNS_NAO_AVALIADO"]
    assert achados[0].severity.weight == 0


# --------------------------------------------------------------------------- #
# Porta 80 inalcançável ≠ site que redireciona direito
# --------------------------------------------------------------------------- #
def test_porta_80_inalcancavel_nao_vira_aprovacao() -> None:
    """Firewall corporativo com egresso na 80 fechado dava 8 pontos de brinde."""
    sonda_falha = make_probe(status=0, error="ConnectError: [WinError 10061]")
    ctx = make_context(primary=make_probe(final_url="https://exemplo.com/"), http_probe=sonda_falha)
    ids = {f.id for f in TransportChecker().run(ctx)}
    assert "SEM_REDIRECT_HTTPS" not in ids
    assert "TRANSPORTE_NAO_AVALIADO" in ids


# --------------------------------------------------------------------------- #
# Relógio local
# --------------------------------------------------------------------------- #
def test_relogio_muito_diferente_do_alvo_e_declarado() -> None:
    ctx = make_context(primary=make_probe(headers={"Date": "Tue, 01 Jan 2019 00:00:00 GMT"}))
    ids = {f.id for f in TlsChecker()._check_relogio(ctx)}
    assert "RELOGIO_LOCAL_DIVERGENTE" in ids


def test_relogio_proximo_nao_gera_ruido() -> None:
    from datetime import datetime, timezone
    from email.utils import format_datetime

    agora = format_datetime(datetime.now(timezone.utc))
    ctx = make_context(primary=make_probe(headers={"Date": agora}))
    assert list(TlsChecker()._check_relogio(ctx)) == []


def test_alvo_sem_cabecalho_date_nao_inventa_achado() -> None:
    assert list(TlsChecker()._check_relogio(make_context(primary=make_probe()))) == []


# --------------------------------------------------------------------------- #
# TLS legado que o cliente local não consegue oferecer
# --------------------------------------------------------------------------- #
def test_tls_legado_nao_testavel_e_declarado() -> None:
    ids = {f.id for f in TlsChecker()._check_protocols([], ["TLS 1.0", "TLS 1.1"])}
    assert "TLS_LEGADO_NAO_AVALIADO" in ids
    assert "TLS_PROTOCOLO_LEGADO" not in ids


def test_servidor_que_recusa_legado_nao_gera_nada() -> None:
    assert list(TlsChecker()._check_protocols([], [])) == []


# --------------------------------------------------------------------------- #
# Redirecionamento bloqueado pela guarda anti-SSRF
# --------------------------------------------------------------------------- #
def test_redirecionamento_para_rede_interna_falha_alto() -> None:
    """Um Pi-hole devolvendo 0.0.0.0 fazia o probe voltar como 3xx de corpo vazio,
    e as checagens liam isso como "resposta boa e vazia" — enxurrada de achados de
    ausência falsos. Agora o Probe volta com erro e as checagens se abstêm."""
    from sentinela.core.http import HttpClient

    with HttpClient(timeout=1.0) as client:
        probe = client.request("GET", "http://127.0.0.1:9/", follow_redirects=True)
    # O alvo inicial nunca é bloqueado (varredura interna é legítima): o que se prova
    # aqui é que uma falha de transporte não vira Probe "ok" com corpo vazio.
    assert not probe.ok
    assert not probe.corpo_confiavel


def test_probe_saudavel_tem_corpo_confiavel() -> None:
    assert make_probe(body="<html></html>").corpo_confiavel is True
