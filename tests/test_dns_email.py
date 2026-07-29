"""Testes de DNS/e-mail com resolver e consultas TXT falsificados."""

from __future__ import annotations

import dns.resolver
import pytest

import sentinela.checks.dns_email as de
from conftest import make_context, make_target
from sentinela.checks._util import is_ip, registrable
from sentinela.checks.dns_email import DnsEmailChecker


class FakeResolver:
    def __init__(
        self,
        *,
        caa_ok: bool = False,
        dnskey_ok: bool = False,
        mx_ok: bool = False,
        mx_null: bool = False,
    ) -> None:
        self.caa_ok = caa_ok
        self.dnskey_ok = dnskey_ok
        self.mx_ok = mx_ok
        self.mx_null = mx_null

    def resolve(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
        if rdtype == "CAA" and self.caa_ok:
            return ["0 issue letsencrypt.org"]
        if rdtype == "DNSKEY" and self.dnskey_ok:
            return ["key"]
        if rdtype == "MX" and self.mx_null:
            return ["0 ."]  # null MX (RFC 7505)
        if rdtype == "MX" and self.mx_ok:
            return ["10 mx.example.com"]
        raise dns.resolver.NoAnswer()


def _patch(monkeypatch: pytest.MonkeyPatch, txt: dict[str, list[str]], resolver: FakeResolver) -> None:
    monkeypatch.setattr(de, "_resolver", lambda: resolver)
    monkeypatch.setattr(de, "_txt_records", lambda _r, name: txt.get(name, []))


def _run(target_host: str = "example.com"):
    ctx = make_context(target=make_target(f"https://{target_host}/"))
    return {f.id for f in DnsEmailChecker().run(ctx)}


def test_is_ip() -> None:
    assert is_ip("1.2.3.4")
    assert not is_ip("example.com")


def test_ip_puro_nao_gera_achados(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {}, FakeResolver())
    assert _run("8.8.8.8") == set()


def test_spf_e_dmarc_ausentes(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {}, FakeResolver())
    ids = _run()
    assert "SPF_AUSENTE" in ids
    assert "DMARC_AUSENTE" in ids
    assert "CAA_AUSENTE" in ids
    assert "DNSSEC_AUSENTE" in ids


def test_spf_permissivo(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {"example.com": ["v=spf1 include:_spf.google.com +all"]}
    _patch(monkeypatch, txt, FakeResolver())
    assert "SPF_PERMISSIVO" in _run()


def test_dmarc_sem_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:a@example.com"],
    }
    _patch(monkeypatch, txt, FakeResolver())
    ids = _run()
    assert "DMARC_SEM_ENFORCEMENT" in ids
    assert "SPF_AUSENTE" not in ids


def test_config_saudavel(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    }
    _patch(monkeypatch, txt, FakeResolver(caa_ok=True, dnskey_ok=True))
    assert _run() == set()


# Bateria de campo (2026-07-22): acurácia independente da infra do resolver/hosting.
def test_txt_lookup_failure_returns_none() -> None:
    import dns.exception

    class Boom:
        def resolve(self, name, rdtype):  # type: ignore[no-untyped-def]
            raise dns.exception.Timeout()

    assert de._txt_records(Boom(), "example.com") is None  # falha != ausência


def test_txt_real_absence_returns_empty() -> None:
    class NoRec:
        def resolve(self, name, rdtype):  # type: ignore[no-untyped-def]
            raise dns.resolver.NXDOMAIN()

    assert de._txt_records(NoRec(), "example.com") == []


def test_dns_failure_does_not_claim_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # SERVFAIL/timeout → _txt_records=None → NÃO afirmar SPF/DMARC ausente (era falso -8pt).
    monkeypatch.setattr(de, "_resolver", lambda: FakeResolver())
    monkeypatch.setattr(de, "_txt_records", lambda _r, name: None)
    ids = _run()
    assert "SPF_AUSENTE" not in ids
    assert "DMARC_AUSENTE" not in ids


def test_provider_hosted_skips_email_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    # github.io & cia.: DNS/e-mail são do provedor — não dinga o dono do site.
    _patch(monkeypatch, {}, FakeResolver())
    ids = _run("paulo.github.io")
    assert "DNS_HOSPEDAGEM_GERENCIADA" in ids
    assert "DMARC_AUSENTE" not in ids
    assert "SPF_AUSENTE" not in ids


# --------------------------------------------------------------------------- #
# ESCOPO. Sem a seção privada da PSL, `cliente.blogspot.com` resolvia para
# `blogspot.com` e a ferramenta consultava o SPF/DMARC/CAA do PROVEDOR, atribuindo o
# achado ao cliente errado. `empresa.br.com` (revenda de domínio) resolvia para
# `br.com` — pior ainda, porque ali o cliente controla a zona de verdade.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("host", "esperado"),
    [
        ("paulo.github.io", "paulo.github.io"),
        ("cliente.blogspot.com", "cliente.blogspot.com"),
        ("meu-bucket.s3.amazonaws.com", "meu-bucket.s3.amazonaws.com"),
        ("loja.myshopify.com", "loja.myshopify.com"),
        ("empresa.br.com", "empresa.br.com"),  # revenda: o cliente É o dono da zona
        ("www.empresa.com.br", "empresa.com.br"),  # TLD composto comum continua certo
    ],
)
def test_dominio_registravel_nao_sobe_para_o_provedor(host: str, esperado: str) -> None:
    assert registrable(host) == esperado


def test_dominio_de_revenda_continua_recebendo_checagem_de_email(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `br.com`/`uk.com`/`us.com` estão na seção PRIVADA da PSL, mas quem está em
    # `empresa.br.com` controla a própria zona e PODE publicar SPF/DMARC. Derivar o
    # "pular checagens" de `is_private` silenciaria esse cliente — falso negativo.
    _patch(monkeypatch, {}, FakeResolver())
    ids = _run("empresa.br.com")
    assert "DNS_HOSPEDAGEM_GERENCIADA" not in ids
    assert {"SPF_AUSENTE", "DMARC_AUSENTE"} <= ids


def test_hospedagem_gerenciada_nomeia_o_host_do_cliente_nao_o_do_provedor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, {}, FakeResolver())
    ctx = make_context(target=make_target("https://paulo.github.io/"))
    achado = next(f for f in DnsEmailChecker().run(ctx) if f.id == "DNS_HOSPEDAGEM_GERENCIADA")
    assert "paulo.github.io" in achado.description


def test_mta_sts_e_tls_rpt_ausentes_quando_ha_mx(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}
    _patch(monkeypatch, txt, FakeResolver(caa_ok=True, dnskey_ok=True, mx_ok=True))
    ids = _run()
    assert "MTA_STS_AUSENTE" in ids
    assert "TLS_RPT_AUSENTE" in ids


def test_sem_mx_nao_reporta_mta_sts(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sem MX confirmado, não afirmamos postura de e-mail (evita achado enganoso).
    txt = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}
    _patch(monkeypatch, txt, FakeResolver(caa_ok=True, dnskey_ok=True, mx_ok=False))
    ids = _run()
    assert "MTA_STS_AUSENTE" not in ids
    assert "TLS_RPT_AUSENTE" not in ids


def test_null_mx_nao_reporta_mta_sts(monkeypatch: pytest.MonkeyPatch) -> None:
    # Null MX (RFC 7505: `0 .`) = domínio não recebe e-mail → não exigir MTA-STS/TLS-RPT.
    txt = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]}
    _patch(monkeypatch, txt, FakeResolver(caa_ok=True, dnskey_ok=True, mx_null=True))
    ids = _run()
    assert "MTA_STS_AUSENTE" not in ids
    assert "TLS_RPT_AUSENTE" not in ids


def test_mta_sts_publicado_nao_gera_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
        "_mta-sts.example.com": ["v=STSv1; id=20260722"],
        "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
    }
    _patch(monkeypatch, txt, FakeResolver(caa_ok=True, dnskey_ok=True, mx_ok=True))
    ids = _run()
    assert "MTA_STS_AUSENTE" not in ids
    assert "TLS_RPT_AUSENTE" not in ids
