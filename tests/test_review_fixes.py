"""Regressões dos achados da revisão adversarial (2026-07-21)."""

from __future__ import annotations

import pytest

import sentinela.checks.dns_email as de
from conftest import FakeClient, make_context, make_probe, make_target
from sentinela.checks.dns_email import DnsEmailChecker
from sentinela.checks.exposure import ExposureChecker, _is_svn_entries
from sentinela.core.http import Probe, _host_is_blocked
from sentinela.core.target import parse_target


# --- Guarda anti-SSRF e alvo IPv6 ---------------------------------------- #
def test_host_bloqueado_faixas_internas() -> None:
    assert _host_is_blocked("127.0.0.1")
    assert _host_is_blocked("10.0.0.1")
    assert _host_is_blocked("192.168.1.10")
    assert _host_is_blocked("169.254.169.254")  # metadados de cloud
    assert _host_is_blocked("::1")


def test_host_publico_nao_bloqueado() -> None:
    assert not _host_is_blocked("8.8.8.8")
    assert not _host_is_blocked("1.1.1.1")
    assert not _host_is_blocked(None)
    assert not _host_is_blocked("")


def test_target_ipv6_gera_url_valida() -> None:
    t = parse_target("https://[::1]:8443/")
    assert t.host == "::1"
    assert t.host_for_url == "[::1]"
    assert t.origin == "https://[::1]:8443"


def test_probe_header_case_insensitive() -> None:
    p = Probe(url="x", status_code=200, headers={"Content-Type": "text/html"})
    assert p.header("content-type") == "text/html"
    assert p.has_header("CONTENT-TYPE")
    assert p.header("ausente") is None


# --- SPF sem mecanismo `all` (falso-negativo corrigido) ------------------ #
def _dns(monkeypatch: pytest.MonkeyPatch, txt: dict[str, list[str]]):
    class R:
        def resolve(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
            raise de.dns.resolver.NoAnswer()

    monkeypatch.setattr(de, "_resolver", lambda: R())
    monkeypatch.setattr(de, "_txt_records", lambda _r, name: txt.get(name, []))
    ctx = make_context(target=make_target("https://example.com/"))
    return {f.id for f in DnsEmailChecker().run(ctx)}


def test_spf_sem_all_e_permissivo(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = _dns(monkeypatch, {"example.com": ["v=spf1 include:_spf.google.com"]})
    assert "SPF_PERMISSIVO" in ids


def test_spf_hardfail_nao_permissivo(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = _dns(monkeypatch, {"example.com": ["v=spf1 include:_spf.google.com -all"]})
    assert "SPF_PERMISSIVO" not in ids


# --- DMARC p=reject com sp=none (falso-positivo corrigido) ---------------- #
def test_dmarc_reject_com_sp_none_nao_flaga(monkeypatch: pytest.MonkeyPatch) -> None:
    txt = {
        "example.com": ["v=spf1 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@example.com; sp=none"],
    }
    ids = _dns(monkeypatch, txt)
    assert "DMARC_SEM_ENFORCEMENT" not in ids


# --- Assinatura SVN (falso-positivo de substring 'dir' corrigido) -------- #
def test_svn_entries_assinatura() -> None:
    assert _is_svn_entries("10\n\ndir\nnome\n")
    assert not _is_svn_entries("<html>flex-direction: row; redirect; director</html>")


def test_exposure_svn_conteudo_generico_nao_flaga() -> None:
    def handler(method, url, headers):  # type: ignore[no-untyped-def]
        if url.endswith("/.svn/entries"):
            return make_probe(status=200, body="<html>directory redirect director</html>")
        return make_probe(status=404)

    ids = {f.id for f in ExposureChecker().run(make_context(client=FakeClient(handler=handler)))}
    assert "SVN_EXPOSTO" not in ids
