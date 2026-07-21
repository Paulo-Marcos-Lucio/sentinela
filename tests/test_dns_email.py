"""Testes de DNS/e-mail com resolver e consultas TXT falsificados."""

from __future__ import annotations

import dns.resolver
import pytest

import sentinela.checks.dns_email as de
from conftest import make_context, make_target
from sentinela.checks.dns_email import DnsEmailChecker, _is_ip


class FakeResolver:
    def __init__(self, *, caa_ok: bool = False, dnskey_ok: bool = False) -> None:
        self.caa_ok = caa_ok
        self.dnskey_ok = dnskey_ok

    def resolve(self, name: str, rdtype: str):  # type: ignore[no-untyped-def]
        if rdtype == "CAA" and self.caa_ok:
            return ["0 issue letsencrypt.org"]
        if rdtype == "DNSKEY" and self.dnskey_ok:
            return ["key"]
        raise dns.resolver.NoAnswer()


def _patch(monkeypatch: pytest.MonkeyPatch, txt: dict[str, list[str]], resolver: FakeResolver) -> None:
    monkeypatch.setattr(de, "_resolver", lambda: resolver)
    monkeypatch.setattr(de, "_txt_records", lambda _r, name: txt.get(name, []))


def _run(target_host: str = "example.com"):
    ctx = make_context(target=make_target(f"https://{target_host}/"))
    return {f.id for f in DnsEmailChecker().run(ctx)}


def test_is_ip() -> None:
    assert _is_ip("1.2.3.4")
    assert not _is_ip("example.com")


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
