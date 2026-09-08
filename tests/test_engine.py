"""Testes de orquestração do motor (com cliente HTTP falso, sem rede)."""

from __future__ import annotations

import pytest

import sentinela.core.engine as engine
from conftest import make_probe
from sentinela.core.config import ScanConfig
from sentinela.core.target import parse_target


class FakeHttpClient:
    def __init__(self, primary=None, **_kw) -> None:  # type: ignore[no-untyped-def]
        self._primary = primary if primary is not None else make_probe(headers={})

    def __enter__(self) -> FakeHttpClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        return self._primary

    def request(self, method: str, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        # A tentativa de recuperação (UA de navegador) reencontra a MESMA condição: um host
        # genuinamente fora do ar continua fora do ar. Assim o erro de transporte é registrado
        # em vez de silenciosamente "recuperado" por um probe sintético.
        return self._primary

    def close(self) -> None:
        return None


def test_engine_orquestra_e_marca_conclusao(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "HttpClient", FakeHttpClient)
    target = parse_target("https://example.com/")
    result = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert result.finished_at is not None
    assert result.checks_run == ["security-headers"]
    assert result.tool_version
    # example.com sem cabeçalhos de segurança deve gerar ao menos um achado
    assert result.findings


def test_engine_registra_erro_de_transporte(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_factory(**_kw: object) -> FakeHttpClient:
        return FakeHttpClient(primary=make_probe(error="ConnectError", status=0))

    monkeypatch.setattr(engine, "HttpClient", fake_factory)
    target = parse_target("https://example.com/")
    result = engine.run_scan(target, ScanConfig(only=frozenset({"security-headers"})))
    assert any(e.check_id == "http" for e in result.errors)


# =========================================================================== #
# Classe fn-cascata-alvo-inacessivel (auditoria 2026-09-08).
# INVARIANTE: ALVO_INACESSIVEL por bloqueio/cert-não-verificável NÃO é ausência de
# superfície — é falha de coleta recuperável (retry com UA de navegador; e, em cert só
# não-verificável, conexão permissiva) MARCANDO a proveniência. Cert não-verificável ≠
# alvo inacessível: os cabeçalhos ainda devem ser lidos e laudados.
# =========================================================================== #
_CERT_ERR = (
    "ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "unable to get local issuer certificate (_ssl.c:1006)"
)
_HTML_OK = "<html><head></head><body>ola</body></html>"


def test_erro_de_confianca_recuperavel_distingue_cert_de_outros() -> None:
    assert engine._erro_de_confianca_recuperavel(_CERT_ERR) is True
    # falhas com significado próprio NÃO são recuperáveis por conexão permissiva
    assert (
        engine._erro_de_confianca_recuperavel(
            "ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired (_ssl.c:1006)"
        )
        is False
    )
    assert engine._erro_de_confianca_recuperavel("ConnectError: [Errno 111] Connection refused") is False
    assert engine._erro_de_confianca_recuperavel(None) is False


class _FakeConfig:
    """Fábrica de HttpClient falso parametrizada pelo que cada canal devolve."""

    def __init__(self, quando_verifica, quando_permissivo):  # type: ignore[no-untyped-def]
        self._verifica = quando_verifica
        self._permissivo = quando_permissivo

    def __call__(self, **kw):  # type: ignore[no-untyped-def]
        probe = self._permissivo if kw.get("verify_tls") is False else self._verifica
        return _FakeClientCfg(probe)


class _FakeClientCfg:
    def __init__(self, probe) -> None:  # type: ignore[no-untyped-def]
        self._probe = probe

    def __enter__(self) -> _FakeClientCfg:
        return self

    def __exit__(self, *_e: object) -> None:
        return None

    def get(self, url: str, **_k: object):  # type: ignore[no-untyped-def]
        return self._probe

    def request(self, method: str, url: str, **_k: object):  # type: ignore[no-untyped-def]
        return self._probe

    def close(self) -> None:
        return None


def _scan_headers(monkeypatch, factory) -> tuple[set[str], list]:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(engine, "HttpClient", factory)
    result = engine.run_scan(
        parse_target("https://example.com/"), ScanConfig(only=frozenset({"security-headers"}))
    )
    return {f.id for f in result.findings}, result.errors


def test_cert_nao_verificavel_le_a_superficie_por_conexao_permissiva(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    falha = make_probe(error=_CERT_ERR, status=0)
    ok = make_probe(headers={"Content-Type": "text/html"}, body=_HTML_OK)
    ids, errors = _scan_headers(monkeypatch, _FakeConfig(quando_verifica=falha, quando_permissivo=ok))
    assert "COLETA_PRIMARIA_RECUPERADA" in ids  # proveniência marcada
    assert "ALVO_INACESSIVEL" not in ids  # não é inacessível
    assert "CSP_AUSENTE" in ids  # a superfície FOI avaliada
    assert not any(e.check_id == "http" for e in errors)


def test_bloqueio_por_ua_recuperado_com_ua_de_navegador(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # get() (coleta padrão) falha; request() (retry com UA de navegador) responde -> recupera.
    class _Fac:
        def __call__(self, **kw):  # type: ignore[no-untyped-def]
            return _ClienteUA()

    class _ClienteUA:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_e: object) -> None:
            return None

        def get(self, url: str, **_k: object):  # type: ignore[no-untyped-def]
            return make_probe(error="ConnectError: connection reset by peer", status=0)

        def request(self, method: str, url: str, **_k: object):  # type: ignore[no-untyped-def]
            return make_probe(headers={"Content-Type": "text/html"}, body=_HTML_OK)

        def close(self) -> None:
            return None

    ids, errors = _scan_headers(monkeypatch, _Fac())
    assert "COLETA_PRIMARIA_RECUPERADA" in ids
    assert "ALVO_INACESSIVEL" not in ids
    assert "CSP_AUSENTE" in ids


def test_falha_nao_recuperavel_continua_alvo_inacessivel(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # O lado oposto: um host genuinamente fora do ar (não cert) NÃO pode ser 'recuperado'.
    falha = make_probe(error="ConnectError: [Errno 111] Connection refused", status=0)
    ids, errors = _scan_headers(monkeypatch, _FakeConfig(quando_verifica=falha, quando_permissivo=falha))
    assert "ALVO_INACESSIVEL" in ids
    assert "COLETA_PRIMARIA_RECUPERADA" not in ids
    assert any(e.check_id == "http" for e in errors)
