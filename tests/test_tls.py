"""Testes das checagens de certificado TLS (certificados gerados em memória)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from sentinela.checks.tls import (
    TlsChecker,
    _classificar_confianca,
    _FalhaConfianca,
    _hostname_matches,
    _san_dns_names,
)

# Falha de cadeia "não confiável" (autoassinado): o formato que `_trust_error` agora devolve.
_NAO_CONFIAVEL = _FalhaConfianca("self signed certificate", incompleta=False)

_DER = Encoding.DER

_KEY_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KEY_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - fraca de propósito


def _cert(
    host: str = "example.com",
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key: rsa.RSAPrivateKey = _KEY_2048,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    not_before = not_before or (now - timedelta(days=1))
    not_after = not_after or (now + timedelta(days=365))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hash_alg or hashes.SHA256())
    )


checker = TlsChecker()


def test_certificado_expirado() -> None:
    now = datetime.now(timezone.utc)
    cert = _cert(not_before=now - timedelta(days=400), not_after=now - timedelta(days=10))
    ids = {f.id for f in checker._check_expiry(cert)}
    assert "CERT_EXPIRADO" in ids


def test_certificado_expirando() -> None:
    now = datetime.now(timezone.utc)
    cert = _cert(not_after=now + timedelta(days=5))
    ids = {f.id for f in checker._check_expiry(cert)}
    assert "CERT_EXPIRANDO" in ids


def test_certificado_valido_sem_achado_de_expiracao() -> None:
    assert list(checker._check_expiry(_cert())) == []


def test_hostname_divergente() -> None:
    cert = _cert(host="example.com")
    ids = {f.id for f in checker._check_hostname(cert, "outrodominio.com")}
    assert "CERT_HOSTNAME_INVALIDO" in ids


def test_hostname_correto() -> None:
    cert = _cert(host="example.com")
    assert list(checker._check_hostname(cert, "example.com")) == []


def test_chave_fraca() -> None:
    cert = _cert(key=_KEY_1024)
    ids = {f.id for f in checker._check_key_and_signature(cert)}
    assert "CERT_CHAVE_FRACA" in ids


class _CertComAssinaturaLegada:
    """Certificado com assinatura SHA-1.

    O `cryptography` desta versão recusa ASSINAR com SHA-1 (`UnsupportedAlgorithm`), mas
    certificados assim existem em campo — em appliance e ambiente interno antigo, que é
    justamente onde a Sentinela é usada. Este proxy expõe o mesmo par de atributos que a
    checagem lê, sem precisar produzir uma assinatura fraca de verdade.
    """

    def __init__(self, cert: x509.Certificate, algoritmo: str) -> None:
        self._cert = cert
        self.signature_hash_algorithm = type("Alg", (), {"name": algoritmo})()

    def public_key(self):  # type: ignore[no-untyped-def]
        return self._cert.public_key()


@pytest.mark.parametrize("algoritmo", ["sha1", "md5"])
def test_assinatura_obsoleta(algoritmo: str) -> None:
    cert = _CertComAssinaturaLegada(_cert(), algoritmo)
    ids = {f.id for f in checker._check_key_and_signature(cert)}  # type: ignore[arg-type]
    assert "CERT_ASSINATURA_FRACA" in ids


def test_certificado_moderno_nao_gera_achado_de_chave_ou_assinatura() -> None:
    assert list(checker._check_key_and_signature(_cert())) == []


def test_san_extraction() -> None:
    assert _san_dns_names(_cert(host="alvo.com")) == ["alvo.com"]


def test_hostname_matches_wildcard() -> None:
    assert _hostname_matches("app.exemplo.com", ["*.exemplo.com"])
    assert not _hostname_matches("a.b.exemplo.com", ["*.exemplo.com"])
    assert _hostname_matches("exemplo.com", ["exemplo.com"])
    assert not _hostname_matches("exemplo.com", ["*.exemplo.com"])


# Alvo IP puro: comparar contra IP SANs (não DNS) — evita falso-positivo de cert (ex.: 1.1.1.1).
def test_ip_target_matched_against_ip_san() -> None:
    import ipaddress

    from cryptography.x509 import IPAddress, SubjectAlternativeName

    from sentinela.checks.tls import _san_ip_names

    key = _KEY_2048
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(SubjectAlternativeName([IPAddress(ipaddress.ip_address("1.2.3.4"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    assert _san_ip_names(cert) == ["1.2.3.4"]
    assert {f.id for f in checker._check_hostname(cert, "1.2.3.4")} == set()  # coberto → sem FP
    assert "CERT_HOSTNAME_INVALIDO" in {f.id for f in checker._check_hostname(cert, "9.9.9.9")}


def test_ip_target_not_compared_to_dns_san() -> None:
    # cert só com DNS SAN, alvo IP → não flagra (não compara IP contra nome DNS).
    cert = _cert("example.com")
    assert {f.id for f in checker._check_hostname(cert, "203.0.113.7")} == set()


# --- Profundidade TLS (#8): forward secrecy + suporte a TLS 1.3 ---
def test_tls_hardening_sem_pfs_e_sem_13() -> None:
    # RSA estático em 1.2: sem PFS; e negociar 1.2 com cliente 1.3-capaz => sem 1.3.
    ids = {f.id for f in checker._check_tls_hardening("TLSv1.2", "AES128-GCM-SHA256")}
    assert ids == {"TLS_13_AUSENTE", "TLS_SEM_PFS"}


def test_tls_hardening_ecdhe_tem_pfs() -> None:
    ids = {f.id for f in checker._check_tls_hardening("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")}
    assert "TLS_SEM_PFS" not in ids  # ECDHE tem forward secrecy
    assert "TLS_13_AUSENTE" in ids


def test_tls_hardening_dhe_tem_pfs() -> None:
    # DHE (não-ECDHE) TAMBÉM tem PFS — o critério ingênuo "not ECDHE" geraria FP aqui.
    ids = {f.id for f in checker._check_tls_hardening("TLSv1.2", "DHE-RSA-AES128-GCM-SHA256")}
    assert "TLS_SEM_PFS" not in ids


def test_tls_hardening_13_negociado_nao_gera_achado() -> None:
    assert list(checker._check_tls_hardening("TLSv1.3", "TLS_AES_256_GCM_SHA384")) == []


def test_tls_hardening_inconclusivo_nao_gera_achado() -> None:
    assert list(checker._check_tls_hardening(None, None)) == []


def test_protocolos_legados_aceitos() -> None:
    ids = {f.id for f in checker._check_protocols(["TLS 1.0", "TLS 1.1"], [])}
    assert ids == {"TLS_PROTOCOLO_LEGADO"}


def test_sem_protocolo_legado_nao_gera_achado() -> None:
    assert list(checker._check_protocols([], [])) == []


# --------------------------------------------------------------------------- #
# FIAÇÃO do checker. Todos os testes acima chamam os métodos `_check_*` direto:
# com eles, `TlsChecker.run` inteiro podia virar `return` e a suíte ficava verde
# (o maior módulo de segurança do repo, 50% de cobertura). Este teste monkeypatcha
# só as 4 funções de rede e assere que os achados SAEM do run().
# --------------------------------------------------------------------------- #
def test_run_costura_certificado_confianca_e_protocolos(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    now = datetime.now(timezone.utc)
    cert = _cert("example.com", not_before=now - timedelta(days=400), not_after=now - timedelta(days=10))
    monkeypatch.setattr(
        mod,
        "_fetch_certificate",
        lambda *a, **k: (cert.public_bytes(_DER), "TLSv1.2", "AES128-GCM-SHA256"),
    )
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: _NAO_CONFIAVEL)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: (["TLS 1.0"], []))

    ctx = make_context(target=make_target("https://example.com/"))
    ids = {f.id for f in mod.TlsChecker().run(ctx)}
    assert {"CERT_EXPIRADO", "CERT_NAO_CONFIAVEL", "TLS_PROTOCOLO_LEGADO", "TLS_SEM_PFS"} <= ids


def test_run_sem_endpoint_tls_nao_inventa_achado(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    monkeypatch.setattr(mod, "_fetch_certificate", lambda *a, **k: (None, None, None))
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: _NAO_CONFIAVEL)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: (["TLS 1.0"], []))
    ctx = make_context(target=make_target("https://example.com/"))
    assert list(mod.TlsChecker().run(ctx)) == []


def test_um_unico_handshake_entrega_certificado_versao_e_cifra(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Certificado e capacidades saem da MESMA conexão.

    `_fetch_certificate` e o antigo `_tls_capabilities` montavam um `SSLContext` byte a
    byte idêntico e diferiam só no que liam do socket já conectado. Eram 5 handshakes por
    alvo; agora são 4. Este teste conta as conexões TCP abertas pela função.
    """
    import sentinela.checks.tls as mod

    conexoes: list[tuple[str, int]] = []

    class _TlsFalso:
        def __enter__(self) -> _TlsFalso:
            return self

        def __exit__(self, *exc: object) -> None:
            return

        def getpeercert(self, binary_form: bool = False) -> bytes:
            return b"der"

        def version(self) -> str:
            return "TLSv1.3"

        def cipher(self) -> tuple[str, str, int]:
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    class _SockFalso:
        def __enter__(self) -> _SockFalso:
            return self

        def __exit__(self, *exc: object) -> None:
            return

    monkeypatch.setattr(
        mod.socket, "create_connection", lambda addr, timeout=None: conexoes.append(addr) or _SockFalso()
    )
    monkeypatch.setattr(mod.ssl.SSLContext, "wrap_socket", lambda self, sock, **kw: _TlsFalso())

    assert mod._fetch_certificate("exemplo.com", 443, 1.0) == (
        b"der",
        "TLSv1.3",
        "TLS_AES_256_GCM_SHA384",
    )
    assert conexoes == [("exemplo.com", 443)]  # UMA conexão, não duas


# --------------------------------------------------------------------------- #
# Porta TLS: um certificado só pode ser atribuído ao alvo que o serve.
# Classe do bug (auditoria 2026-09-07): alvo `http://host:PORTA` media a 443 —
# um serviço DIFERENTE — e podia tetar a nota em F com o certificado alheio.
# --------------------------------------------------------------------------- #
def test_porta_tls_https_usa_a_porta_do_alvo() -> None:
    from conftest import make_target

    assert TlsChecker._porta_tls(make_target("https://host:8443/")) == 8443


def test_porta_tls_http_padrao_mede_o_par_canonico_443() -> None:
    from conftest import make_target

    assert TlsChecker._porta_tls(make_target("http://host/")) == 443


def test_porta_tls_http_em_porta_nao_padrao_nao_mede_443() -> None:
    # O núcleo do achado: 443 seria OUTRO serviço; a checagem tem de se abster.
    from conftest import make_target

    assert TlsChecker._porta_tls(make_target("http://host:18080/")) is None


def test_run_em_http_porta_nao_padrao_nao_emite_achado_de_cert(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Prova de ponta: mesmo com um certificado EXPIRADO servido na 443, um alvo
    # http://host:18080 não recebe achado nenhum — o cert não é dele.
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    now = datetime.now(timezone.utc)
    cert = _cert("host", not_before=now - timedelta(days=400), not_after=now - timedelta(days=10))
    monkeypatch.setattr(
        mod, "_fetch_certificate", lambda *a, **k: (cert.public_bytes(_DER), "TLSv1.2", "AES128-GCM-SHA256")
    )
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: _NAO_CONFIAVEL)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: ([], []))
    ctx = make_context(target=make_target("http://host:18080/"))
    assert list(mod.TlsChecker().run(ctx)) == []


def test_run_em_http_padrao_carimba_o_endpoint_medido_no_subject(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Ao medir a 443 de um alvo http (porta 80), o achado precisa DECLARAR que
    # observou host:443 — não pode afirmar sobre o alvo sem dizer o que mediu.
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    now = datetime.now(timezone.utc)
    cert = _cert("host", not_before=now - timedelta(days=400), not_after=now - timedelta(days=10))
    monkeypatch.setattr(
        mod, "_fetch_certificate", lambda *a, **k: (cert.public_bytes(_DER), "TLSv1.3", "AES128-GCM-SHA256")
    )
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: None)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: ([], []))
    ctx = make_context(target=make_target("http://host/"))
    expirados = [f for f in mod.TlsChecker().run(ctx) if f.id == "CERT_EXPIRADO"]
    assert expirados and expirados[0].subject == "host:443"


def test_run_em_https_nao_carimba_subject_de_porta(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Mesma porta do alvo → nada de ruído no subject.
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    now = datetime.now(timezone.utc)
    cert = _cert("example.com", not_before=now - timedelta(days=400), not_after=now - timedelta(days=10))
    monkeypatch.setattr(
        mod, "_fetch_certificate", lambda *a, **k: (cert.public_bytes(_DER), "TLSv1.3", "AES128-GCM-SHA256")
    )
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: None)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: ([], []))
    ctx = make_context(target=make_target("https://example.com/"))
    expirados = [f for f in mod.TlsChecker().run(ctx) if f.id == "CERT_EXPIRADO"]
    assert expirados and expirados[0].subject is None


def test_probe_legado_so_credita_versao_realmente_negociada(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Blindagem descoberta na bateria de campo 2026-09-07: se o OpenSSL ignorar min/max
    e negociar uma versão diferente da forçada, o handshake bem-sucedido NÃO pode ser
    creditado como 'TLS 1.0 aceito'. Só a versão realmente negociada conta."""
    import sentinela.checks.tls as mod

    class _FakeSSock:
        def __init__(self, versao: str) -> None:
            self._v = versao

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def version(self) -> str:
            return self._v

    class _FakeCtx:
        def __init__(self, versao_negociada: str) -> None:
            self._v = versao_negociada
            self.check_hostname = False
            self.verify_mode = 0
            self.minimum_version = None
            self.maximum_version = None

        def set_ciphers(self, _s: str) -> None:
            return None

        def wrap_socket(self, _sock: object, server_hostname: str = "") -> _FakeSSock:  # noqa: ARG002
            return _FakeSSock(self._v)

    # Handshake "sucede", mas negocia TLS 1.2 (não a versão forçada) → não credita.
    monkeypatch.setattr(mod.socket, "create_connection", lambda *a, **k: _FakeSSock("x"))
    monkeypatch.setattr(mod.ssl, "SSLContext", lambda *a, **k: _FakeCtx("TLSv1.2"))
    aceitos, _ = mod._accepts_legacy_tls("host", 443, 2.0)
    assert aceitos == [], "negociar 1.2 não pode virar 'TLS 1.0 aceito'"

    # Handshake negocia exatamente TLS 1.0 → credita.
    monkeypatch.setattr(mod.ssl, "SSLContext", lambda *a, **k: _FakeCtx("TLSv1"))
    aceitos2, _ = mod._accepts_legacy_tls("host", 443, 2.0)
    assert "TLS 1.0" in aceitos2


# --------------------------------------------------------------------------- #
# Classe fp-cert-nao-confiavel-cadeia-incompleta (auditoria 2026-09-08).
# INVARIANTE: 'CA desconhecida/autoassinado' (ALTA) ≠ 'CA pública mas intermediário não
# servido' (cadeia incompleta, MÉDIA). O critério é o verify_code (20/21 = emissor local
# ausente = cadeia incompleta). O oráculo é a classificação PURA por código — testável
# sem handshake, atacando a classe e não o exemplo tjrj.
# --------------------------------------------------------------------------- #
def test_classificar_confianca_codigo_20_21_e_cadeia_incompleta() -> None:
    for code in (20, 21):
        falha = _classificar_confianca(code, "unable to get local issuer certificate")
        assert falha is not None and falha.incompleta is True, code


def test_classificar_confianca_autoassinado_e_ca_desconhecida_nao_e_incompleta() -> None:
    # 18 = self-signed (depth 0); 19 = self-signed root na cadeia. Continuam 'não confiável'.
    for code in (18, 19):
        falha = _classificar_confianca(code, "self signed certificate")
        assert falha is not None and falha.incompleta is False, code


def test_classificar_confianca_expiracao_e_hostname_tem_checagem_dedicada() -> None:
    # Não duplicar: expiração e hostname divergente já têm achado próprio -> None.
    assert _classificar_confianca(9, "certificate is not yet valid") is None
    assert _classificar_confianca(10, "certificate has expired") is None
    assert _classificar_confianca(62, "Hostname mismatch, certificate is not valid for 'x'") is None


def _run_tls_com_falha(monkeypatch, falha: _FalhaConfianca) -> set[str]:  # type: ignore[no-untyped-def]
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    cert = _cert("example.com")
    monkeypatch.setattr(
        mod,
        "_fetch_certificate",
        lambda *a, **k: (cert.public_bytes(_DER), "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
    )
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: falha)
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: ([], []))
    ctx = make_context(target=make_target("https://example.com/"))
    return {f.id for f in mod.TlsChecker().run(ctx)}


def test_cadeia_incompleta_emite_achado_dedicado_medio_nao_o_alto(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    ids = _run_tls_com_falha(monkeypatch, _FalhaConfianca("unable to get local issuer certificate", True))
    assert "CERT_CADEIA_INCOMPLETA" in ids
    assert "CERT_NAO_CONFIAVEL" not in ids  # não pode continuar acusando 'não confiável'


def test_ca_desconhecida_continua_sendo_cert_nao_confiavel_alto(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # O lado oposto: autoassinado/CA desconhecida NÃO pode virar 'cadeia incompleta' (média).
    ids = _run_tls_com_falha(monkeypatch, _FalhaConfianca("self signed certificate", False))
    assert "CERT_NAO_CONFIAVEL" in ids
    assert "CERT_CADEIA_INCOMPLETA" not in ids


def test_severidade_cadeia_incompleta_e_media_e_nao_confiavel_e_alta(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from sentinela.core.models import Severity

    inc = TlsChecker._achado_de_confianca(_FalhaConfianca("x", True))
    desc = TlsChecker._achado_de_confianca(_FalhaConfianca("x", False))
    assert inc.severity is Severity.MEDIUM and inc.id == "CERT_CADEIA_INCOMPLETA"
    assert desc.severity is Severity.HIGH and desc.id == "CERT_NAO_CONFIAVEL"
