"""Testes das checagens de certificado TLS (certificados gerados em memória)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from sentinela.checks.tls import TlsChecker, _hostname_matches, _san_dns_names

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
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: "self signed certificate")
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: (["TLS 1.0"], []))

    ctx = make_context(target=make_target("https://example.com/"))
    ids = {f.id for f in mod.TlsChecker().run(ctx)}
    assert {"CERT_EXPIRADO", "CERT_NAO_CONFIAVEL", "TLS_PROTOCOLO_LEGADO", "TLS_SEM_PFS"} <= ids


def test_run_sem_endpoint_tls_nao_inventa_achado(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import sentinela.checks.tls as mod
    from conftest import make_context, make_target

    monkeypatch.setattr(mod, "_fetch_certificate", lambda *a, **k: (None, None, None))
    monkeypatch.setattr(mod, "_trust_error", lambda *a, **k: "erro qualquer")
    monkeypatch.setattr(mod, "_accepts_legacy_tls", lambda *a, **k: (["TLS 1.0"], []))
    ctx = make_context(target=make_target("https://example.com/"))
    assert list(mod.TlsChecker().run(ctx)) == []
    # EV-05: sem endpoint TLS não é mais silêncio — é uma checagem DECLARADA como pulada,
    # o caso típico de um alvo `http://` (dogfood do CI roda exatamente este cenário).
    assert [s.check for s in ctx.skipped] == ["tls"]
    assert "endpoint TLS" in ctx.skipped[0].reason


def test_run_certificado_ilegivel_tambem_e_pulado_e_nao_inventa_achado(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from conftest import make_context, make_target

    # DER inválido: o handshake completou (não é o caso "sem endpoint" acima), mas o
    # certificado que veio não é interpretável — outra forma de "não deu para avaliar",
    # com uma razão diferente. Monkeypatch por caminho de string (em vez de um segundo
    # `import ... as mod` do módulo já importado no topo do arquivo): mesmo efeito,
    # sem duplicar o import.
    monkeypatch.setattr(
        "sentinela.checks.tls._fetch_certificate",
        lambda *a, **k: (b"nao-e-der-valido", "TLSv1.3", "X"),
    )
    monkeypatch.setattr("sentinela.checks.tls._trust_error", lambda *a, **k: None)
    monkeypatch.setattr("sentinela.checks.tls._accepts_legacy_tls", lambda *a, **k: ([], []))
    ctx = make_context(target=make_target("https://example.com/"))
    assert list(TlsChecker().run(ctx)) == []
    assert [s.check for s in ctx.skipped] == ["tls"]
    assert "certificado" in ctx.skipped[0].reason


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
