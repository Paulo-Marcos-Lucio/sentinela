"""Testes das checagens de certificado TLS (certificados gerados em memória)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sentinela.checks.tls import TlsChecker, _hostname_matches, _san_dns_names

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
