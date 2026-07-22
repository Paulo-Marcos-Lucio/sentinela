"""Inspeção de TLS e do certificado do servidor.

Faz um handshake TLS de baixo nível (sem baixar conteúdo) para avaliar:
versão de protocolo negociada, aceitação de protocolos legados, validade e
expiração do certificado, correspondência de hostname, chave fraca e algoritmo
de assinatura obsoleto. Tudo defensivo: qualquer erro inesperado resulta em
"não avaliado", nunca em exceção propagada.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Timeout por handshake. Servidor OK responde em <1s; o teto só é atingido em host
# lento/que descarta a conexão em silêncio — por isso as conexões rodam em PARALELO
# (o check inteiro fica limitado a UM handshake, não à soma de quatro).
_HANDSHAKE_TIMEOUT = 6.0


class TlsChecker(Checker):
    id = "tls"
    name = "TLS e certificado"
    category = Category.TLS
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        host = ctx.target.host
        port = ctx.target.port if ctx.target.is_https else 443

        # As conexões TLS são independentes → em paralelo, evitando um host lento
        # transformar 4×timeout em ~40s (o que travaria uma demo).
        is_ip = _is_ip(host)
        with ThreadPoolExecutor(max_workers=3) as pool:
            cert_future = pool.submit(_fetch_certificate, host, port)
            # Alvo IP puro: a validação de cadeia por hostname não se aplica (o navegador
            # casaria contra IP SAN); a checagem de hostname abaixo já cobre o IP SAN.
            trust_future = None if is_ip else pool.submit(_trust_error, host, port)
            legacy_future = pool.submit(_accepts_legacy_tls, host, port)
            der = cert_future.result()
            trust_error = trust_future.result() if trust_future is not None else None
            legados = legacy_future.result()

        if der is None:
            return  # sem endpoint TLS acessível — não é papel desta checagem relatar
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            return

        yield from self._check_expiry(cert)
        yield from self._check_hostname(cert, host)
        yield from self._check_key_and_signature(cert)
        if trust_error is not None:
            yield Finding(
                id="CERT_NAO_CONFIAVEL",
                title="Certificado não confiável",
                category=self.category,
                severity=Severity.HIGH,
                description="A validação padrão do certificado falhou (cadeia não confiável).",
                evidence=trust_error,
                impact=(
                    "Certificados autoassinados ou de cadeia incompleta fazem o "
                    "navegador alertar o usuário e comprometem a confiança na conexão."
                ),
                recommendation="Use um certificado emitido por uma CA reconhecida e envie a cadeia completa.",
                references=(ref.OWASP_TLS_CHEATSHEET, ref.MOZILLA_SSL_CONFIG),
            )
        yield from self._check_protocols(legados)

    def _check_expiry(self, cert: x509.Certificate) -> Iterable[Finding]:
        not_after = _not_valid_after(cert)
        now = datetime.now(timezone.utc)
        dias = (not_after - now).days

        if not_after < now:
            yield Finding(
                id="CERT_EXPIRADO",
                title="Certificado TLS expirado",
                category=self.category,
                severity=Severity.HIGH,
                description="O certificado do servidor já venceu.",
                evidence=f"Expirou em {not_after.date().isoformat()}",
                impact=(
                    "Navegadores exibem tela de erro bloqueando o acesso, e o "
                    "certificado deixa de garantir a identidade do servidor."
                ),
                recommendation="Renove o certificado imediatamente e automatize a renovação (ex.: ACME/Let's Encrypt).",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )
        elif dias <= 15:
            yield Finding(
                id="CERT_EXPIRANDO",
                title="Certificado TLS próximo do vencimento",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O certificado vence em {dias} dia(s).",
                evidence=f"Expira em {not_after.date().isoformat()}",
                impact="Se não renovado a tempo, o site ficará inacessível para os usuários.",
                recommendation="Renove antecipadamente e configure renovação automática com alertas.",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )

    def _check_hostname(self, cert: x509.Certificate, host: str) -> Iterable[Finding]:
        if _is_ip(host):
            ip_sans = _san_ip_names(cert)
            if ip_sans and host not in ip_sans:
                yield Finding(
                    id="CERT_HOSTNAME_INVALIDO",
                    title="Certificado não cobre o IP acessado",
                    category=self.category,
                    severity=Severity.HIGH,
                    description="O IP acessado não consta como IP SAN no certificado.",
                    evidence=f"host={host} · IP SANs={', '.join(ip_sans[:5])}",
                    impact=(
                        "Um certificado que não corresponde ao endereço quebra a garantia "
                        "de identidade e faz o navegador bloquear a conexão."
                    ),
                    recommendation="Acesse o serviço pelo hostname coberto pelo certificado, "
                    "ou emita um certificado com o IP no SAN.",
                    references=(ref.OWASP_TLS_CHEATSHEET,),
                )
            return  # não comparar IP contra SANs de DNS (geraria falso-positivo)
        names = _san_dns_names(cert)
        if names and not _hostname_matches(host, names):
            yield Finding(
                id="CERT_HOSTNAME_INVALIDO",
                title="Certificado não cobre o hostname",
                category=self.category,
                severity=Severity.HIGH,
                description="O hostname acessado não consta no certificado (SAN).",
                evidence=f"host={host} · SAN={', '.join(names[:5])}",
                impact=(
                    "Um certificado que não corresponde ao domínio quebra a garantia "
                    "de identidade e faz o navegador bloquear a conexão."
                ),
                recommendation="Emita um certificado cujo SAN inclua exatamente o domínio servido.",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )

    def _check_key_and_signature(self, cert: x509.Certificate) -> Iterable[Finding]:
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            yield Finding(
                id="CERT_CHAVE_FRACA",
                title="Chave RSA fraca no certificado",
                category=self.category,
                severity=Severity.HIGH,
                description=f"A chave pública RSA tem apenas {key.key_size} bits.",
                evidence=f"RSA {key.key_size} bits",
                impact="Chaves RSA abaixo de 2048 bits são consideradas fracas e passíveis de quebra.",
                recommendation="Reemita o certificado com RSA de no mínimo 2048 bits (ou uma chave ECDSA P-256).",
                references=(ref.MOZILLA_TLS,),
            )

        algo = cert.signature_hash_algorithm
        if algo is not None and algo.name.lower() in {"md5", "sha1"}:
            yield Finding(
                id="CERT_ASSINATURA_FRACA",
                title="Certificado assinado com algoritmo obsoleto",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O certificado usa assinatura {algo.name.upper()}.",
                evidence=f"Assinatura: {algo.name}",
                impact="MD5 e SHA-1 são vulneráveis a colisões e não oferecem garantia de integridade.",
                recommendation="Reemita o certificado com assinatura SHA-256 ou superior.",
                references=(ref.MOZILLA_TLS,),
            )

    def _check_protocols(self, legados: list[str]) -> Iterable[Finding]:
        if legados:
            yield Finding(
                id="TLS_PROTOCOLO_LEGADO",
                title="Protocolos TLS legados aceitos",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O servidor aceita: {', '.join(legados)}.",
                evidence=", ".join(legados),
                impact=(
                    "TLS 1.0/1.1 têm fraquezas conhecidas (ex.: BEAST, cifras RC4) e "
                    "foram formalmente descontinuados. Mantê-los habilitados amplia a "
                    "superfície de ataque e reprova em conformidades como PCI-DSS."
                ),
                recommendation="Desabilite TLS 1.0 e 1.1; sirva apenas TLS 1.2 e 1.3.",
                references=(ref.MOZILLA_TLS, ref.MOZILLA_SSL_CONFIG),
            )


# --------------------------------------------------------------------------- #
# Funções auxiliares de baixo nível
# --------------------------------------------------------------------------- #
def _fetch_certificate(host: str, port: int) -> bytes | None:
    """Obtém o certificado do servidor mesmo que não seja confiável/expirado."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            return tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def _trust_error(host: str, port: int) -> str | None:
    """``None`` se a cadeia é confiável (ou a falha já tem checagem dedicada); caso
    contrário, a mensagem curta da falha de CADEIA de confiança."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return None
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, "verify_code", None)
        msg = str(getattr(exc, "verify_message", "") or exc).lower()
        # Expiração e hostname divergente já têm checagens dedicadas — não duplicar.
        if code in (9, 10) or "expired" in msg or "hostname mismatch" in msg or "not valid for" in msg:
            return None
        return _short(str(exc))
    except (OSError, ssl.SSLError):
        return None


def _accepts_legacy_tls(host: str, port: int) -> list[str]:
    """Testa, de forma tolerante e em PARALELO, se TLS 1.0/1.1 são aceitos."""

    def probe(versao: ssl.TLSVersion, rotulo: str) -> str | None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = versao
            context.maximum_version = versao
        except (ValueError, OSError):
            return None  # OpenSSL local não permite forçar essa versão
        try:
            with (
                socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock,
                context.wrap_socket(sock, server_hostname=host),
            ):
                return rotulo
        except (OSError, ssl.SSLError):
            return None

    versoes = ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        resultados = list(pool.map(lambda vr: probe(*vr), versoes))
    return [r for r in resultados if r is not None]


def _not_valid_after(cert: x509.Certificate) -> datetime:
    """Compatível com versões novas e antigas do `cryptography`."""
    value: datetime | None = getattr(cert, "not_valid_after_utc", None)
    if value is not None:
        return value
    naive: datetime = cert.not_valid_after  # deprecado, mas em UTC
    return naive.replace(tzinfo=timezone.utc)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def _san_ip_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]


def _hostname_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.lower().rstrip(".")
        if pattern == host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".exemplo.com"
            # Curinga cobre exatamente um rótulo à esquerda.
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0 and host != suffix[1:]:
                return True
    return False


def _short(text: str, limit: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
