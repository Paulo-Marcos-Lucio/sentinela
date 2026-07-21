"""Taxonomia: mapeia cada achado para OWASP Top 10:2025 e para o CWE.

Manter o mapeamento fora das checagens (fonte única de verdade) permite evoluir
a taxonomia sem tocar na lógica de detecção. O OWASP Top 10:2025 é a edição
vigente (versão final publicada em janeiro de 2026); mantemos o código no formato
``Axx:2025`` para deixar explícito contra qual versão o relatório mapeia.
"""

from __future__ import annotations

from dataclasses import dataclass

# Rótulos OWASP Top 10:2025 (owasp.org/Top10/2025/)
A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Security Misconfiguration"
A04 = "A04:2025 Cryptographic Failures"
A07 = "A07:2025 Authentication Failures"


@dataclass(frozen=True, slots=True)
class Tag:
    """Classificação de um achado em taxonomias de mercado."""

    owasp: str | None
    cwe: str | None
    cwe_name: str | None = None


# finding.id -> Tag. Achados puramente informativos/higiene podem não ter OWASP.
_TAGS: dict[str, Tag] = {
    # Cabeçalhos de segurança -> A02 Security Misconfiguration
    "XCTO_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "REFERRER_POLICY_AUSENTE": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    "PERMISSIONS_POLICY_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "COOP_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_DIRETIVA_INSEGURA": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CLICKJACKING_SEM_PROTECAO": Tag(A02, "CWE-1021", "Improper Restriction of Rendered UI Layers"),
    "XXSS_PROTECTION_LEGADO": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    # HSTS / transporte -> A04 Cryptographic Failures
    "HSTS_AUSENTE": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "HSTS_FRACO": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "HSTS_SEM_SUBDOMINIOS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SEM_REDIRECT_HTTPS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    # Cookies
    "COOKIE_SEM_HTTPONLY": Tag(A07, "CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
    "COOKIE_SEM_SECURE": Tag(A04, "CWE-614", "Sensitive Cookie Without 'Secure' Attribute"),
    "COOKIE_SEM_SAMESITE": Tag(A01, "CWE-352", "Cross-Site Request Forgery (CSRF)"),
    # CORS
    "CORS_REFLEXAO_COM_CREDENCIAIS": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    "CORS_CURINGA_COM_CREDENCIAIS": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    "CORS_REFLEXAO_ORIGEM": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    # Métodos HTTP
    "HTTP_TRACE_HABILITADO": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "HTTP_METODOS_PERIGOSOS": Tag(A02, "CWE-650", "Trusting HTTP Permission Methods on the Server Side"),
    # Exposição de informação
    "VERSAO_STACK_EXPOSTA": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    "LISTAGEM_DIRETORIO": Tag(A02, "CWE-548", "Exposure of Information Through Directory Listing"),
    # Arquivos/rotas sensíveis
    "GIT_EXPOSTO": Tag(A02, "CWE-527", "Exposure of Version-Control Repository to Web"),
    "DOTENV_EXPOSTO": Tag(
        A02, "CWE-538", "Insertion of Sensitive Information into Externally-Accessible File"
    ),
    "SVN_EXPOSTO": Tag(A02, "CWE-527", "Exposure of Version-Control Repository to Web"),
    "APACHE_STATUS_EXPOSTO": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    "PHPINFO_EXPOSTO": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    # TLS / certificado -> A04 Cryptographic Failures
    "CERT_EXPIRADO": Tag(A04, "CWE-298", "Improper Validation of Certificate Expiration"),
    "CERT_EXPIRANDO": Tag(A04, "CWE-298", "Improper Validation of Certificate Expiration"),
    "CERT_HOSTNAME_INVALIDO": Tag(A04, "CWE-295", "Improper Certificate Validation"),
    "CERT_CHAVE_FRACA": Tag(A04, "CWE-326", "Inadequate Encryption Strength"),
    "CERT_ASSINATURA_FRACA": Tag(A04, "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "CERT_NAO_CONFIAVEL": Tag(A04, "CWE-295", "Improper Certificate Validation"),
    "TLS_PROTOCOLO_LEGADO": Tag(A04, "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    # DNS / e-mail
    "SPF_AUSENTE": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "SPF_PERMISSIVO": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "DMARC_AUSENTE": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "DMARC_SEM_ENFORCEMENT": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "CAA_AUSENTE": Tag(A04, "CWE-295", "Improper Certificate Validation"),
    "DNSSEC_AUSENTE": Tag(A02, "CWE-345", "Insufficient Verification of Data Authenticity"),
    # Higiene / processo (sem OWASP direto)
    "SECURITY_TXT_AUSENTE": Tag(None, None, None),
}


def tag_for(finding_id: str) -> Tag | None:
    """Retorna a classificação OWASP/CWE de um achado, ou ``None``."""
    return _TAGS.get(finding_id)


# Lista completa OWASP Top 10:2025, para documentação e relatórios.
OWASP_TOP10_2025: tuple[str, ...] = (
    "A01:2025 Broken Access Control",
    "A02:2025 Security Misconfiguration",
    "A03:2025 Software Supply Chain Failures",
    "A04:2025 Cryptographic Failures",
    "A05:2025 Injection",
    "A06:2025 Insecure Design",
    "A07:2025 Authentication Failures",
    "A08:2025 Software or Data Integrity Failures",
    "A09:2025 Security Logging and Alerting Failures",
    "A10:2025 Mishandling of Exceptional Conditions",
)
