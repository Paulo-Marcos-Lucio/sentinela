"""Taxonomia: mapeia cada achado para OWASP Top 10:2025 e para o CWE.

Manter o mapeamento fora das checagens (fonte única de verdade) permite evoluir
a taxonomia sem tocar na lógica de detecção. O OWASP Top 10:2025 é a edição
vigente (versão final publicada em janeiro de 2026); mantemos o código no formato
``Axx:2025`` para deixar explícito contra qual versão o relatório mapeia.
"""

from __future__ import annotations

from dataclasses import dataclass

# Edição do OWASP Top 10 contra a qual este mapeamento é feito. Vai como campo próprio no
# JSON e no SARIF: um dashboard nunca deveria precisar fazer parsing da string do rótulo
# para saber que `A03` de 2025 e `A03` de 2021 significam coisas OPOSTAS.
OWASP_EDICAO = "2025"

# Rótulos OWASP Top 10:2025 (owasp.org/Top10/2025/)
A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Security Misconfiguration"
A03 = "A03:2025 Software Supply Chain Failures"
A04 = "A04:2025 Cryptographic Failures"
A05 = "A05:2025 Injection"
A07 = "A07:2025 Authentication Failures"


@dataclass(frozen=True, slots=True)
class Tag:
    """Classificação de um achado em taxonomias de mercado."""

    owasp: str | None
    cwe: str | None
    cwe_name: str | None = None


# finding.id -> Tag. Achados puramente informativos/higiene podem não ter OWASP.
_TAGS: dict[str, Tag] = {
    # "Não avaliado": inconclusivo NÃO é ausência. Sem taxonomia OWASP de propósito —
    # não são vulnerabilidade, são limite declarado da execução.
    "DNS_NAO_AVALIADO": Tag(None, None, None),
    "TRANSPORTE_NAO_AVALIADO": Tag(None, None, None),
    "CSP_NAO_AVALIADA": Tag(None, None, None),
    "TLS_LEGADO_NAO_AVALIADO": Tag(None, None, None),
    "DESCOBERTA_NAO_AVALIADA": Tag(None, None, None),
    "RELOGIO_LOCAL_DIVERGENTE": Tag(None, None, None),
    "METODOS_NAO_AVALIADOS": Tag(None, None, None),
    "FORMS_NAO_AVALIADO": Tag(None, None, None),
    # Contexto da resposta primária: NÃO são vulnerabilidade do alvo, são o motor declarando
    # que o objeto avaliado não é o alvo (página de bloqueio/erro/outro host) — classe C2/FN-01.
    "ALVO_BLOQUEADO": Tag(None, None, None),
    "RESPOSTA_DE_ERRO": Tag(None, None, None),
    "ALVO_REDIRECIONADO_OUTRO_HOST": Tag(None, None, None),
    # Cabeçalhos de segurança -> A02 Security Misconfiguration
    "XCTO_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "REFERRER_POLICY_AUSENTE": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    "PERMISSIONS_POLICY_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "COOP_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_AUSENTE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_DIRETIVA_INSEGURA": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_ESTILO_INLINE": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_APENAS_REPORT_ONLY": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_WILDCARD_PERMISSIVO": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_SEM_OBJECT_SRC": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_SEM_BASE_URI": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CSP_SEM_SCRIPT_SRC": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    "CLICKJACKING_SEM_PROTECAO": Tag(A02, "CWE-1021", "Improper Restriction of Rendered UI Layers"),
    "XXSS_PROTECTION_LEGADO": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    # Política entregue por <meta> em vez de cabeçalho: informativo (é legítimo), mas com
    # limite real — via <meta> o navegador ignora frame-ancestors/sandbox/report-uri.
    "POLITICA_VIA_META": Tag(A02, None, None),
    # HSTS / transporte -> A04 Cryptographic Failures
    "HSTS_AUSENTE": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "HSTS_FRACO": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "HSTS_SEM_SUBDOMINIOS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SEM_HTTPS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SEM_REDIRECT_HTTPS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    # Cookies
    "COOKIE_SEM_HTTPONLY": Tag(A07, "CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
    "COOKIE_SEM_HTTPONLY_FUNCIONAL": Tag(A07, "CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag"),
    "COOKIE_CSRF_LEGIVEL_POR_JS": Tag(None, None, None),
    "COOKIE_SEM_SECURE": Tag(A04, "CWE-614", "Sensitive Cookie Without 'Secure' Attribute"),
    "COOKIE_SEM_SAMESITE": Tag(A01, "CWE-352", "Cross-Site Request Forgery (CSRF)"),
    "COOKIE_SAMESITE_NONE_INSEGURO": Tag(
        A01, "CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"
    ),
    "COOKIE_PREFIXO_INVALIDO": Tag(A02, "CWE-693", "Protection Mechanism Failure"),
    # Conteúdo HTML / integridade da página
    "CONTEUDO_MISTO": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SRI_AUSENTE": Tag(A03, "CWE-353", "Missing Support for Integrity Check"),
    "FORM_ACTION_INSEGURA": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "SENHA_SEM_HTTPS": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    # CORS
    "CORS_REFLEXAO_COM_CREDENCIAIS": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    "CORS_CURINGA_COM_CREDENCIAIS": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    "CORS_REFLEXAO_ORIGEM": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
    "CORS_NULL_COM_CREDENCIAIS": Tag(A01, "CWE-942", "Permissive Cross-domain Policy"),
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
    "TLS_SEM_PFS": Tag(A04, "CWE-326", "Inadequate Encryption Strength"),
    "TLS_13_AUSENTE": Tag(A04, None, None),
    # DNS / e-mail
    # Sem OWASP de propósito: é uma constatação de escopo (o DNS é do provedor), não uma falha.
    "DNS_HOSPEDAGEM_GERENCIADA": Tag(None, None, None),
    "SPF_AUSENTE": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "SPF_PERMISSIVO": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "DMARC_AUSENTE": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    "DMARC_SEM_ENFORCEMENT": Tag(A07, "CWE-290", "Authentication Bypass by Spoofing"),
    # CAA é hardening de DNS (restringe quais CAs podem emitir); sem CWE canônico bom.
    "CAA_AUSENTE": Tag(A02, None, None),
    "DNSSEC_AUSENTE": Tag(A02, "CWE-345", "Insufficient Verification of Data Authenticity"),
    "MTA_STS_AUSENTE": Tag(A04, "CWE-319", "Cleartext Transmission of Sensitive Information"),
    "TLS_RPT_AUSENTE": Tag(None, None, None),
    # Recon passiva de arquivos públicos
    "ROBOTS_CAMINHOS_SENSIVEIS": Tag(A02, "CWE-200", "Exposure of Sensitive Information"),
    # Superfície de ataque / subdomínios
    "SUPERFICIE_SUBDOMINIOS": Tag(None, None, None),
    "SUBDOMAIN_TAKEOVER": Tag(A02, "CWE-284", "Improper Access Control"),
    "SUBDOMAIN_TAKEOVER_POSSIVEL": Tag(A02, "CWE-284", "Improper Access Control"),
    # Conteúdo — cache de página sensível
    "CACHE_SENSIVEL_SEM_NOSTORE": Tag(
        A02, "CWE-525", "Use of Web Browser Cache Containing Sensitive Information"
    ),
    # Meta-achado: alvo inacessível (teta a nota)
    "ALVO_INACESSIVEL": Tag(None, None, None),
    # Higiene / processo (sem OWASP direto)
    "SECURITY_TXT_AUSENTE": Tag(None, None, None),
    # Superfície de formulários e injeção (checker passivo `forms`)
    "SENHA_EM_GET": Tag(A07, "CWE-598", "Use of GET Request Method With Sensitive Query Strings"),
    "FORMULARIO_CREDENCIAL_SEM_HTTPS": Tag(
        A04, "CWE-319", "Cleartext Transmission of Sensitive Information"
    ),
    "CSRF_TOKEN_AUSENTE": Tag(A01, "CWE-352", "Cross-Site Request Forgery (CSRF)"),
    "REFLEXAO_DE_PARAMETRO": Tag(
        A05, "CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)"
    ),
    "DADO_SENSIVEL_NA_URL": Tag(A07, "CWE-598", "Use of GET Request Method With Sensitive Query Strings"),
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
