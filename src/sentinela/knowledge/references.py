"""Referências documentais canônicas.

Centralizar os links aqui garante que todo achado aponte para fontes primárias
consistentes (OWASP, MDN, IETF/RFC, Mozilla) e facilita a manutenção.
"""

from __future__ import annotations

# OWASP
OWASP_SECURE_HEADERS = "https://owasp.org/www-project-secure-headers/"
OWASP_TOP10 = "https://owasp.org/www-project-top-ten/"
OWASP_TLS_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
)
OWASP_HSTS_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
)
OWASP_CSP_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
)
OWASP_CORS = "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"
OWASP_COOKIES = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"

# MDN
MDN_HSTS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
MDN_CSP = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"
MDN_XCTO = "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"
MDN_XFO = "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"
MDN_REFERRER = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"
MDN_PERMISSIONS = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"
MDN_COOP = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
MDN_COEP = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
MDN_CORP = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
MDN_SETCOOKIE = "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"
MDN_CORS = "https://developer.mozilla.org/docs/Web/HTTP/CORS"

# Mozilla / TLS
MOZILLA_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"
MOZILLA_SSL_CONFIG = "https://ssl-config.mozilla.org/"

# RFCs / IETF
RFC_HSTS = "https://www.rfc-editor.org/rfc/rfc6797"
RFC_TRACE = "https://www.rfc-editor.org/rfc/rfc9110#name-trace"
RFC_SECURITY_TXT = "https://www.rfc-editor.org/rfc/rfc9116"
RFC_TLS13 = "https://www.rfc-editor.org/rfc/rfc8446"

# DNS / e-mail
RFC_SPF = "https://www.rfc-editor.org/rfc/rfc7208"
RFC_DMARC = "https://www.rfc-editor.org/rfc/rfc7489"
RFC_CAA = "https://www.rfc-editor.org/rfc/rfc8659"
RFC_DNSSEC = "https://www.rfc-editor.org/rfc/rfc9364"
DMARC_ORG = "https://dmarc.org/overview/"

# Brasil / regulatório
LGPD = "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm"
MARCO_CIVIL = "https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2014/lei/l12965.htm"
