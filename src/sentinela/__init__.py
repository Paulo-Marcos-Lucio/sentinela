"""Sentinela — diagnóstico de segurança para aplicações web.

Ferramenta de linha de comando que audita, de forma **não-intrusiva por padrão**,
a higiene de segurança de uma aplicação web exposta na internet: cabeçalhos HTTP,
TLS/certificado, cookies, CORS, métodos HTTP, exposição de informação e segurança
de DNS/e-mail (SPF, DMARC, CAA). O resultado é um relatório profissional pronto
para virar entregável de consultoria.
"""

from sentinela.version import __version__

__all__ = ["__version__"]
