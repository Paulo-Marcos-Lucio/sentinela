"""Utilidades compartilhadas pelas checagens.

Existe para haver UMA definição de cada coisa: `is_ip`, `registrable` e a lista de
hospedagens gerenciadas estavam copiadas em três módulos, e a cópia já tinha produzido
divergência real (o mesmo defeito de escopo precisava ser corrigido em dois lugares).
"""

from __future__ import annotations

import ipaddress

import tldextract

# Extrator offline e determinístico (snapshot embutido da PSL, sem rede).
#
# `include_psl_private_domains=True` é o que define o ESCOPO da varredura. Sem ele,
# `paulo.github.io` resolvia para `github.io`, e a ferramenta passava a auditar — e, com
# `--descobrir`, a ENUMERAR por Certificate Transparency e requisitar por HTTP — o
# domínio do PROVEDOR em vez do ativo do cliente. Também corrige domínios de revenda:
# `empresa.br.com` resolvia para `br.com` (consultando o SPF de terceiro).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Hospedagens gerenciadas (páginas estáticas/PaaS/SaaS): o DONO do site NÃO controla o DNS
# do apex nem envia e-mail por esse nome. SPF/DMARC/CAA/DNSSEC "ausente" aqui é do provedor
# — afirmá-lo contra o cliente é impreciso e não-acionável.
#
# Lista CURADA de propósito, e não derivada da seção privada da PSL: a seção privada inclui
# sufixos de REVENDA de domínio (br.com, uk.com, eu.com…) em que o cliente controla a
# própria zona e PODE publicar SPF/DMARC. Usar `is_private` como critério de pulo
# silenciaria achados legítimos — falso negativo é pior que o falso positivo que se quer
# corrigir. Por isso as duas coisas são independentes: a PSL privada decide o ESCOPO
# (qual nome auditar), esta lista decide se as checagens de e-mail/DNS FAZEM SENTIDO.
PROVIDER_HOSTED = frozenset(
    {
        # Páginas estáticas / PaaS
        "github.io",
        "gitlab.io",
        "netlify.app",
        "vercel.app",
        "herokuapp.com",
        "pages.dev",
        "web.app",
        "firebaseapp.com",
        "azurewebsites.net",
        "onrender.com",
        "surge.sh",
        "readthedocs.io",
        "bitbucket.io",
        "workers.dev",
        "fly.dev",
        "render.com",
        "appspot.com",
        "cloudfunctions.net",
        "wixsite.com",
        "myshopify.com",
        "blogspot.com",
        "squarespace.com",
        "wpengine.com",
        # SaaS com subdomínio por cliente
        "sharepoint.com",
        "zendesk.com",
        "atlassian.net",
        "hubspot.com",
        "freshdesk.com",
        "salesforce.com",
        # Plataformas brasileiras
        "vtexcommercestable.com.br",
        "tray.com.br",
        "lojaintegrada.com.br",
        "rdstation.com.br",
    }
)


def is_ip(host: str) -> bool:
    """Verdadeiro se ``host`` é um literal de endereço IP (v4 ou v6)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable(host: str) -> str | None:
    """Domínio registrável (eTLD+1) do host, considerando a seção privada da PSL."""
    ext = _EXTRACT(host)
    # `top_domain_under_public_suffix` é o nome novo; `registered_domain` é o legado.
    top = getattr(ext, "top_domain_under_public_suffix", None)
    if top is not None:
        return str(top) or None
    return str(ext.registered_domain) or None


def is_provider_hosted(host: str) -> bool:
    """Verdadeiro se o host está sob uma hospedagem gerenciada conhecida."""
    h = host.lower().rstrip(".")
    return any(h == p or h.endswith("." + p) for p in PROVIDER_HOSTED)


def truncate(text: str, limit: int = 180) -> str:
    """Texto em uma linha, cortado em ``limit`` caracteres (para campo de evidência)."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
