"""Normalização do alvo informado pelo usuário."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sentinela.core.models import Target

_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_target(raw: str) -> Target:
    """Normaliza uma entrada livre do usuário em um :class:`Target`.

    Aceita ``exemplo.com``, ``exemplo.com.br/app``, ``https://host:8443``. Quando
    o esquema é omitido, assume ``https`` — o padrão seguro. Levanta ``ValueError``
    para entradas sem host reconhecível.
    """
    text = raw.strip()
    if not text:
        raise ValueError("Alvo vazio.")

    # urlsplit só reconhece o host se houver esquema; adiciona um provisório.
    has_scheme = "://" in text
    candidate = text if has_scheme else f"https://{text}"
    parts = urlsplit(candidate)

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"Esquema não suportado: {scheme!r}. Use http ou https.")

    host = parts.hostname
    if not host:
        raise ValueError(f"Não foi possível extrair um host de {raw!r}.")

    port = parts.port or _DEFAULT_PORTS[scheme]
    path = parts.path or "/"
    url = urlunsplit((scheme, parts.netloc, path, parts.query, ""))

    return Target(raw=raw, scheme=scheme, host=host.lower(), port=port, url=url)
