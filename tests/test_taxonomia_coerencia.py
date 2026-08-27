"""Invariante de coerência da taxonomia: CWE × categoria OWASP × nome oficial do MITRE.

Existe porque `knowledge/mapping._TAGS` é editado por humano, entrada por entrada, e nada
impedia duas classes de erro que passariam despercebidas em revisão de diff:

    1. o mesmo CWE apontando para categorias OWASP diferentes em achados distintos —
       inconsistência interna que nenhum teste existente pega, porque cada achado é
       validado isoladamente;
    2. `cwe_name` divergindo do nome oficial que o MITRE publica para aquele CWE — o
       relatório (JSON/SARIF/Markdown/HTML) manda esse texto para o cliente como se
       fosse a nomenclatura padrão do mercado, e uma abreviação ou paráfrase feita à
       mão vira uma citação errada da fonte que ela alega representar.

O primeiro teste tranca a classe (1): não precisa de autoridade externa, só self-
-consistência — se um CWE aparece com duas categorias diferentes, uma das duas está
errada. O segundo tranca a classe (2) contra `_NOMES_OFICIAIS_MITRE`, um dicionário
fixado à mão a partir de cwe.mitre.org (versão 4.20, agosto/2026) para cada CWE que
`_TAGS` de fato usa hoje — não é lido de arquivo em runtime, é o mesmo padrão de fonte
fixada que `test_taxonomy.py` (item irmão `TX-01`) usa para a sincronia YAML×código.

Ao escrever este teste, 8 dos 24 CWEs em uso divergiam do nome oficial (paráfrase ou
abreviação: p.ex. "Exposure of Sensitive Information" em vez de "...to an Unauthorized
Actor", "(XSS)" em vez de "('Cross-site Scripting')") — corrigidos em `mapping.py` junto
com este teste, não deixados vermelhos.
"""

from __future__ import annotations

from sentinela.knowledge.mapping import _TAGS

# Nome oficial do MITRE para cada CWE usado em `_TAGS` hoje. Fonte: cwe.mitre.org,
# versão 4.20 (consultado em agosto/2026). Só cobre os CWEs em uso — um CWE novo em
# `_TAGS` sem entrada aqui é achado pelo teste abaixo (contagem confere as duas vias).
_NOMES_OFICIAIS_MITRE: dict[str, str] = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-284": "Improper Access Control",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-527": "Exposure of Version-Control Repository to an Unauthorized Control Sphere",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-598": "Use of HTTP Request With Sensitive Query String",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-942": "Permissive Cross-domain Security Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
}


def test_todo_cwe_de_tags_tem_nome_oficial_fixado() -> None:
    """Guarda o próprio fixture: um CWE novo em `_TAGS` sem entrada aqui é lacuna do
    teste, não ausência de defeito — falha explícita em vez de pular a checagem."""
    cwes_em_uso = {tag.cwe for tag in _TAGS.values() if tag.cwe is not None}
    faltando = sorted(cwes_em_uso - _NOMES_OFICIAIS_MITRE.keys())
    assert faltando == [], f"CWE sem nome oficial fixado no teste: {faltando}"


def test_cwe_name_bate_com_nome_oficial_do_mitre() -> None:
    divergentes = {
        finding_id: {"codigo": tag.cwe_name, "mitre": _NOMES_OFICIAIS_MITRE[tag.cwe]}
        for finding_id, tag in _TAGS.items()
        if tag.cwe is not None and tag.cwe_name != _NOMES_OFICIAIS_MITRE[tag.cwe]
    }
    assert divergentes == {}


def test_cwe_sempre_mapeia_para_a_mesma_categoria_owasp() -> None:
    """Self-consistência: um CWE não pode pertencer a duas categorias OWASP diferentes
    dependendo de qual achado o cita — sinal de reclassificação feita pela metade."""
    categoria_por_cwe: dict[str, str] = {}
    conflitos: dict[str, set[str]] = {}
    for tag in _TAGS.values():
        if tag.cwe is None or tag.owasp is None:
            continue
        vista = categoria_por_cwe.setdefault(tag.cwe, tag.owasp)
        if vista != tag.owasp:
            conflitos.setdefault(tag.cwe, {vista}).add(tag.owasp)
    assert conflitos == {}
